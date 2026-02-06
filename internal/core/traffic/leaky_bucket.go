package traffic

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/penwyp/mini-gateway/config"
	"github.com/penwyp/mini-gateway/internal/core/observability"
	"github.com/penwyp/mini-gateway/pkg/logger"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

var leakyBucketTracer = otel.Tracer("ratelimit:leaky-bucket")

// MultiDimensionalLeakyBucket 管理多维度限流
type MultiDimensionalLeakyBucket struct {
	globalLimiter *LeakyBucketLimiter
	ipLimiters    sync.Map // map[string]*LeakyBucketLimiter
	routeLimiters sync.Map // map[string]*LeakyBucketLimiter
	config        *config.Config
	mutex         sync.Mutex
}

// LeakyBucketLimiter 实现漏桶限流器
type LeakyBucketLimiter struct {
	capacity int           // 桶容量（突发限制）
	rate     float64       // 漏出速率（每秒请求数，QPS）
	queue    chan struct{} // 表示桶队列的通道
	mutex    sync.Mutex    // 确保队列操作的线程安全
	stopChan chan struct{} // 信号通道，用于停止漏出协程
}

func NewMultiDimensionalLeakyBucket(cfg *config.Config) *MultiDimensionalLeakyBucket {
	mdl := &MultiDimensionalLeakyBucket{
		config: cfg,
	}

	// 初始化全局限流器
	if cfg.Traffic.RateLimit.Enabled {
		mdl.globalLimiter = NewLeakyBucketLimiter(cfg.Traffic.RateLimit.QPS, cfg.Traffic.RateLimit.Burst)
	}

	return mdl
}

func NewLeakyBucketLimiter(qps, burst int) *LeakyBucketLimiter {
	l := &LeakyBucketLimiter{
		capacity: burst,
		rate:     float64(qps),
		// 创建一个容量为 burst 的通道
		queue:    make(chan struct{}, burst),
		stopChan: make(chan struct{}),
	}
	// 【风险点】每创建一个限流器，就会启动一个后台 Goroutine
	go l.startLeak()
	logger.Info("LeakyBucketLimiter initialized",
		zap.Int("qps", qps),
		zap.Int("burst", burst))
	return l
}

func (l *LeakyBucketLimiter) startLeak() {
	// 1. 设置打点器 (Ticker)
	// 如果 Rate = 10 (QPS)，那么 interval = 1秒 / 10 = 100毫秒
	// 也就是每 100ms 触发一次
	ticker := time.NewTicker(time.Second / time.Duration(l.rate))
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C: // 每 100ms 执行一次
			l.mutex.Lock()
			// 如果桶里有水 (len > 0)
			if len(l.queue) > 0 {
				select {
				case <-l.queue: // 【核心】从通道里拿走一个，腾出一个空位
				default:
				}
			}
			l.mutex.Unlock()
		case <-l.stopChan:
			logger.Info("LeakyBucketLimiter leak routine stopped")
			return
		}
	}
	//不管请求进来的速度有多快（哪怕一瞬间进来100个），
	//这个 startLeak 依然慢条斯理地、雷打不动地每 1/Rate 秒腾出一个空位。这就实现了恒定速率。
}

func (l *LeakyBucketLimiter) Allow() bool {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	select {
	// 尝试往桶里放一个东西 (占座)
	case l.queue <- struct{}{}:
		return true // 放进去了，允许通行
	default:
		return false // 桶满了 (Channel 满了)，阻塞了，直接拒绝
	}
}

func (l *LeakyBucketLimiter) Stop() {
	close(l.stopChan)
}

// getOrCreateLimiter 获取或创建特定维度的限流器
func (mdl *MultiDimensionalLeakyBucket) getOrCreateLimiter(dimension, key string, qps, burst int) *LeakyBucketLimiter {
	var limiterMap *sync.Map
	if dimension == "ip" {
		limiterMap = &mdl.ipLimiters
	} else if dimension == "route" {
		limiterMap = &mdl.routeLimiters
	}

	if limiter, ok := limiterMap.Load(key); ok {
		return limiter.(*LeakyBucketLimiter)
	}

	mdl.mutex.Lock()
	defer mdl.mutex.Unlock()

	// 双重检查
	if limiter, ok := limiterMap.Load(key); ok {
		return limiter.(*LeakyBucketLimiter)
	}

	limiter := NewLeakyBucketLimiter(qps, burst)
	limiterMap.Store(key, limiter)
	return limiter
}

func LeakyBucketRateLimit() gin.HandlerFunc {
	cfg := config.GetConfig()
	mdl := NewMultiDimensionalLeakyBucket(cfg)

	return func(c *gin.Context) {
		if !cfg.Traffic.RateLimit.Enabled {
			c.Next()
			return
		}

		// 开启 OpenTelemetry 链路追踪，方便在 Jaeger 里看到限流耗时
		_, span := leakyBucketTracer.Start(c.Request.Context(), "RateLimit.LeakyBucket",
			trace.WithAttributes(attribute.String("path", c.Request.URL.Path)))
		defer span.End()

		// 检查全局限流
		// --- 第一关：全局限流 (Global) ---
		// 保护整个网关不被压垮。
		// 逻辑：如果全局桶存在，且 Allow() 返回 false (桶满了)，则拒绝。
		if mdl.globalLimiter != nil && !mdl.globalLimiter.Allow() {
			rejectRequest(c, span, "global", "", cfg.Traffic.RateLimit.QPS, cfg.Traffic.RateLimit.Burst)
			return
		}

		// 检查IP限流（这里假设配置中增加了IP限流规则）
		// --- 第二关：IP 维度限流 (IP) ---
		// 保护网关不被单个 IP 攻击。
		clientIP := c.ClientIP()
		ipQPS := cfg.Traffic.RateLimit.QPS / 2 // 示例：IP限流为全局的一半
		ipBurst := cfg.Traffic.RateLimit.Burst / 2
		ipLimiter := mdl.getOrCreateLimiter("ip", clientIP, ipQPS, ipBurst)
		if !ipLimiter.Allow() {
			rejectRequest(c, span, "ip", clientIP, ipQPS, ipBurst) // 拒绝并标记是被 IP 规则拦下的
			return
		}

		// 检查路由限流（这里假设配置中增加了路由限流规则）
		// --- 第三关：路由维度限流 (Route) ---
		// 保护特定接口不被刷爆。
		route := c.Request.URL.Path
		routeQPS := cfg.Traffic.RateLimit.QPS // 示例：使用全局QPS
		routeBurst := cfg.Traffic.RateLimit.Burst
		routeLimiter := mdl.getOrCreateLimiter("route", route, routeQPS, routeBurst)
		if !routeLimiter.Allow() {
			rejectRequest(c, span, "route", route, routeQPS, routeBurst)
			return
		}
		// --- 全部通过 ---
		span.SetStatus(codes.Ok, "Request allowed by leaky bucket")
		c.Next() // 放行，进入下一个中间件或业务逻辑
	}
}

func rejectRequest(c *gin.Context, span trace.Span, dimension, key string, qps, burst int) {
	//记录日志
	logger.Warn("Rate limit exceeded with leaky bucket",
		zap.String("dimension", dimension),
		zap.String("key", key),
		zap.String("clientIP", c.ClientIP()),
		zap.String("path", c.Request.URL.Path),
		zap.Int("qps", qps),
		zap.Int("burst", burst))
	//链路追踪状态 (Tracing)
	span.SetStatus(codes.Error, "Rate limit exceeded")
	//监控指标
	observability.RateLimitRejections.WithLabelValues(c.Request.URL.Path).Inc()

	//返回响应 (HTTP Response)
	c.JSON(http.StatusTooManyRequests, gin.H{
		"error":     "Request rate limit exceeded",
		"dimension": dimension,
		"key":       key,
		"qps":       qps,
		"burst":     burst,
	})
	//中断请求
	c.Abort()
}

// 为什么需要它？
// 在你的 NewLeakyBucketLimiter 实现中，每创建一个限流器，就会启动一个后台 Goroutine 去不断地从 Channel 里“漏水”。
// 如果不显式停止它们，当你重载配置（Reload Config）或者优雅关闭服务时，
// 这些 Goroutine 会一直跑，变成 孤儿协程 (Goroutine Leak)，白白消耗 CPU 和内存。
func CleanupLeakyBucket(mdl *MultiDimensionalLeakyBucket) {
	if mdl.globalLimiter != nil {
		mdl.globalLimiter.Stop()
	}
	mdl.ipLimiters.Range(func(key, value interface{}) bool {
		value.(*LeakyBucketLimiter).Stop()
		return true
	})
	mdl.routeLimiters.Range(func(key, value interface{}) bool {
		value.(*LeakyBucketLimiter).Stop()
		return true
	})
	logger.Info("MultiDimensionalLeakyBucket resources cleaned up")
}
