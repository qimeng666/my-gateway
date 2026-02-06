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
	uberRatelimit "go.uber.org/ratelimit"
	"go.uber.org/zap"
)

var tokenBucketTracer = otel.Tracer("ratelimit:token-bucket")

// MultiDimensionalTokenBucket 管理多维度限流
type MultiDimensionalTokenBucket struct {
	globalLimiter *TokenBucketLimiter // 1. 全局限流器 (总闸)
	ipLimiters    sync.Map            // map[string]*TokenBucketLimiter // 2. IP 限流器 (针对每个IP单独限流)
	routeLimiters sync.Map            // map[string]*TokenBucketLimiter // 3. 路由限流器 (针对每个API接口单独限流)
	config        *config.Config
	mutex         sync.Mutex // 用于创建新限流器时的并发锁
}

//globalLimiter: 限制整个网关每秒最多处理 10000 个请求。
//ipLimiters: 限制 IP 192.168.1.1 每秒最多发 10 个请求。
//routeLimiters: 限制接口 /api/login 每秒最多被调用 500 次。

type TokenBucketLimiter struct {
	limiter uberRatelimit.Limiter
}

func NewMultiDimensionalTokenBucket(cfg *config.Config) *MultiDimensionalTokenBucket {
	mdt := &MultiDimensionalTokenBucket{
		config: cfg,
	}

	if cfg.Traffic.RateLimit.Enabled {
		mdt.globalLimiter = NewTokenBucketLimiter(cfg.Traffic.RateLimit.QPS, cfg.Traffic.RateLimit.Burst)
	}

	return mdt
}

//核心概念讲解 (QPS vs Burst)：
//场景：你设置 QPS = 10 (每秒10个)。
//如果没有 Burst：请求必须匀速来，每 100ms 处理一个。如果一瞬间来了 10 个，第 1 个处理，后 9 个都要排队等待。
//如果有 Burst = 10：
//如果过去 1 秒没人访问，桶里就攒了 10 个令牌。
//下一秒突然来了 10 个请求（并发），因为桶里有库存，这 10 个请求瞬间同时通过，不需要排队。
//这就是令牌桶比漏桶（Leaky Bucket）优秀的地方：它允许突发流量。

func NewTokenBucketLimiter(qps, burst int) *TokenBucketLimiter {
	l := &TokenBucketLimiter{
		// uberRatelimit.New 是核心
		// qps: 每秒产生多少令牌
		// WithSlack(burst): 允许攒多少令牌 (应对突发流量)
		limiter: uberRatelimit.New(qps, uberRatelimit.WithSlack(burst)),
	}
	logger.Info("TokenBucketLimiter initialized",
		zap.Int("qps", qps),
		zap.Int("burst", burst))
	return l
}

func (tbl *TokenBucketLimiter) Take() time.Time {
	return tbl.limiter.Take()
}

func (mdt *MultiDimensionalTokenBucket) getOrCreateLimiter(dimension, key string, qps, burst int) *TokenBucketLimiter {
	// ... 决定查哪个 Map (ip 还是 route) ...

	var limiterMap *sync.Map
	if dimension == "ip" {
		limiterMap = &mdt.ipLimiters
	} else if dimension == "route" {
		limiterMap = &mdt.routeLimiters
	}

	// 1. 第一次检查：如果已经有了，直接返回 (快路径)
	if limiter, ok := limiterMap.Load(key); ok {
		return limiter.(*TokenBucketLimiter)
	}

	// 2. 加锁：防止两个请求同时创建一个新的限流器
	mdt.mutex.Lock()
	defer mdt.mutex.Unlock()

	// 3. 第二次检查 (Double Check)：可能在排队等锁的时候，别人已经创建好了
	if limiter, ok := limiterMap.Load(key); ok {
		return limiter.(*TokenBucketLimiter)
	}

	// 4. 真的没有，创建一个新的，存入 Map
	limiter := NewTokenBucketLimiter(qps, burst)
	limiterMap.Store(key, limiter)
	return limiter
}

//干了什么： 这是经典的 Double-Checked Locking (双重检查锁) 模式。
//例子：1000 个用户同时第一次访问 1.2.3.4 这个 IP。
//如果不加锁：系统可能会创建 1000 个限流器对象，浪费内存。
//如果只加锁不检查：所有请求都要排队，慢死。
//现在的做法：只有第 1 个请求会加锁创建，后面的 999 个直接读缓存，既安全又快。

func TokenBucketRateLimit() gin.HandlerFunc {
	cfg := config.GetConfig()
	mdt := NewMultiDimensionalTokenBucket(cfg)

	return func(c *gin.Context) {
		// 0. 开关检查
		if !cfg.Traffic.RateLimit.Enabled {
			c.Next()
			return
		}

		// ... 开启链路追踪 Span ...
		_, span := tokenBucketTracer.Start(c.Request.Context(), "RateLimit.TokenBucket",
			trace.WithAttributes(attribute.String("path", c.Request.URL.Path)))
		defer span.End()

		// 检查全局限流
		// 1. 第一道关卡：全局限流
		// 如果总流量超了，所有人都不许进
		if mdt.globalLimiter != nil {
			if !checkLimit(mdt.globalLimiter, c, span, "global", "") {
				return
			}
		}

		// 检查IP限流
		// 2. 第二道关卡：IP 限流
		// 防止某个恶意 IP 刷爆接口
		clientIP := c.ClientIP()
		// 注意：这里硬编码了策略，IP的限流阈值是全局的一半 (QPS/2)
		ipQPS := cfg.Traffic.RateLimit.QPS / 2
		ipBurst := cfg.Traffic.RateLimit.Burst / 2
		ipLimiter := mdt.getOrCreateLimiter("ip", clientIP, ipQPS, ipBurst)
		if !checkLimit(ipLimiter, c, span, "ip", clientIP) {
			return
		}

		// 检查路由限流
		// 3. 第三道关卡：路由限流
		// 防止某个耗时接口 (如 /download) 占满资源
		route := c.Request.URL.Path
		routeQPS := cfg.Traffic.RateLimit.QPS
		routeBurst := cfg.Traffic.RateLimit.Burst
		routeLimiter := mdt.getOrCreateLimiter("route", route, routeQPS, routeBurst)
		if !checkLimit(routeLimiter, c, span, "route", route) {
			return
		}

		span.SetStatus(codes.Ok, "Request allowed by token bucket")
		c.Next()
	}
}

func checkLimit(limiter *TokenBucketLimiter, c *gin.Context, span trace.Span, dimension, key string) bool {
	now := time.Now()                 // 记录当前时间
	takeTime := limiter.Take()        // 【核心】尝试拿令牌
	waitDuration := takeTime.Sub(now) // 计算拿令牌花了多久 (即“排队等待时间”)

	// 如果需要等待 (waitDuration > 0)，说明桶空了
	if waitDuration > 0 {
		// --- 拒绝流程 ---
		// 1. 记日志
		logger.Warn("Rate limit exceeded with token bucket",
			zap.String("dimension", dimension),
			zap.String("key", key),
			zap.String("clientIP", c.ClientIP()),
			zap.String("path", c.Request.URL.Path),
			zap.Duration("waitDuration", waitDuration))
		span.SetStatus(codes.Error, "Rate limit exceeded")
		// 2. 监控计数 +1
		observability.RateLimitRejections.WithLabelValues(c.Request.URL.Path).Inc()

		// 3. 返回 429 Too Many Requests
		c.JSON(http.StatusTooManyRequests, gin.H{
			"error":      "Request rate limit exceeded",
			"dimension":  dimension,
			"key":        key,
			"waitTimeMs": waitDuration.Milliseconds(),
		})
		c.Abort()
		return false
	}
	return true
}
