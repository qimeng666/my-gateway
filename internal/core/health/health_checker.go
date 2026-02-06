package health

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"net/url"

	"github.com/gorilla/websocket"
	"github.com/penwyp/mini-gateway/config"
	"github.com/penwyp/mini-gateway/pkg/cache" // 引入 Redis 包
	"github.com/penwyp/mini-gateway/pkg/logger"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"
)

// TargetStatus 后端目标的状态信息
// 存储在 Redis 里的“病历本”，记录每个后端的详细指标
type TargetStatus struct {
	Rule              string    `json:"rule"`                // 归属的路由规则名
	URL               string    `json:"url"`                 // 后端地址 (127.0.0.1:8080)
	Protocol          string    `json:"protocol"`            // 协议 (http/grpc)
	RequestCount      int64     `json:"request_count"`       // 总请求数 (被动转发产生)
	SuccessCount      int64     `json:"success_count"`       // 成功次数 (200 OK)
	CacheHitCount     int64     `json:"cache_hit_count"`     // 缓存命中次数
	FailureCount      int64     `json:"failure_count"`       // 失败次数 (500/502)
	ProbeRequestCount int64     `json:"probe_request_count"` // 主动探测总次数
	ProbeSuccessCount int64     `json:"probe_success_count"` // 主动探测成功次数
	ProbeFailureCount int64     `json:"probe_failure_count"` // 主动探测失败次数
	LastProbeTime     time.Time `json:"last_probe_time"`     // 上次探测时间
	LastRequestTime   time.Time `json:"last_request_time"`   // 上次用户请求时间
}

// HealthChecker 健康检查服务
type HealthChecker struct {
	healthPaths map[string]string // 记录每个 IP 对应的检查路径 (如 10.0.0.1 -> /ping)
	mu          sync.RWMutex      // 读写锁，保护 healthPaths 的并发读写
	cfg         *config.Config    // 全局配置
	cleanupCh   chan struct{}     // 信号通道，用来优雅关闭后台协程
	ctx         context.Context   // 上下文，用于 Redis 操作
}

// Redis key 前缀
const (
	healthStatsPrefix = "mg:health:stats:"    // 健康检查状态
	cachePrefix       = "mg:cache:"           // 缓存内容
	reqCountPrefix    = "mg:cache:req_count:" // 请求计数
)

// GetHealthStatsKey 生成目标的健康状态 Redis 键
func GetHealthStatsKey(target string) string {
	return healthStatsPrefix + target
}

// GetCacheKey 生成缓存内容的 Redis 键
func GetCacheKey(method, path string) string {
	return cachePrefix + method + ":" + path
}

// GetPathReqCountKey 生成路径请求计数的 Redis 键
func GetPathReqCountKey(path string) string {
	return reqCountPrefix + path
}

var (
	globalHealthChecker *HealthChecker
	once                sync.Once
)

// GetGlobalHealthChecker 获取全局健康检查实例
func GetGlobalHealthChecker() *HealthChecker {
	return globalHealthChecker
}

// InitHealthChecker 创建并初始化健康检查服务
func InitHealthChecker(cfg *config.Config) *HealthChecker {
	logger.Info("Initializing health checker service")
	checker := &HealthChecker{
		healthPaths: make(map[string]string),
		cfg:         cfg,
		cleanupCh:   make(chan struct{}),
		ctx:         context.Background(),
	}

	// 清空 Redis 中所有健康检查和缓存相关键
	// 1. 清空 Redis 旧数据
	// 网关重启时，为了防止沿用上次运行留下的脏数据，先来一次大扫除。
	err := checker.clearRedisKeys()
	if err != nil {
		logger.Error("Failed to clear Redis keys", zap.Error(err))
	} else {
		logger.Info("Cleared all existing health stats and cache keys from Redis")
	}

	// 2. 加载目标
	// 把 config.yaml 里的后端列表读进来。
	checker.RefreshTargets(cfg)
	// 3. 启动心跳
	// 开启后台协程，开始周期性巡逻。
	go checker.startHeartbeat()

	once.Do(func() {
		globalHealthChecker = checker
	})
	// ... 单例模式赋值 ...
	return checker
}

// clearRedisKeys 清空 Redis 中所有相关键
func (h *HealthChecker) clearRedisKeys() error {
	// 定义要删的前缀：mg:health:*, mg:cache:*
	patterns := []string{
		healthStatsPrefix + "*",
		cachePrefix + "*",
		reqCountPrefix + "*",
	}
	for _, pattern := range patterns {
		keys, err := cache.Client.Keys(h.ctx, pattern).Result()
		if err != nil {
			return err
		}
		if len(keys) > 0 {
			// 使用 Pipeline (管道) 技术
			// Pipeline 可以把 100 次删除命令打包成 1 个网络包发给 Redis，极大提升性能。
			pipe := cache.Client.Pipeline()
			for _, key := range keys {
				pipe.Del(h.ctx, key)
			}
			_, err = pipe.Exec(h.ctx)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// RefreshTargets 刷新目标健康检查路径并初始化 Redis 数据
// 这个方法把配置文件里的静态规则，转换成 Redis 里的动态状态。
func (h *HealthChecker) RefreshTargets(cfg *config.Config) {
	h.mu.Lock() // 写操作，加互斥锁
	defer h.mu.Unlock()

	h.cfg = cfg
	h.healthPaths = make(map[string]string)

	// 遍历配置文件里的 rules
	for ruleName, rules := range cfg.Routing.Rules {
		for _, rule := range rules {
			// 归一化：把 "http://127.0.0.1:80" 变成 "127.0.0.1:80"
			host, err := NormalizeTarget(rule)
			if err != nil {
				logger.Error("Invalid target address",
					zap.String("target", rule.Target),
					zap.Error(err))
				continue
			}

			// 确定体检路径：如果没配，默认用 "/health"
			if rule.HealthCheckPath != "" {
				h.healthPaths[host] = rule.HealthCheckPath
			} else {
				h.healthPaths[host] = "/health"
			}

			// 初始化一个“全零”的状态对象
			stat := TargetStatus{
				Rule:              ruleName,
				URL:               rule.Target,
				Protocol:          rule.Protocol,
				RequestCount:      0,
				SuccessCount:      0,
				FailureCount:      0,
				ProbeRequestCount: 0,
				ProbeSuccessCount: 0,
				ProbeFailureCount: 0,
				LastProbeTime:     time.Time{},
			}
			// 保存到 Redis
			// 这样即使还没流量，Redis 里也能看到这个节点存在了。
			err = h.saveToRedis(host, &stat)
			if err != nil {
				logger.Error("Failed to initialize target in Redis",
					zap.String("target", host), zap.Error(err))
			} else {
				logger.Info("Initialized new health check target in Redis",
					zap.String("target", host),
					zap.String("protocol", rule.Protocol),
					zap.String("healthCheckPath", h.healthPaths[host]))
			}
		}
	}
	logger.Info("Health checker targets refreshed",
		zap.Int("totalTargets", len(h.healthPaths)))
}

// saveToRedis 保存目标状态到 Redis
func (h *HealthChecker) saveToRedis(target string, stat *TargetStatus) error {
	key := GetHealthStatsKey(target)
	data := map[string]interface{}{
		"rule":                stat.Rule,
		"url":                 stat.URL,
		"protocol":            stat.Protocol,
		"request_count":       stat.RequestCount,
		"success_count":       stat.SuccessCount,
		"cache_hit_count":     stat.CacheHitCount,
		"failure_count":       stat.FailureCount,
		"probe_request_count": stat.ProbeRequestCount,
		"probe_success_count": stat.ProbeSuccessCount,
		"probe_failure_count": stat.ProbeFailureCount,
		"last_probe_time":     stat.LastProbeTime.Unix(),
		"last_request_time":   stat.LastRequestTime.Unix(),
	}
	return cache.Client.HMSet(h.ctx, key, data).Err()
}

// loadFromRedis 从 Redis 加载目标状态
func (h *HealthChecker) loadFromRedis(target string) (*TargetStatus, error) {
	// 1. 拼 key
	// 比如 target="127.0.0.1:8080"，生成的 key 可能是 "mg:health:stats:127.0.0.1:8080"
	key := GetHealthStatsKey(target)
	data, err := cache.Client.HGetAll(h.ctx, key).Result()
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}

	// 5. 创建结构体对象
	// 这里先填那几个本来就是 string 类型的字段。
	// 因为类型匹配（都是 string），所以不需要转换，直接赋值。
	stat := &TargetStatus{
		Rule:     data["rule"],     // 比如 "rule_user_service"
		URL:      data["url"],      // 比如 "127.0.0.1:8080"
		Protocol: data["protocol"], // 比如 "http"
	}
	// 6. 解析 request_count
	// data["request_count"] 取出来可能是一个字符串 "1005"
	// strconv.ParseInt: Go 标准库函数，把字符串转成整数。
	//   - 参数1: 字符串
	//   - 参数2: 10 (十进制)
	//   - 参数3: 64 (转成 int64)
	if v, err := strconv.ParseInt(data["request_count"], 10, 64); err == nil {
		stat.RequestCount = v
	}
	if v, err := strconv.ParseInt(data["success_count"], 10, 64); err == nil {
		stat.SuccessCount = v
	}
	if v, err := strconv.ParseInt(data["cache_hit_count"], 10, 64); err == nil {
		stat.CacheHitCount = v
	}
	if v, err := strconv.ParseInt(data["failure_count"], 10, 64); err == nil {
		stat.FailureCount = v
	}
	if v, err := strconv.ParseInt(data["probe_request_count"], 10, 64); err == nil {
		stat.ProbeRequestCount = v
	}
	if v, err := strconv.ParseInt(data["probe_success_count"], 10, 64); err == nil {
		stat.ProbeSuccessCount = v
	}
	if v, err := strconv.ParseInt(data["probe_failure_count"], 10, 64); err == nil {
		stat.ProbeFailureCount = v
	}
	if v, err := strconv.ParseInt(data["last_probe_time"], 10, 64); err == nil {
		stat.LastProbeTime = time.Unix(v, 0)
	}
	if v, err := strconv.ParseInt(data["last_request_time"], 10, 64); err == nil {
		stat.LastRequestTime = time.Unix(v, 0)
	}
	return stat, nil
}

// CheckCache 检查缓存是否存在并返回内容，同时更新缓存命中计数
func (h *HealthChecker) CheckCache(ctx context.Context, method, path, target string) (string, bool) {
	if cache.Client == nil {
		logger.Warn("Redis client not initialized, skipping cache check")
		return "", false
	}

	key := GetCacheKey(method, path)
	// 1. 查缓存内容
	content, err := cache.Client.Get(ctx, key).Result()
	if err == redis.Nil {
		logger.Debug("Cache miss", zap.String("key", key))
		return "", false
	} else if err != nil {
		logger.Error("Failed to check cache", zap.Error(err), zap.String("key", key))
		return "", false
	}

	// 更新缓存命中计数
	h.mu.Lock()
	defer h.mu.Unlock()
	// 2. 如果命中了，更新该后端的“缓存命中数”
	// 注意：这里是一个读-改-写操作，高并发下有竞争风险，但在统计场景下通常可以容忍微小误差。
	if stat, err := h.loadFromRedis(target); err == nil && stat != nil {
		stat.CacheHitCount++
		h.saveToRedis(target, stat)
	}

	logger.Debug("Cache hit", zap.String("key", key))
	return content, true
}

// SetCache 设置缓存内容并指定过期时间
func (h *HealthChecker) SetCache(ctx context.Context, method, path string, content string, ttl time.Duration) error {
	if cache.Client == nil {
		logger.Warn("Redis client not initialized, skipping cache set")
		return fmt.Errorf("redis client not initialized")
	}

	key := GetCacheKey(method, path)
	err := cache.Client.Set(ctx, key, content, ttl).Err()
	if err != nil {
		logger.Error("Failed to set cache", zap.Error(err), zap.String("key", key), zap.Duration("ttl", ttl))
		return err
	}

	logger.Debug("Cache set successfully", zap.String("key", key), zap.Duration("ttl", ttl))
	return nil
}

// IncrementRequestCount 增加指定路径的请求计数，返回当前计数
func (h *HealthChecker) IncrementRequestCount(ctx context.Context, path string, ttl time.Duration) int64 {
	key := GetPathReqCountKey(path)
	// 为什么要用 Lua 脚本？
	// 这里的需求是：如果 key 不存在，就 INCR (变成1)，并且立刻设置过期时间 (EXPIRE)。
	// 如果不用 Lua，分成两步写，可能第一步成功，第二步网关挂了，导致产生一个“永不过期”的 key (内存泄漏)。
	// Lua 脚本保证了这两步是原子性的：要么都做，要么都不做。
	script := redis.NewScript(`
		local key = KEYS[1]
		local ttl = ARGV[1]
		local count = redis.call('INCR', key)
		redis.call('EXPIRE', key, ttl)
		return count
	`)
	count, err := script.Run(ctx, cache.Client, []string{key}, ttl.Seconds()).Int64()
	if err != nil {
		logger.Error("Failed to increment request count with Lua", zap.Error(err), zap.String("key", key))
		return 0
	}
	return count
}

// NormalizeTarget 规范化目标地址
func NormalizeTarget(target config.RoutingRule) (string, error) {
	if target.Protocol == "grpc" {
		return target.Target, nil
	}
	u, err := url.Parse(target.Target)
	if err != nil {
		return "", err
	}
	return u.Host, nil
}

// NormalizeTargetHost 规范化目标主机地址
func NormalizeTargetHost(target string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return target, err
	}
	return u.Host, nil
}

// startHeartbeat 开始周期性心跳检测
func (h *HealthChecker) startHeartbeat() {
	// 创建一个打点器，每秒响一次（虽然 ticker 是 1s，但下面有个 Reset 控制实际间隔）
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-h.cleanupCh: // 收到停止信号，退出
			logger.Info("Stopping heartbeat checks")
			return
		case <-ticker.C: // 时间到了
			h.mu.RLock()
			// 读取配置里的间隔，比如 30秒
			heartbeatInterval := 30 * time.Second
			if h.cfg.Routing.HeartbeatInterval > 0 {
				heartbeatInterval = time.Duration(h.cfg.Routing.HeartbeatInterval) * time.Second
			}
			h.mu.RUnlock()

			// 执行一次全面检查
			h.performHeartbeatCheck()
			// 重置打点器，30秒后再响
			ticker.Reset(heartbeatInterval)
		}
	}
}

// performHeartbeatCheck 执行一次心跳检测
func (h *HealthChecker) performHeartbeatCheck() {
	h.mu.RLock()
	defer h.mu.RUnlock()

	logger.Info("Starting heartbeat check",
		zap.Int("targetCount", len(h.healthPaths)),
		zap.String("timestamp", time.Now().Format("2006-01-02 15:04:05")))

	// 遍历所有要检查的目标
	for target, healthPath := range h.healthPaths {
		// 1. 先从 Redis 读出旧状态（我们要保留之前的成功/失败次数，只更新 Probe 字段）
		stat, err := h.loadFromRedis(target)
		if err != nil || stat == nil {
			logger.Warn("Failed to load target stats from Redis",
				zap.String("target", target), zap.Error(err))
			continue
		}

		now := time.Now()
		stat.LastProbeTime = now
		// 2. 探测次数 +1
		stat.ProbeRequestCount++

		// 3. 根据协议分发检查任务
		switch stat.Protocol {
		case "http", "":
			h.checkHTTP(target, healthPath, stat)
		case "grpc":
			h.checkGRPC(target, stat)
		case "websocket":
			h.checkWebSocket(stat.URL, healthPath, stat)
		default:
			logger.Warn("Unsupported protocol, skipping health check",
				zap.String("protocol", stat.Protocol),
				zap.String("target", target))
		}

		// 保存更新后的状态到 Redis
		err = h.saveToRedis(target, stat)
		if err != nil {
			logger.Error("Failed to save target stats to Redis",
				zap.String("target", target), zap.Error(err))
		}
	}
}

// checkHTTP 检查 HTTP 目标健康状态
func (h *HealthChecker) checkHTTP(target, healthPath string, stat *TargetStatus) {
	// 使用 fasthttp 的对象池，零内存分配
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI("http://" + target + healthPath)
	// 构造请求：HEAD http://127.0.0.1:8080/health
	// 为什么用 HEAD？因为我们只需要知道服务器活着 (状态码 200)，不需要它传回网页内容，省流量。
	req.Header.SetMethod("HEAD")

	client := &fasthttp.Client{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	// 发送请求，设置 5秒 超时
	err := client.DoTimeout(req, resp, 5*time.Second)
	// 判断死活：报错 或者 状态码 >= 400 (比如 404, 500) 都算失败
	if err != nil || resp.StatusCode() >= 400 {
		stat.ProbeFailureCount++
		logger.Warn("HTTP heartbeat check failed",
			zap.String("target", target),
			zap.String("healthPath", healthPath),
			zap.Error(err),
			zap.Int("statusCode", resp.StatusCode()))
		return
	}
	stat.ProbeSuccessCount++
	logger.Info("HTTP heartbeat check succeeded",
		zap.String("target", target),
		zap.String("healthPath", healthPath))
}

// checkGRPC 检查 gRPC 目标健康状态
func (h *HealthChecker) checkGRPC(target string, stat *TargetStatus) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, target, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		stat.ProbeFailureCount++
		logger.Warn("gRPC dial failed",
			zap.String("target", target),
			zap.Error(err))
		return
	}
	defer conn.Close()

	healthPath, ok := h.healthPaths[target]
	if !ok {
		healthPath = "" // 默认检查整个服务器
	}

	client := grpc_health_v1.NewHealthClient(conn)
	serviceName := healthPath
	if serviceName == "/health" {
		serviceName = "" // 检查整个服务器
	}

	resp, err := client.Check(ctx, &grpc_health_v1.HealthCheckRequest{Service: serviceName})
	if err != nil || (resp != nil && resp.GetStatus() != grpc_health_v1.HealthCheckResponse_SERVING) {
		stat.ProbeFailureCount++
		var statusStr string
		if resp != nil {
			statusStr = resp.GetStatus().String()
		} else {
			statusStr = "UNKNOWN"
		}
		logger.Warn("gRPC health check failed",
			zap.String("target", target),
			zap.String("service", serviceName),
			zap.Error(err),
			zap.String("status", statusStr))
		return
	}

	stat.ProbeSuccessCount++
	logger.Info("gRPC health check succeeded",
		zap.String("target", target),
		zap.String("service", serviceName))
}

// checkWebSocket 检查 WebSocket 目标健康状态
func (h *HealthChecker) checkWebSocket(target, healthPath string, stat *TargetStatus) {
	dialer := websocket.DefaultDialer
	fullURL := target + healthPath
	conn, _, err := dialer.Dial(fullURL, nil)
	if err != nil {
		stat.ProbeFailureCount++
		logger.Warn("WebSocket heartbeat check failed",
			zap.String("target", target),
			zap.String("healthPath", healthPath),
			zap.String("fullURL", fullURL),
			zap.Error(err))
		return
	}
	defer conn.Close()
	stat.ProbeSuccessCount++
	logger.Info("WebSocket heartbeat check succeeded",
		zap.String("target", target),
		zap.String("healthPath", healthPath),
		zap.String("fullURL", fullURL))
}

// UpdateRequestCount 更新业务请求计数
func (h *HealthChecker) UpdateRequestCount(target string, success bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	host, _ := NormalizeTargetHost(target)
	// 1. 读 Redis
	stat, err := h.loadFromRedis(host)
	if err != nil || stat == nil {
		logger.Warn("Target not found in Redis, unable to update request count",
			zap.String("target", target), zap.Error(err))
		return
	}

	// 2. 改内存
	stat.RequestCount++
	if success {
		stat.SuccessCount++
	} else {
		stat.FailureCount++
	}
	stat.LastRequestTime = time.Now()

	// 3. 写 Redis
	err = h.saveToRedis(host, stat)
	if err != nil {
		logger.Error("Failed to update target stats in Redis",
			zap.String("target", host), zap.Error(err))
	}
}

// ResetAllStats 重置所有后端目标的状态信息
func (h *HealthChecker) ResetAllStats() {
	h.mu.Lock()
	defer h.mu.Unlock()

	for target := range h.healthPaths {
		stat, err := h.loadFromRedis(target)
		if err != nil || stat == nil {
			continue
		}
		stat.RequestCount = 0
		stat.SuccessCount = 0
		stat.FailureCount = 0
		stat.ProbeRequestCount = 0
		stat.ProbeSuccessCount = 0
		stat.ProbeFailureCount = 0
		stat.LastProbeTime = time.Time{}
		err = h.saveToRedis(target, stat)
		if err != nil {
			logger.Error("Failed to reset target stats in Redis",
				zap.String("target", target), zap.Error(err))
		}
	}
	logger.Info("All target stats reset")
}

// GetAllStats 获取所有后端目标的状态信息
func (h *HealthChecker) GetAllStats() []TargetStatus {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var stats []TargetStatus
	for target := range h.healthPaths {
		stat, err := h.loadFromRedis(target)
		if err != nil {
			logger.Error("Failed to load target stats from Redis",
				zap.String("target", target), zap.Error(err))
			continue
		}
		if stat != nil {
			stats = append(stats, *stat)
		}
	}

	sort.Slice(stats, func(i, j int) bool {
		if stats[i].Protocol == stats[j].Protocol {
			return stats[i].URL < stats[j].URL
		}
		if stats[i].Rule == stats[j].Rule {
			return stats[i].Protocol < stats[j].Protocol
		}
		return stats[i].Rule < stats[j].Rule
	})
	return stats
}

// Close 关闭健康检查服务
func (h *HealthChecker) Close() {
	close(h.cleanupCh)
	logger.Info("Health checker service closed")
}
