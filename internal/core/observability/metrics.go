package observability

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// 定义全局 Prometheus 指标用于可观测性
var (
	// RequestsTotal 跟踪网关处理的请求总数，按方法、路径和状态码分类
	// RequestsTotal: 计数器 (Counter)
	// 作用：记录一共收到了多少请求。
	// 标签 (Labels)：Method (GET/POST), Path (/api/user), Status (200/500)。
	// 场景：在 Grafana 上画出 QPS 曲线，或者计算错误率 (500的数量 / 总数)。
	RequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_requests_total",
			Help: "Total number of requests processed by the gateway",
		},
		[]string{"method", "path", "status"},
	)

	// RequestDuration 测量请求延迟分布（单位：秒），按方法和路径分类
	// RequestDuration: 直方图 (Histogram)
	// 作用：记录请求处理花了多久。
	// Buckets (桶)：它把耗时分成了很多个区间（比如 <0.05s, <0.1s, <1s...）。
	// 场景：计算 P99 延迟（99%的请求都在多少毫秒内完成）。
	RequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "gateway_request_duration_seconds",
			Help:    "Request latency in seconds",
			Buckets: prometheus.DefBuckets, // 默认桶：0.005, 0.01, 0.025, ..., 10
		},
		[]string{"method", "path"},
	)

	// RateLimitRejections 统计因限流拒绝的请求数，按路径分类
	// RateLimitRejections: 计数器
	// 作用：记录被限流器（TokenBucket/LeakyBucket）拒绝了多少次。
	// 场景：如果这个数飙升，说明有人在刷接口，或者你的 QPS 阈值设太低了。
	RateLimitRejections = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_rate_limit_rejections_total",
			Help: "Total number of requests rejected due to rate limiting",
		},
		[]string{"path"},
	)

	// BreakerTrips 统计熔断器触发的次数，按路径分类
	// BreakerTrips: 计数器
	// 作用：记录熔断器跳闸了多少次。
	// 场景：如果这有数，说明你的后端服务挂了。
	BreakerTrips = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_breaker_trips_total",
			Help: "Total number of circuit breaker trips",
		},
		[]string{"path"},
	)

	// ActiveWebSocketConnections 跟踪当前活跃的 WebSocket 连接数
	// ActiveWebSocketConnections: 仪表 (Gauge)
	// 特点：数值可增可减（Counter 只能增）。
	// 作用：当前有多少人连着 WebSocket。
	// 场景：监控长连接服务器的负载压力。
	ActiveWebSocketConnections = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "gateway_websocket_connections_active",
			Help: "Number of active WebSocket connections",
		},
	)

	// JwtAuthFailures 统计 JWT 认证失败的次数，按路径分类
	// JwtAuthFailures: 计数器
	// 作用：记录 JWT 认证失败次数。
	// 场景：用来发现非法登录尝试。
	JwtAuthFailures = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_jwt_auth_failures_total",
			Help: "Total number of JWT authentication failures",
		},
		[]string{"path"},
	)

	// IPAclRejections 统计因 IP 访问控制列表拒绝的请求数，按路径和 IP 分类
	// IPAclRejections: 计数器
	// 作用：记录被黑白名单拦截的次数。包含 IP 标签，能直接看到是哪个 IP 在搞事。
	IPAclRejections = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_ip_acl_rejections_total",
			Help: "Total number of requests rejected by IP ACL",
		},
		[]string{"path", "ip"},
	)

	// AntiInjectionBlocks 统计因检测到注入行为而阻止的请求数，按路径分类
	// AntiInjectionBlocks: 计数器
	// 作用：记录被 SQL 注入/XSS 防护拦截的次数。
	AntiInjectionBlocks = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_anti_injection_blocks_total",
			Help: "Total number of requests blocked due to injection detection",
		},
		[]string{"path"},
	)

	// CacheHits 统计缓存命中的次数，按路径分类
	// CacheHits & CacheMisses: 计数器
	// 作用：记录缓存命中和未命中的次数。
	// 场景：计算缓存命中率 = Hits / (Hits + Misses)。如果命中率太低，说明缓存策略有问题。
	CacheHits = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_cache_hits_total",
			Help: "Total number of cache hits",
		},
		[]string{"method", "path", "taget"},
	)

	// CacheMisses 统计缓存未命中的次数，按路径分类
	CacheMisses = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_cache_misses_total",
			Help: "Total number of cache misses",
		},
		[]string{"method", "path", "taget"},
	)

	// GRPCCallsTotal 跟踪处理的 gRPC 调用总数，按路径和状态分类
	// GRPCCallsTotal: 计数器
	// 作用：专门统计 gRPC 调用的次数。
	GRPCCallsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_grpc_calls_total",
			Help: "Total number of gRPC calls processed by the gateway",
		},
		[]string{"path", "status"},
	)

	// MemoryAllocations 跟踪网关内存分配情况，按类型分类
	// MemoryAllocations: 仪表向量 (GaugeVec)
	// 作用：记录内存使用情况。
	MemoryAllocations = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "gateway_memory_allocations_bytes",
			Help: "Memory allocation in bytes by the gateway",
		},
		[]string{"type"}, // 类型可以是：heap, stack, system 等
	)

	// metricsInitialized 确保指标只初始化一次
	metricsInitialized bool
)

// InitMetrics 初始化所有 Prometheus 指标（如果尚未初始化）
func InitMetrics() {
	if metricsInitialized {
		return // 防止重复初始化
	}

	// 通过 promauto 在包级别自动注册指标，标记为已初始化
	metricsInitialized = true
}

// RegisterCustomCounter 注册自定义 Counter 指标
func RegisterCustomCounter(name, help string, labels []string) *prometheus.CounterVec {
	return promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_" + name,
			Help: help,
		},
		labels,
	)
}

// RegisterCustomGauge 注册自定义 Gauge 指标
func RegisterCustomGauge(name, help string) prometheus.Gauge {
	return promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "gateway_" + name,
			Help: help,
		},
	)
}

// RegisterCustomHistogram 注册自定义 Histogram 指标
func RegisterCustomHistogram(name, help string, labels []string, buckets []float64) *prometheus.HistogramVec {
	if buckets == nil {
		buckets = prometheus.DefBuckets // 未指定时使用默认桶
	}
	return promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "gateway_" + name,
			Help:    help,
			Buckets: buckets,
		},
		labels,
	)
}

// ResetMetrics 重置所有指标到初始状态（用于测试或特殊场景）
func ResetMetrics() {
	RequestsTotal.Reset()
	RequestDuration.Reset()
	RateLimitRejections.Reset()
	BreakerTrips.Reset()
	ActiveWebSocketConnections.Set(0)
	JwtAuthFailures.Reset()
	IPAclRejections.Reset()
	AntiInjectionBlocks.Reset()
	CacheHits.Reset()
	CacheMisses.Reset()
	GRPCCallsTotal.Reset()
	MemoryAllocations.Reset() // 重置内存分配指标
}
