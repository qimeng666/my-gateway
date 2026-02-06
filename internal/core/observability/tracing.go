package observability

import (
	"context"

	"github.com/penwyp/mini-gateway/config"
	"github.com/penwyp/mini-gateway/pkg/logger"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.uber.org/zap"
)

// InitTracing 初始化分布式追踪（使用 Jaeger），根据配置决定是否启用
// 返回一个清理资源的关闭函数
// InitTracing: 接收配置对象，返回一个“清理函数” (用于 main.go 里 defer 调用)
func InitTracing(cfg *config.Config) func(context.Context) error {
	// 1. 检查配置开关
	if !cfg.Observability.Jaeger.Enabled {
		logger.Info("Jaeger tracing is disabled in configuration")
		// 如果没开，直接返回一个空的关闭函数，什么都不做
		return func(ctx context.Context) error { return nil } // 无操作的关闭函数
	}
	logger.Info("Jaeger tracing is enabled in configuration")

	// 2. 创建 OTLP HTTP 导出器
	// "Exporter" 负责把内存里的 Trace 数据搬运到 Jaeger 服务器
	exporter, err := otlptracehttp.New(context.Background(),
		// 设置 Jaeger 的地址 (例如 "localhost:4318")
		otlptracehttp.WithEndpoint(cfg.Observability.Jaeger.Endpoint),
		// 设置 API 路径，标准 OTLP 是 /v1/traces
		otlptracehttp.WithURLPath("/v1/traces"),
		// 禁用 TLS (HTTPS)。因为我们在本地 docker 跑 Jaeger，通常是不加密的 HTTP
		otlptracehttp.WithInsecure(), // 本地测试禁用 TLS，生产环境需配置
	)
	if err != nil {
		logger.Error("Failed to initialize OTLP exporter",
			zap.String("endpoint", cfg.Observability.Jaeger.Endpoint),
			zap.Error(err))
		panic(err) // 致命错误，生产环境建议优雅处理
	}

	// 3. 决定“采样率”
	// 并不是所有请求都需要记录。如果 QPS 很高，全记录会把磁盘撑爆。
	var sampler sdktrace.Sampler
	switch cfg.Observability.Jaeger.Sampler {
	case "always":
		// 开发环境常用：记录 100% 的请求
		sampler = sdktrace.AlwaysSample()
	case "ratio":
		// 生产环境常用：只记录一定比例 (如 10%)
		// ParentBased 意思是：如果上游请求已经有 Trace 了，我就跟着记；如果没有，我再按比例抽样。
		sampler = sdktrace.ParentBased(sdktrace.TraceIDRatioBased(cfg.Observability.Jaeger.SampleRatio))
	default:
		// 默认全记录，防止配置写错导致丢数据
		sampler = sdktrace.AlwaysSample()
		logger.Warn("Unknown sampler type detected, defaulting to 'always'",
			zap.String("sampler", cfg.Observability.Jaeger.Sampler))
	}

	// 定义服务资源信息
	// 4. 定义服务身份
	// 当你在 Jaeger 界面上筛选 "Service" 时，看到的名字就是这里定义的
	res, err := resource.New(context.Background(),
		resource.WithAttributes(
			semconv.ServiceNameKey.String("mini-gateway"),
			semconv.ServiceVersionKey.String("0.1.0"), // 可从全局版本变量获取
		),
	)
	if err != nil {
		logger.Error("Failed to create tracing resource",
			zap.Error(err))
		panic(err) // 致命错误，生产环境建议优雅处理
	}

	// 初始化 TracerProvider，包含导出器、资源和采样器
	// 5. 组装所有组件，创建 TracerProvider
	tp := sdktrace.NewTracerProvider(
		// Batcher: 不会每产生一条数据就发一次网络请求，而是攒一批再发，提高性能
		sdktrace.WithBatcher(exporter),
		// Resource: 贴上“我是 mini-gateway”的标签
		sdktrace.WithResource(res),
		// Sampler: 带上刚才决定的采样策略
		sdktrace.WithSampler(sampler),
	)

	// 6. [关键] 设置全局 Provider
	// 这样你在 breaker.go 或其他地方调用 otel.Tracer("xxx") 时，
	// 就会自动使用这里配置好的 tp，而不是默认的空实现。
	// 设置全局 TracerProvider 和 TextMapPropagator 用于追踪传播
	otel.SetTracerProvider(tp)
	// 7. 设置“传播器” (Propagator)
	// 它的作用是解析和注入 HTTP Header (比如 `traceparent` 头)
	// 让网关能把 TraceID 传给后端的微服务，把整个链路串起来。
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	logger.Info("Distributed tracing initialized successfully",
		zap.String("endpoint", cfg.Observability.Jaeger.Endpoint),
		zap.String("sampler", cfg.Observability.Jaeger.Sampler),
		zap.Float64("sampleRatio", cfg.Observability.Jaeger.SampleRatio))

	// 8. 返回 Shutdown 函数
	// 在 main.go 里，当网关退出时，会调用它，
	// 确保内存里还没发出去的 Trace 数据能强制刷新给 Jaeger。
	return tp.Shutdown // 返回清理函数以释放资源
}
