package proxy

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/penwyp/mini-gateway/config"
	"github.com/penwyp/mini-gateway/internal/core/health"
	"github.com/penwyp/mini-gateway/internal/core/observability"
	"github.com/penwyp/mini-gateway/pkg/logger"
	"github.com/penwyp/mini-gateway/proto/proto"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	gproto "google.golang.org/protobuf/proto"
)

// 它使用了 grpc-ecosystem/grpc-gateway 这个库，将外部进来的 RESTful HTTP 请求（比如 JSON 格式），自动转成 gRPC 协议发给后端，然后再把后端的 gRPC 响应转回 JSON 给前端。
// grpcTracer 为 gRPC 代理初始化追踪器
var grpcTracer = otel.Tracer("proxy:grpc")

// 新增：允许测试时注入自定义 gRPC 连接创建和处理器注册逻辑
// 这是一个非常有经验的写法。
// 它把 grpc.Dial 和 RegisterHelloServiceHandlerFunc 定义成了变量。
// 为什么？为了写单元测试 (Unit Test) 时可以方便地 Mock (替换) 掉它们，
// 而不需要真的去连一个 gRPC 服务器。
var newGRPCClient = func(target string, dialOpts ...grpc.DialOption) (*grpc.ClientConn, error) {
	return grpc.Dial(target, dialOpts...)
}

var registerHelloServiceHandlerFunc = proto.RegisterHelloServiceHandler

// SetupGRPCProxy 配置 HTTP 到 gRPC 的反向代理
func SetupGRPCProxy(cfg *config.Config, r gin.IRouter) {
	// 1. 创建 gRPC Gateway 的多路复用器 (Mux)
	// 它的作用类似于 Gin，用来把收到的 HTTP 请求路由到对应的 gRPC 方法上。
	mux := runtime.NewServeMux(
		// 自定义错误处理器：比如 gRPC 返回 "NOT_FOUND"，这里要负责把它转成 HTTP 404。
		runtime.WithErrorHandler(httpErrorHandler()),
		// 响应修改器：在返回 HTTP 响应前，加一些自定义 Header（如 X-Proxy-Type）。
		runtime.WithForwardResponseOption(httpResponseModifier),
	)

	// 2. gRPC 连接选项
	dialOpts := []grpc.DialOption{
		// 生产环境严禁使用 insecure！这里为了演示方便关掉了 TLS。
		grpc.WithTransportCredentials(insecure.NewCredentials()), // 本地测试用，生产环境需启用 TLS
		// 开启 OpenTelemetry 监控拦截器
		grpc.WithUnaryInterceptor(otelgrpc.UnaryClientInterceptor()),
	}

	// 遍历 gRPC 路由规则
	for route, rules := range cfg.Routing.GetGrpcRules() {
		for _, rule := range rules {
			if rule.Protocol != "grpc" {
				continue
			}

			// 3. 建立 gRPC 连接 (长连接)
			// 比如连上 "192.168.1.5:9090"
			conn, err := newGRPCClient(rule.Target, dialOpts...)
			if err != nil {
				logger.Error("Failed to establish gRPC connection",
					zap.String("target", rule.Target),
					zap.Error(err))
				continue
			}

			// 在设置期间注册 gRPC 服务处理器
			// 4. 【核心】注册 Service Handler
			// 这一步告诉 mux：“如果你收到了符合 HelloService 定义的 HTTP 请求，
			// 请通过 conn 这个连接，转发给后端的 HelloService。”
			// 注意：这里的 registerHelloServiceHandlerFunc 是硬编码的，
			// 意味着这个网关目前只支持转发 HelloService。通用网关通常需要动态加载 proto。
			if err := registerHelloServiceHandlerFunc(context.Background(), mux, conn); err != nil {
				logger.Error("Failed to register gRPC service handler",
					zap.String("target", rule.Target),
					zap.Error(err))
				conn.Close()
				continue
			}
			logger.Info("Successfully registered gRPC service handler",
				zap.String("path", route),
				zap.String("target", rule.Target))
		}

		// 处理带有上下文传播的传入请求
		// 注册 Gin 路由
		// 当用户访问 "POST /api/v1/hello" 时进入这里
		r.Any(route, func(c *gin.Context) {
			ctx, span := grpcTracer.Start(c.Request.Context(), "GRPCProxy.Handle",
				trace.WithAttributes(
					attribute.String("http.method", c.Request.Method),
					attribute.String("http.path", c.Request.URL.Path),
					attribute.String("grpc.prefix", cfg.GRPC.Prefix),
				))
			defer span.End()

			span.SetAttributes(attribute.String("grpc.routing.path", c.Request.URL.Path))

			// 6. 路径修剪 (Path Stripping)
			// 举例：
			//   Config Prefix: "/grpc"
			//   Original URL: "/grpc/v1/say_hello"
			//   Adjusted URL: "/v1/say_hello"
			// gRPC Gateway 需要匹配 proto 里定义的路径 (如 /v1/say_hello)，所以要把网关前缀去掉。
			req := c.Request
			// 规范化 URL，避免不必要的重定向
			if strings.HasSuffix(req.URL.Path, "/") {
				req.URL.Path = strings.TrimSuffix(req.URL.Path, "/")
			}
			// ... TrimPrefix 逻辑 ...

			originalPath := req.URL.Path
			grpcPrefix := cfg.GRPC.Prefix
			adjustedPath := strings.TrimPrefix(originalPath, grpcPrefix)
			if adjustedPath == originalPath {
				logger.Warn("Request path lacks gRPC prefix, no adjustment applied",
					zap.String("path", originalPath),
					zap.String("prefix", grpcPrefix))
			} else {
				logger.Info("Adjusted gRPC request path by removing prefix",
					zap.String("originalPath", originalPath),
					zap.String("adjustedPath", adjustedPath),
					zap.String("prefix", grpcPrefix))
				req.URL.Path = adjustedPath
			}

			// 将元数据传播到请求上下文中
			// 7. 传递 Metadata (Header)
			// 把 HTTP Header 里的 Request-ID 塞进 gRPC 的 Metadata 里，
			// 这样后端微服务也能拿到这个 ID，实现全链路追踪。
			ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("request-id", c.GetHeader("X-Request-ID")))
			req = req.WithContext(ctx)

			// 8. 【核心转发】
			// 使用 statusRecorder 包装一下 ResponseWriter，为了记录返回的状态码（给 HealthCheck 用）。
			start := time.Now()
			recorder := &statusRecorder{ResponseWriter: c.Writer, Status: http.StatusOK}
			// 调用 mux.ServeHTTP。
			// 这一步完成了神奇的转换：HTTP -> JSON Decode -> gRPC Request -> gRPC Call -> gRPC Response -> JSON Encode -> HTTP
			mux.ServeHTTP(recorder, req)

			// 9. 健康检查打点
			// 找出当前请求对应的 Target IP
			// 从路由规则中识别目标
			target := ""
			for _, rule := range cfg.Routing.GetGrpcRules()[route] {
				if rule.Protocol == "grpc" {
					target = rule.Target
					break
				}
			}
			// 根据 HTTP 状态码判断健康状况。
			// 比如 200 OK -> 成功；503 Service Unavailable -> 失败。
			health.GetGlobalHealthChecker().UpdateRequestCount(target, recorder.Status < http.StatusBadRequest)

			// 记录请求延迟
			// 10. 记录 Prometheus 监控指标
			duration := time.Since(start).Seconds()
			observability.RequestDuration.WithLabelValues(c.Request.Method, c.Request.URL.Path).Observe(duration)
			span.SetStatus(codes.Ok, "gRPC proxy completed successfully")
		})
		logger.Info("gRPC proxy route configured successfully",
			zap.String("path", route))
	}
}

// statusRecorder 捕获 HTTP 响应状态码
type statusRecorder struct {
	gin.ResponseWriter
	Status int
}

// WriteHeader 重写 WriteHeader 以捕获状态码
func (r *statusRecorder) WriteHeader(code int) {
	r.Status = code
	r.ResponseWriter.WriteHeader(code)
}

// httpErrorHandler 自定义 gRPC 请求的错误处理
func httpErrorHandler() runtime.ErrorHandlerFunc {
	return func(ctx context.Context, mux *runtime.ServeMux, marshaler runtime.Marshaler, w http.ResponseWriter, r *http.Request, err error) {
		// 把 gRPC error (e.g. Code: 5 NOT_FOUND) 转成 HTTP Status (404)
		st, _ := status.FromError(err)
		statusCode := fmt.Sprintf("%d", st.Code())
		path := r.URL.Path

		// 记录监控指标：比如 grpc_calls_total{code="5"} +1
		observability.GRPCCallsTotal.WithLabelValues(path, statusCode).Inc()
		logger.Error("gRPC request processing failed",
			zap.String("path", path),
			zap.String("statusCode", statusCode),
			zap.String("error", st.Message()))

		// 调用默认逻辑输出 JSON
		runtime.DefaultHTTPErrorHandler(ctx, mux, marshaler, w, r, err)
	}
}

// httpResponseModifier 为 HTTP 响应添加自定义头部
func httpResponseModifier(ctx context.Context, w http.ResponseWriter, _ gproto.Message) error {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		logger.Info("Metadata found in request context",
			zap.Any("metadata", md))
	} else {
		logger.Warn("No metadata found in request context")
	}
	// 比如加上 "X-Proxy-Type: grpc-gateway"
	// 让客户端知道这个响应是从 gRPC 网关过来的。
	w.Header().Set("X-Proxy-Type", "grpc-gateway")
	w.Header().Set("X-Powered-By", "mini-gateway")
	return nil
}
