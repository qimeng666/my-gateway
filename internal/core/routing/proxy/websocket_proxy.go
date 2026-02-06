package proxy

import (
	"context"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/penwyp/mini-gateway/pkg/util"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/penwyp/mini-gateway/config"
	"github.com/penwyp/mini-gateway/internal/core/health"
	"github.com/penwyp/mini-gateway/internal/core/loadbalancer"
	"github.com/penwyp/mini-gateway/internal/core/observability"
	"github.com/penwyp/mini-gateway/pkg/logger"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// websocketTracer 为 WebSocket 代理操作初始化追踪器
var websocketTracer = otel.Tracer("proxy:websocket")

// WebSocketProxy 管理 WebSocket 代理，包括连接池和负载均衡
type WebSocketProxy struct {
	pool *WebSocketPool            // WebSocket 连接池
	lb   loadbalancer.LoadBalancer // 负载均衡器
}

// NewWebSocketProxy 根据配置创建并初始化 WebSocketProxy 实例
func NewWebSocketProxy(cfg *config.Config) *WebSocketProxy {
	// 1. 尝试初始化配置里指定的负载均衡器 (如 "round-robin", "random")
	lb, err := loadbalancer.NewLoadBalancer(cfg.Routing.LoadBalancer, cfg)
	if err != nil {
		logger.Error("Failed to initialize load balancer",
			zap.String("type", cfg.Routing.LoadBalancer),
			zap.Error(err))
		lb = loadbalancer.NewRoundRobin() // 初始化失败时回退到轮询
	}
	return &WebSocketProxy{
		pool: NewWebSocketPool(cfg),
		lb:   lb,
	}
}

// SetupWebSocketProxy 根据提供的规则配置 WebSocket 代理路由
func (wp *WebSocketProxy) SetupWebSocketProxy(r gin.IRouter, cfg *config.Config) {
	rules := cfg.Routing.GetWebSocketRules()
	if len(rules) == 0 {
		// 没配规则就直接跳过
		logger.Info("No WebSocket routing rules found in configuration")
		return
	}

	// 对象池优化：用于减少切片扩容带来的内存分配（在 createWebSocketHandler 里会用到）
	poolMgr := util.NewPoolManager(cfg)

	// 【核心组件】Upgrader
	// 这是 gorilla/websocket 提供的工具，用于把 HTTP 协议“升级”为 WebSocket 协议
	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		// 【重要】允许跨域 (CORS)
		// 浏览器默认限制跨域 WS 连接，这里 return true 表示允许所有来源连接。
		// 生产环境通常需要根据 origin 也就是 cfg 来做判断
		CheckOrigin: func(r *http.Request) bool {
			return true // 可根据配置调整跨源策略
		},
	}

	// 遍历配置，注册路由
	for path, targetRules := range rules {
		logger.Info("Setting up WebSocket proxy route",
			zap.String("path", path),
			zap.Any("targets", targetRules))
		// 注意：WebSocket 握手本质上是一个 HTTP GET 请求，带 Upgrade 头。
		// 所以这里用 r.GET 注册路由。
		r.GET(path, wp.createWebSocketHandler(targetRules, upgrader, cfg, poolMgr))
	}
}

// createWebSocketHandler 创建 WebSocket 连接的处理函数
func (wp *WebSocketProxy) createWebSocketHandler(rules config.RoutingRules, upgrader websocket.Upgrader, cfg *config.Config, poolMgr *util.ObjectPoolManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 从 HTTP 请求头中提取追踪上下文
		ctx := otel.GetTextMapPropagator().Extract(c.Request.Context(), propagation.HeaderCarrier(c.Request.Header))
		ctx, connectSpan := websocketTracer.Start(ctx, "WebSocket.Connect",
			trace.WithAttributes(attribute.String("path", c.Request.URL.Path)))
		defer connectSpan.End()

		// 将客户端连接升级为 WebSocket
		// 2. 【核心动作】协议升级 (HTTP -> WebSocket)
		// 这一步会发送 HTTP 101 Switching Protocols 响应。
		// 之后，c.Writer 和 c.Request 就被“劫持”了，变成了一个长连接 clientConn。
		clientConn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
		if err != nil {
			// 升级失败（比如客户端没发 Upgrade 头），记录错误并返回 500
			connectSpan.RecordError(err)
			connectSpan.SetStatus(codes.Error, "Failed to upgrade connection")
			logger.Error("Failed to upgrade client connection to WebSocket",
				zap.String("path", c.Request.URL.Path),
				zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to upgrade to WebSocket"})
			return
		}
		// 确保函数结束（连接断开）时关闭连接
		defer clientConn.Close()

		// 跟踪活跃的 WebSocket 连接数
		// 3. 监控指标：活跃连接数 +1
		observability.ActiveWebSocketConnections.Inc()
		defer observability.ActiveWebSocketConnections.Dec()

		// 使用对象池管理器获取目标切片
		// 4. 获取目标列表
		// 从 poolMgr 借一个切片，避免 make([]string) 产生 GC
		targets := poolMgr.GetTargets(len(rules))
		defer poolMgr.PutTargets(targets)

		for _, rule := range rules {
			targets = append(targets, rule.Target)
		}
		// 5. 负载均衡选择
		target := wp.lb.SelectTarget(targets, c.Request)
		if target == "" {
			// 没选出来（比如后端全挂了），告诉客户端并在日志报错
			connectSpan.SetStatus(codes.Error, "No available target")
			logger.Warn("No available WebSocket target found",
				zap.String("path", c.Request.URL.Path))
			clientConn.WriteMessage(websocket.TextMessage, []byte("No available target"))
			return
		}
		logger.Debug("Selected WebSocket target by load balancer",
			zap.String("target", target))

		// 验证目标是否为有效的 WebSocket URL
		// 6. 校验目标地址格式 (必须是 ws:// 或 wss://)
		targetURL, err := url.Parse(target)
		if err != nil || (targetURL.Scheme != "ws" && targetURL.Scheme != "wss") {
			// 如果配置写错了，扣除该节点的健康分，并断开
			health.GetGlobalHealthChecker().UpdateRequestCount(target, false)
			connectSpan.RecordError(err)
			connectSpan.SetStatus(codes.Error, "Invalid backend URL")
			logger.Error("Invalid WebSocket target URL detected",
				zap.String("target", target),
				zap.Error(err))
			clientConn.WriteMessage(websocket.TextMessage, []byte("Invalid target address"))
			return
		}

		// 调整请求路径，去除 WebSocket 前缀
		// 7. 【路径剥离】(Path Stripping)
		// 例子：
		//   配置 Prefix: "/ws"
		//   用户请求: "ws://gateway/ws/chat/123"
		//   originalPath: "/ws/chat/123"
		//   adjustedPath: "/chat/123" (去掉了 /ws)
		originalPath := c.Request.URL.Path
		wsPrefix := cfg.WebSocket.Prefix
		adjustedPath := strings.TrimPrefix(originalPath, wsPrefix)
		if adjustedPath == originalPath {
			logger.Warn("Request path lacks WebSocket prefix, no adjustment applied",
				zap.String("path", originalPath),
				zap.String("prefix", wsPrefix))
		} else {
			logger.Info("Adjusted WebSocket path by removing prefix",
				zap.String("originalPath", originalPath),
				zap.String("adjustedPath", adjustedPath),
				zap.String("prefix", wsPrefix))
		}

		// 构造完整的转发目标 URL
		fullTarget := target // e.g., "ws://192.168.1.5:8080"
		if adjustedPath != "" && adjustedPath != "/" {
			// 合并后：ws://192.168.1.5:8080/chat/123
			targetURL.Path = path.Join(targetURL.Path, adjustedPath)
			fullTarget = targetURL.String()
		}
		logger.Debug("Determined final WebSocket forwarding target",
			zap.String("fullTarget", fullTarget))

		// 从连接池获取或创建后端 WebSocket 连接
		// 8. 连接后端
		// wp.pool.GetConn 这里不一定是复用连接，对于 WS 来说，通常是发起一个新的 Dial。
		// 这一步完成后，网关手里有了两个连接：
		//   clientConn (连着用户)
		//   backendConn (连着后端)
		backendConn, err := wp.pool.GetConn(fullTarget) // fullTarget 比如是 "ws://192.168.1.5:8080/chat"
		if err != nil {
			health.GetGlobalHealthChecker().UpdateRequestCount(target, false)
			connectSpan.RecordError(err)
			connectSpan.SetStatus(codes.Error, "Failed to connect to backend")
			logger.Error("Failed to establish backend WebSocket connection",
				zap.String("fullTarget", fullTarget),
				zap.Error(err))
			clientConn.WriteMessage(websocket.TextMessage, []byte("Backend connection failed"))
			return
		}

		// 双向转发客户端与后端之间的消息
		// 9. 建立错误通道
		// 缓冲区为 2，因为有两个协程可能报错。
		errCh := make(chan error, 2)
		// 10. 启动两个搬运工
		// 协程 A: 客户端 -> 网关 -> 后端
		go wp.forwardMessages(ctx, clientConn, backendConn, "client-to-backend", errCh)
		// 协程 B: 后端 -> 网关 -> 客户端
		go wp.forwardMessages(ctx, backendConn, clientConn, "backend-to-client", errCh)

		// 11. 【阻塞等待】
		// 主协程在这里卡住，等待 errCh 里出现错误。
		// 只要任意一方断开连接（ReadMessage 报错），这里就会收到信号。
		if err := <-errCh; err != nil {
			health.GetGlobalHealthChecker().UpdateRequestCount(target, false)
			connectSpan.RecordError(err)
			connectSpan.SetStatus(codes.Error, "Message forwarding failed")
			logger.Error("WebSocket message forwarding failed",
				zap.String("path", c.Request.URL.Path),
				zap.String("fullTarget", fullTarget),
				zap.Error(err))
		}
	}
}

// forwardMessages 在两个 WebSocket 连接之间转发消息
func (wp *WebSocketProxy) forwardMessages(ctx context.Context, from, to *websocket.Conn, direction string, errCh chan<- error) {
	for {
		// 1. 每转发一条消息，都记录一个 Span (用于精细化追踪)
		_, span := websocketTracer.Start(ctx, "WebSocket.Message",
			trace.WithAttributes(attribute.String("direction", direction)))
		// 2. 读消息 (阻塞)
		// msgType: 文本(TextMessage) 或 二进制(BinaryMessage)
		// msg: 消息内容 []byte
		// 这行代码会“卡住” (Block)，直到对方发来消息，或者断开连接。
		// 只要连接不断，这个 for 循环就永远不会结束！
		msgType, msg, err := from.ReadMessage()
		if err != nil {
			// 读失败（通常意味着连接断开了），发送错误给主协程，退出循环
			span.RecordError(err)
			span.SetStatus(codes.Error, "Failed to read message")
			span.End()
			errCh <- err
			return
		}
		// 3. 写消息
		// 原封不动地发给另一端
		err = to.WriteMessage(msgType, msg)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "Failed to write message")
			span.End()
			errCh <- err
			return
		}
		// 4. 成功：记录状态
		span.SetStatus(codes.Ok, "Message forwarded successfully")
		// 这里认为只要能成功写入，接收方就是健康的
		health.GetGlobalHealthChecker().UpdateRequestCount(to.LocalAddr().String(), true)
		span.End()
	}
}

// Close 关闭 WebSocket 代理并释放资源
func (wp *WebSocketProxy) Close() {
	// 关闭连接池，断开所有闲置或活跃的后端连接
	wp.pool.Close()
	logger.Info("WebSocket proxy closed successfully")
}
