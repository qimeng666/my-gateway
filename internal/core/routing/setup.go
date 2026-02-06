package routing

import (
	"os"
	"strings"

	"github.com/penwyp/mini-gateway/internal/core/routing/proxy"
	internalrouter "github.com/penwyp/mini-gateway/internal/core/routing/router"

	"github.com/gin-gonic/gin"
	"github.com/penwyp/mini-gateway/config"
	"github.com/penwyp/mini-gateway/pkg/logger"
	"go.uber.org/zap"
)

// isRegexPattern 检查路径是否包含正则表达式字符
// 这是一个工具函数，通过检查是否包含 * . ? [] 等特殊字符来判断一个 path 是静态的（如 /api/user）还是动态正则的（如 /api/v\d+）
func isRegexPattern(path string) bool {
	return strings.ContainsAny(path, ".*+?()|[]^$\\")
}

// validateRules 验证路由规则与配置的引擎兼容性
func validateRules(cfg *config.Config) {
	engine := cfg.Routing.Engine // 获取配置里的引擎类型，例如 "trie" 或 "regexp"
	rules := cfg.Routing.Rules   // 获取所有路由规则

	for path, pathEndpoints := range rules { // 遍历每一条配置的路由
		for _, endpoint := range pathEndpoints {
			// 跳过 gRPC 的进一步验证，因其有单独处理
			// 1. gRPC 协议有专门的代理逻辑，不受 HTTP 路由引擎限制，所以跳过
			if endpoint.Protocol == "grpc" {
				continue
			}
			// Trie 引擎不支持正则表达式路径
			// 2. 检查冲突：如果你用了 "trie" (前缀树) 引擎，但路径里却写了正则符号
			if engine == "trie" && isRegexPattern(path) {
				logger.Error("Trie routing engine does not support regular expression paths",
					zap.String("path", path),
					zap.String("hint", "Use 'trie-regexp' or 'regexp' engine for regex support"))
				os.Exit(1)
			}
			// 除 trie-regexp 和 regexp 外的非正则引擎无法处理正则路径
			// 3. 检查兼容性：如果路径是正则，且引擎不是专门支持正则的那两款
			if isRegexPattern(path) && engine != "trie-regexp" && engine != "regexp" {
				logger.Error("Routing engine incompatible with regular expression path",
					zap.String("engine", engine),
					zap.String("path", path),
					zap.String("hint", "Use 'trie-regexp' or 'regexp' engine for regex support"))
				os.Exit(1)
			}
		}
	}
}

// Setup 初始化路由引擎并配置路由规则，包括 gRPC 和 WebSocket 代理
// 参数 protected: 已经挂载了 Auth 中间件的 Gin 路由组
// 参数 httpProxy: 我们之前分析过的，负责负载均衡和转发的核心组件
func Setup(protected gin.IRouter, httpProxy *proxy.HTTPProxy, cfg *config.Config) {
	logger.Info("Loading routing rules from configuration",
		zap.Any("rules", cfg.Routing.Rules))
	validateRules(cfg)

	// 根据配置选择并初始化适当的路由引擎
	// 2. 路由引擎工厂模式 (Factory Pattern)
	// 根据配置文件中的 routing.engine 字段，实例化不同的 Router 接口实现
	var router internalrouter.Router
	switch cfg.Routing.Engine {
	case "trie":
		// 初始化前缀树路由（查找速度极快，但不支持正则）
		router = internalrouter.NewTrieRouter()
		logger.Info("Initialized Trie routing engine")
	case "trie-regexp", "trie_regexp": // 支持连字符和下划线两种变体
		// 初始化混合路由（静态路径用 Trie，动态路径用正则，兼顾性能与灵活）
		router = internalrouter.NewTrieRegexpRouter()
		logger.Info("Initialized Trie-Regexp routing engine")
	case "regexp":
		// 初始化纯正则路由（最灵活，但性能相对较低）
		router = internalrouter.NewRegexpRouter(cfg)
		logger.Info("Initialized Regexp routing engine")
	case "gin":
		// 使用 Gin 框架自带的路由算法（基准）
		router = internalrouter.NewGinRouter()
		logger.Info("Initialized Gin routing engine")
	default:
		// 兜底策略：如果配错了，默认用 Gin
		logger.Warn("Unknown routing engine specified, defaulting to Gin",
			zap.String("engine", cfg.Routing.Engine))
		router = internalrouter.NewGinRouter()
	}

	// 为 gRPC 和 WebSocket 路由创建分组，使用配置中的前缀
	// 3. 创建协议专用的路由组
	// 例如：grpcGroup 对应 /grpc，wsGroup 对应 /websocket
	// 这样做是为了让不同协议的请求在 URL 层面就隔离开
	grpcGroup := protected.Group(cfg.GRPC.Prefix)
	wsGroup := protected.Group(cfg.WebSocket.Prefix)

	// 配置 HTTP 路由
	// 4. 【关键步骤】配置 HTTP 路由
	// 调用具体引擎实现的 Setup 方法。
	// 这里会将具体的 path (如 /api/user) 和 httpProxy (转发逻辑) 绑定起来。
	router.Setup(protected, httpProxy, cfg)

	// 如果启用且存在规则，配置 gRPC 代理
	if cfg.GRPC.Enabled && len(cfg.Routing.GetGrpcRules()) > 0 {
		proxy.SetupGRPCProxy(cfg, grpcGroup)
	}

	// 如果启用且存在规则，配置 WebSocket 代理
	// 6. 配置 WebSocket 代理 (如果开启)
	// 类似 gRPC，初始化专门的 WebSocket 代理器并绑定到 wsGroup
	if cfg.WebSocket.Enabled && len(cfg.Routing.GetWebSocketRules()) > 0 {
		wsProxy := proxy.NewWebSocketProxy(cfg)
		wsProxy.SetupWebSocketProxy(wsGroup, cfg)
		logger.Info("WebSocket proxy configured successfully")
	}

	// 为特定引擎中的动态路由注册空处理器
	switch cfg.Routing.Engine {
	case "trie", "trie_regexp", "regexp":
		// 遍历所有 HTTP 规则
		for p := range cfg.Routing.GetHTTPRules() {
			// 空处理器依赖特定 Router 实现中的中间件
			// protected.Any(p, func(c *gin.Context) {})
			protected.Any(p, func(c *gin.Context) {})
		}
	}
}
