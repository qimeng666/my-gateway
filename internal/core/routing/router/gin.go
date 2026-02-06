package router

import (
	"github.com/gin-gonic/gin"
	"github.com/penwyp/mini-gateway/config"
	"github.com/penwyp/mini-gateway/internal/core/routing/proxy"
	"github.com/penwyp/mini-gateway/pkg/logger"
	"go.uber.org/zap"
)

// GinRouter 管理 Gin 框架的 HTTP 路由设置
type GinRouter struct {
	// 这里没有任何字段。
	// 为什么？因为 TrieRouter 需要存 Trie 树，RegexpRouter 需要存正则列表。
	// 而 GinRouter 不需要存任何状态，它把所有状态都交给 Gin 框架自己去管了。
}

// NewGinRouter 创建并初始化 GinRouter 实例
func NewGinRouter() *GinRouter {
	logger.Info("GinRouter initialized")
	return &GinRouter{} // 返回一个空结构体实例
}

// Setup 在提供的 Gin 路由器中配置 HTTP 路由规则
// 参数 r: Gin 的路由组（比如 main.go 里的 protected 组）
// 参数 httpProxy: 代理处理器工厂
// 参数 cfg: 全局配置
// Setup 在提供的 Gin 路由器中配置 HTTP 路由规则
func (gr *GinRouter) Setup(r gin.IRouter, httpProxy *proxy.HTTPProxy, cfg *config.Config) {
	// 1. 获取规则
	// 从配置里筛选出 HTTP 协议的规则（排除 gRPC/WebSocket）
	rules := cfg.Routing.GetHTTPRules()
	if len(rules) == 0 {
		logger.Warn("No HTTP routing rules found in configuration")
		return
	}

	// 为每个路径注册路由规则
	// 3. 遍历所有配置的路径
	// 例如 path="/api/user", targetRules=[{Target: "127.0.0.1:8080"}]
	for path, targetRules := range rules {
		logger.Info("Registering HTTP route",
			zap.String("path", path),
			zap.Any("targets", targetRules))

		// 4. 【核心差异点】直接使用 Gin 的 API
		// r.Any 意味着：无论请求是 GET, POST, PUT, DELETE...
		// 只要路径匹配 path，就执行后面的 Handler。
		//
		// 对比 Trie/Regexp 引擎：
		// Trie/Regexp 是用 r.Use() 注册一个全局中间件，自己拦截所有请求去匹配。
		// GinRouter 是为每一个 path 单独注册一个 handler。
		r.Any(path, httpProxy.CreateHTTPHandler(targetRules))
	}
}
