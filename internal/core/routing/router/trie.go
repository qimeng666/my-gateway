package router

import (
	"context"
	"net/http"
	"strings"

	"github.com/penwyp/mini-gateway/internal/core/routing/proxy"

	"github.com/gin-gonic/gin"
	"github.com/penwyp/mini-gateway/config"
	"github.com/penwyp/mini-gateway/pkg/logger"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// trieTracer 为 Trie 路由模块初始化追踪器
// trieTracer 初始化分布式追踪器，用于监控路由匹配耗时
var trieTracer = otel.Tracer("router:trie")

// TrieRouter 使用 Trie 数据结构管理 HTTP 路由
type TrieRouter struct {
	Trie *Trie // Trie 数据结构实例
}

// Trie 表示用于高效前缀匹配路由的 Trie 数据结构
type Trie struct {
	Root *TrieNode // Trie 的根节点
}

// TrieNode 表示 Trie 中的一个节点，包含子节点和路由规则
type TrieNode struct {
	Children map[rune]*TrieNode  // 子节点映射，核心：子节点映射。key是字符(rune)，value是下一个节点
	Rules    config.RoutingRules // 路由规则，负载：如果这个节点是一个路径的终点，这里存放转发规则(目标地址等)
	IsEnd    bool                // 标记此节点是否为有效路由的终点
}

// NewTrieRouter 创建并初始化 TrieRouter 实例
func NewTrieRouter() *TrieRouter {
	return &TrieRouter{
		Trie: &Trie{
			Root: &TrieNode{Children: make(map[rune]*TrieNode)},
		},
	}
}

// Insert 将路径及其关联的路由规则插入 Trie
func (t *Trie) Insert(path string, rules config.RoutingRules) {
	node := t.Root
	path = strings.TrimPrefix(path, "/") // 规范化路径，去除前导斜杠
	// 2. 遍历路径的每一个字符 (rune)
	// 例如 "api" 会遍历 'a', 'p', 'i'
	for _, ch := range path {
		// 如果当前节点的子节点里没有这个字符，就创建一个新节点
		if node.Children[ch] == nil {
			node.Children[ch] = &TrieNode{Children: make(map[rune]*TrieNode)}
		}
		// 指针下移，指向下一个节点
		node = node.Children[ch]
	}
	// 3. 循环结束，node 指向了路径的最后一个字符节点 (例如 'i')
	node.Rules = rules //保存路由规则 (比如转发到 127.0.0.1:8080)
	node.IsEnd = true
	logger.Info("Successfully inserted route into Trie",
		zap.String("path", "/"+path),
		zap.Any("rules", rules))
}

// Search 在 Trie 中查找给定路径的路由规则
func (t *Trie) Search(ctx context.Context, path string) (config.RoutingRules, bool) {
	// 1. 开启链路追踪，记录查找耗时
	ctx, span := trieTracer.Start(ctx, "Trie.Search",
		trace.WithAttributes(attribute.String("path", path)))
	defer span.End()

	node := t.Root
	path = strings.TrimPrefix(path, "/") // 规范化路径，去除前导斜杠
	path = strings.TrimSuffix(path, "/") // 去除尾部斜杠以保持一致性

	// 3. 逐个字符遍历请求路径
	for _, ch := range path {
		// 如果走到某一步断了（比如树里只有 'a'-'p'-'i'，但请求是 'a'-'p'-'p'）
		if node.Children[ch] == nil {
			return nil, false
		}
		node = node.Children[ch]
	}
	// 4. 路径走完了，检查当前节点是不是一个“终点”
	// 注意：如果树里有 "/api/user"，但你请求 "/api"，虽然能走完字符，但 'i' 节点可能 IsEnd=false
	if node.IsEnd {
		return node.Rules, true
	} // 找到了，返回规则
	return nil, false // 没找到
}

// Setup 根据配置在 Gin 路由器中设置 TrieRouter 的 HTTP 路由规则
func (tr *TrieRouter) Setup(r gin.IRouter, httpProxy *proxy.HTTPProxy, cfg *config.Config) {
	rules := cfg.Routing.GetHTTPRules()
	// exmaple:
	//"/api/v1/user": []config.RoutingRule{
	//        {
	//            Target:          "http://127.0.0.1:8381",
	//            Weight:          50,
	//            Env:             "stable",
	//            Protocol:        "http",
	//            HealthCheckPath: "/status",
	//        },
	//        {
	//            Target:          "http://127.0.0.1:8383",
	//            Weight:          25,
	//            Env:             "canary",
	//            Protocol:        "http",
	//            HealthCheckPath: "/status",
	//        },
	//        {
	//            Target:          "http://127.0.0.1:8383",
	//            Weight:          20,
	//            Env:             "canary",
	//            Protocol:        "http",
	//            HealthCheckPath: "/status",
	//        },
	//    },
	if len(rules) == 0 {
		logger.Warn("No HTTP routing rules found in configuration")
		return
	}

	// 将所有路由规则插入 Trie
	// 2. 构建树：把所有配置里的路径插入 Trie
	for path, targetRules := range rules {
		tr.Trie.Insert(path, targetRules)
	}
	logger.Info("Trie routing setup completed",
		zap.Int("ruleCount", len(rules)))
	// 3. 注册全局中间件！！！
	// r.Use 意味着所有进入这个 RouterGroup 的请求，都会先执行这个匿名函数
	// 中间件：处理路由匹配和代理转发
	r.Use(func(c *gin.Context) {
		// --- 请求处理开始 ---
		// 开始追踪路由匹配过程
		// a. 开启追踪
		ctx, span := trieTracer.Start(c.Request.Context(), "Routing.Match",
			trace.WithAttributes(attribute.String("type", "Trie")),
			trace.WithAttributes(attribute.String("path", c.Request.URL.Path)))
		defer span.End()
		//你可以把它想象成按下秒表的“开始”键。
		//作用：它开启了一个新的 Span（跨度）。在分布式追踪（如 Jaeger, Zipkin）中，每一个操作步骤（比如“查数据库”、“调远程接口”、“路由匹配”）都是一个 Span。
		//名字："Routing.Match" 是这个操作的名字。在监控面板上，你会看到一条名为 "Routing.Match" 的条形图。
		//初始标签：trace.WithAttributes(...) 是在创建 Span 的同时，给它贴上第一批标签：type="Trie"：告诉监控系统，这次匹配用的是 Trie 树算法（而不是正则）。
		//path="/api/user"：告诉监控系统，正在匹配哪个路径。defer span.End()：这是按下秒表的“停止”键。无论函数是正常返回还是报错退出，defer 保证了在函数结束的那一刻，记录下这个操作的总耗时。

		logger.Debug("Processing request in Trie routing middleware",
			zap.String("path", c.Request.URL.Path))

		// b. 拿路径，去 Trie 里查
		path := c.Request.URL.Path
		targetRules, found := tr.Trie.Search(ctx, path)
		// c. 如果没查到
		if !found {
			span.SetStatus(codes.Error, "Route not found")
			logger.Warn("No matching route found",
				zap.String("path", path),
				zap.String("method", c.Request.Method))
			c.JSON(http.StatusNotFound, gin.H{"error": "Route not found"})
			c.Abort() // 核心：终止后续所有处理！Gin 原生的路由逻辑根本不会被触发。
			return
		}

		// d. 如果查到了
		// 记录和追踪成功匹配的路由
		span.SetAttributes(attribute.String("matched_target", targetRules[0].Target)) // 记录匹配到了哪个后端
		span.SetStatus(codes.Ok, "Route matched successfully")
		//假如你的网关每天处理 100 万次请求，你在监控后台（Jaeger/Grafana）只看到 100 万条 "Routing.Match" 记录，每条耗时 1ms。这只是宏观数据。
		logger.Info("Successfully matched route in Trie",
			zap.String("path", path),
			zap.Any("rules", targetRules))

		// 将追踪上下文传递下游并处理请求
		// f. 【直接转发】
		// 这是一个非常激进的设计。它没有让请求继续走 Gin 的 Next()，
		// 而是直接在中间件里调用了 httpProxy.CreateHTTPHandler(...) 并立即执行。
		// 这意味着：一旦匹配成功，请求就在这个中间件里被处理完并发给后端了。
		c.Request = c.Request.WithContext(ctx)
		httpProxy.CreateHTTPHandler(targetRules)(c)
	})
}
