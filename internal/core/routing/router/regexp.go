package router

import (
	"context"
	"net/http"
	"regexp"

	"github.com/gin-gonic/gin"
	"github.com/penwyp/mini-gateway/config"
	"github.com/penwyp/mini-gateway/internal/core/loadbalancer"
	"github.com/penwyp/mini-gateway/internal/core/routing/proxy"
	"github.com/penwyp/mini-gateway/pkg/logger"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// regexpTracer 为正则路由模块初始化追踪器
var regexpTracer = otel.Tracer("router:regexp")

// RegexpRouter 使用正则表达式和负载均衡处理路由逻辑
type RegexpRouter struct {
	rules map[string]*regexp.Regexp // 路径到正则表达式的映射
	cfg   *config.Config            // 存储配置以访问路由规则
	lb    loadbalancer.LoadBalancer // 负载均衡器实例
}

// NewRegexpRouter 根据配置创建并初始化 RegexpRouter 实例
func NewRegexpRouter(cfg *config.Config) *RegexpRouter {
	// 1. 初始化负载均衡器 (Load Balancer)
	// 尝试根据配置（如 "round-robin"）创建 LB 实例
	lb, err := loadbalancer.NewLoadBalancer(cfg.Routing.LoadBalancer, cfg)
	if err != nil {
		// --- 容错设计 ---
		// 如果配置写错了（比如写成了 "random_v2" 这种不存在的算法），
		// 它没有 panic 退出，而是回退到默认的 "轮询 (RoundRobin)" 算法。
		// 这是一个很好的健壮性设计（Fallback Mechanism）。
		logger.Error("Failed to initialize load balancer",
			zap.String("type", cfg.Routing.LoadBalancer),
			zap.Error(err))
		lb = loadbalancer.NewRoundRobin() // 初始化失败时回退到轮询
	}
	router := &RegexpRouter{
		rules: make(map[string]*regexp.Regexp),
		cfg:   cfg,
		lb:    lb,
	}
	// 初始化时注册路由规则
	// 2. 预编译路由规则 (Pre-compilation)
	// 遍历配置文件里所有的 HTTP 路由
	rules := cfg.Routing.GetHTTPRules()
	for path := range rules {
		router.registerRule(path)
	}
	return router
}

// registerRule 编译并注册单个路由规则
func (rr *RegexpRouter) registerRule(path string) {
	// 1. 锚点 (Anchoring)
	// 这是一个非常关键的安全和逻辑步骤！
	// 假设配置路径是 "/api/user"
	// 如果不加 ^$，请求 "/api/user/hack" 或者 "/public/api/user" 也会匹配成功（部分匹配）。
	// 加上 ^ (开头) 和 $ (结尾) 后，pattern 变成了 "^/api/user$"。
	// 这强制要求：请求路径必须从头到尾完全符合规则，不能多也不能少。
	pattern := "^" + path + "$" // 为精确匹配添加锚点

	// 2. 编译正则
	re, err := regexp.Compile(pattern)
	if err != nil {
		// 如果你正则写错了（比如写了 "/api/[" 这种缺右括号的），
		// 这里会报错，并且跳过这条路由，防止程序崩溃。
		logger.Error("Failed to compile regular expression for route",
			zap.String("path", path),
			zap.Error(err))
		return
	}
	// 3. 存入仓库
	rr.rules[path] = re
	logger.Info("Successfully registered route in RegexpRouter",
		zap.String("path", path),
		zap.Any("targets", rr.cfg.Routing.Rules[path]))
}

// Match 查找与给定路径匹配的路由规则
func (rr *RegexpRouter) Match(ctx context.Context, path string) (config.RoutingRules, bool) {
	// --- A. 开启链路追踪 (Observability) ---
	// 在 regexp.go 里理应使用 regexpTracer。
	// 但逻辑是一样的：开启一个名为 "RegexpRouter.Match" 的 span，记录“我正在匹配 path”
	ctx, span := trieRegexpTracer.Start(ctx, "RegexpRouter.Match",
		trace.WithAttributes(attribute.String("path", path)))
	defer span.End()

	// --- B. 暴力轮询匹配 (The Heavy Lifting) ---
	// rr.rules 是一个 map[string]*regexp.Regexp
	// pattern 是原始路径字符串（如 "/api/v\d+/user"）
	// re 是编译好的正则对象
	for pattern, re := range rr.rules {
		// --- C. 正则校验 ---
		// 使用正则引擎判断：当前请求 path 是否符合这个 re 的规则
		if re.MatchString(path) {

			return rr.cfg.Routing.Rules[pattern], true
		}
		// --- D. 命中返回 ---
		// 如果匹配成功，不再继续找了（Short-circuit）。
		// 直接用 pattern 去全局配置里查对应的 RoutingRules（目标地址、权重等），并返回 true。
	}
	// --- E. 兜底返回 ---
	// 循环了一圈都没匹配上，说明这是个无效请求（404），返回 nil, false。
	return nil, false
	//这段代码虽然短，但它展示了正则引擎最朴素的实现方式：“遍历 + 试探”。
	//
	//优点：实现简单，逻辑直观。
	//
	//缺点：性能较差（每次都要遍历），且存在随机匹配的严重 Bug。
}

// Setup 根据配置在 Gin 路由器中设置 HTTP 路由规则
func (rr *RegexpRouter) Setup(r gin.IRouter, httpProxy *proxy.HTTPProxy, cfg *config.Config) {
	rules := cfg.Routing.GetHTTPRules()
	if len(rules) == 0 {
		logger.Warn("No HTTP routing rules found in configuration")
		return
	}

	// 中间件：处理路由匹配和代理转发
	// 2. 核心：注册全局中间件 (Global Middleware)
	// 这里的 r 是 main.go 里的 protected 路由组。
	// r.Use 意味着：只要请求进入这个组，必须先经过这个匿名函数！
	r.Use(func(c *gin.Context) {
		// --- A. 开启“秒表” (Tracing) ---
		// 记录这次请求在“路由匹配”阶段的耗时
		ctx, span := regexpTracer.Start(c.Request.Context(), "Routing.Match",
			trace.WithAttributes(attribute.String("type", "Regexp")),
			trace.WithAttributes(attribute.String("path", c.Request.URL.Path)))
		defer span.End()

		// --- B. 执行匹配 (The Core Call) ---
		path := c.Request.URL.Path
		// 调用我们在上面刚刚分析过的 Match 方法
		// 拿着路径去 map 里轮询正则
		targetRules, found := rr.Match(ctx, path)

		// --- C. 没匹配上 (404分支) ---
		if !found {
			logger.Warn("No matching route found",
				zap.String("path", path),
				zap.String("method", c.Request.Method))
			c.JSON(http.StatusNotFound, gin.H{"error": "Route not found"})
			// 【关键点】c.Abort()
			// 它的作用是：立即停止 Gin 的后续处理链。
			// 如果不调这个，Gin 可能会继续执行后面注册的其他 handler（虽然这里后面其实也没啥了）。
			c.Abort()
			span.SetStatus(codes.Error, "Route not found")
			return
		}

		// --- D. 匹配成功 (Success分支) ---
		// 记录匹配到了哪个目标（Matched Target），方便排查问题
		span.SetAttributes(attribute.String("matched_target", targetRules[0].Target))
		span.SetStatus(codes.Ok, "Route matched successfully")
		logger.Info("Successfully matched route",
			zap.String("path", path),
			zap.Any("rules", targetRules))

		// --- E. 移交控制权 (Handover) ---
		// 1. 把带有 Trace ID 的 ctx 塞回请求里
		c.Request = c.Request.WithContext(ctx)
		// 2. 直接调用 Proxy 进行转发
		// httpProxy.CreateHTTPHandler 返回一个闭包函数
		// (c) 立即执行这个闭包
		httpProxy.CreateHTTPHandler(targetRules)(c)
	})
}
