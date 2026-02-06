package proxy

import (
	"math/rand"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/penwyp/mini-gateway/pkg/util"

	"github.com/gin-gonic/gin"
	"github.com/penwyp/mini-gateway/config"
	"github.com/penwyp/mini-gateway/internal/core/health"
	"github.com/penwyp/mini-gateway/internal/core/loadbalancer"
	"github.com/penwyp/mini-gateway/pkg/logger"
	"github.com/valyala/fasthttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

const (
	defaultEnv = "stable" // 默认环境
	canaryEnv  = "canary" // 金丝雀环境
)

// httpTracer 为 HTTP 代理初始化追踪器
var httpTracer = otel.Tracer("proxy:http")

// HTTPProxy 管理 HTTP 代理功能
type HTTPProxy struct {
	httpPool        *HTTPConnectionPool       // HTTP 连接池
	loadBalancer    loadbalancer.LoadBalancer // 负载均衡器
	objectPool      *util.ObjectPoolManager   // 对象池管理器
	httpPoolEnabled bool                      // 是否启用 HTTP 连接池

	selectTargetFunc  func(c *gin.Context, rules config.RoutingRules) (string, string)
	proxyWithPoolFunc func(c *gin.Context, target, env string)
}

// NewHTTPProxy 创建并初始化 HTTPProxy 实例
func NewHTTPProxy(cfg *config.Config) *HTTPProxy {
	lb := initializeLoadBalancer(cfg)
	logPoolStatus(cfg.Performance.HttpPoolEnabled)
	logGrayscaleStatus(cfg.Routing.Grayscale)

	return &HTTPProxy{
		httpPool:        NewHTTPConnectionPool(cfg),
		loadBalancer:    lb,
		objectPool:      util.NewPoolManager(cfg),
		httpPoolEnabled: cfg.Performance.HttpPoolEnabled,
	}
}

// logGrayscaleStatus 记录灰度发布配置状态
func logGrayscaleStatus(grayscale config.Grayscale) {
	logger.Info("Grayscale configuration status",
		zap.Bool("enabled", grayscale.Enabled),
		zap.Bool("weightedRandom", grayscale.WeightedRandom),
		zap.String("defaultEnv", grayscale.DefaultEnv),
		zap.String("canaryEnv", grayscale.CanaryEnv))
}

func (hp *HTTPProxy) GetLoadBalancerType() string {
	if hp == nil || hp.loadBalancer == nil {
		return ""
	}
	return hp.loadBalancer.Type()
}

// RefreshLoadBalancer 刷新负载均衡器
func (hp *HTTPProxy) RefreshLoadBalancer(cfg *config.Config) {
	hp.loadBalancer = initializeLoadBalancer(cfg)
	logger.Info("HTTPProxy load balancer refreshed",
		zap.String("loadBalancerType", cfg.Routing.LoadBalancer))
}

// SetupHTTPProxy 配置 HTTP 代理路由
func (hp *HTTPProxy) SetupHTTPProxy(r gin.IRouter, cfg *config.Config) {
	rules := cfg.Routing.GetHTTPRules()
	if len(rules) == 0 {
		logger.Warn("No HTTP routing rules found in configuration")
		return
	}

	for path, targetRules := range rules {
		logger.Info("Configuring HTTP proxy route",
			zap.String("path", path),
			zap.Any("targets", targetRules))
		r.Any(path, hp.CreateHTTPHandler(targetRules))
	}
}

// CreateHTTPHandler 创建 HTTP 请求处理函数
func (hp *HTTPProxy) CreateHTTPHandler(rules config.RoutingRules) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 1. 开启链路追踪 Span "HTTPProxy.Handle"
		ctx, span := httpTracer.Start(c.Request.Context(), "HTTPProxy.Handle",
			trace.WithAttributes(
				attribute.String("http.method", c.Request.Method),
				attribute.String("http.path", c.Request.URL.Path),
			))
		defer span.End()

		c.Request = c.Request.WithContext(ctx)
		// 2. 【大脑】选择目标 (Select Target)
		// 这一步决定到底是去 stable 环境还是 canary 环境，是去 8081 还是 8082
		target, selectedEnv := hp.getSelectTarget(c, rules)
		if target == "" {
			handleNoTarget(c, span, c.Request.URL.Path, getEnvFromHeader(c))
			return
		}

		span.SetAttributes(attribute.String("proxy.target", target))
		// 3. 【执行】分叉路口
		// 根据配置决定是走“高性能池化模式”还是“标准库模式”
		if hp.httpPoolEnabled {
			hp.getProxyWithPool(c, target, selectedEnv)
		} else {
			hp.proxyDirect(c, target, selectedEnv)
		}
	}
}

// proxyDirect 使用直接代理方式转发请求
func (hp *HTTPProxy) proxyDirect(c *gin.Context, target, env string) {
	// 1. 开启链路追踪
	// 记录这一步“直接转发”花费的时间。
	_, span := httpTracer.Start(c.Request.Context(), "HTTPProxy.Handle.Direct",
		trace.WithAttributes(
			attribute.String("http.method", c.Request.Method),
			attribute.String("http.path", c.Request.URL.Path),
		))
	defer span.End()

	// 2. 解析目标地址
	// target 字符串 (如 "127.0.0.1:8081") 需要被解析成 URL 对象，
	// 这样才能拆分出 Scheme (http), Host, Port 等信息。
	targetURL, err := url.Parse(target)
	if err != nil {
		// 如果 target 格式都不对，直接报错返回
		handleProxyError(c, span, target, "Invalid target URL", err)
		return
	}

	// 3. 【核心】创建反向代理对象
	// httputil.NewSingleHostReverseProxy 是 Go 标准库提供的神器。
	// 它创建了一个可以直接使用的代理对象，内置了连接复用、流式传输等功能。
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	// 4. 【关键定制】设置 Director (导演)
	// 代理对象不知道怎么修改请求（比如怎么改 Path，怎么加 Header）。
	// Director 就是一个回调函数，专门负责在请求发出去之前，“篡改”请求对象。
	proxy.Director = hp.createDirector(targetURL, env)
	// 5. 【关键定制】设置 ErrorHandler (错误处理)
	// 如果转发失败（比如后端挂了），标准库默认只会打印一行丑陋的日志。
	// 我们替换成自己的 Handler，以便记录结构化日志 (Zap) 和更新健康检查状态。
	proxy.ErrorHandler = hp.createErrorHandler(target, span)

	logger.Info("Routing HTTP request",
		zap.String("path", c.Request.URL.Path),
		zap.String("target", target),
		zap.String("env", env),
		zap.String("method", c.Request.Method))

	// 包装 c.Writer，使其满足 http.CloseNotifier 接口要求
	// 6. 【黑科技】包装 Writer
	// 这里是为了兼容性（后面详细讲）。Gin 的 Writer 有时候不直接支持 http.CloseNotifier。
	wrappedWriter := &closeNotifyResponseWriter{c.Writer}
	// 7. 【执行转发】ServeHTTP
	// 这一步是阻塞的。
	// 它会：读取 Client 请求 -> 发给 Backend -> 等待 Backend 响应 -> 写回 Client。
	// 所有的脏活累活都在这一行里自动完成了。
	proxy.ServeHTTP(wrappedWriter, c.Request)
	span.SetStatus(codes.Ok, "HTTP proxy completed successfully") // 8. 收尾工作
	// 只要能正常返回（哪怕是 404 或 500），说明网络通了，标记该节点为健康。
	health.GetGlobalHealthChecker().UpdateRequestCount(target, true)
}

// proxyWithPool 使用连接池代理转发请求
func (hp *HTTPProxy) proxyWithPool(c *gin.Context, target, env string) {
	_, span := httpTracer.Start(c.Request.Context(), "HTTPProxy.Handle.Pool",
		trace.WithAttributes(
			attribute.String("http.method", c.Request.Method),
			attribute.String("http.path", c.Request.URL.Path),
		))
	defer span.End()

	// 2. 【关键】获取连接池客户端
	// target 是 "127.0.0.1:8081"。
	// 这里不是每次 New 一个 client，而是去池子里找一个已经连上这个 IP 的 client。
	client, err := hp.httpPool.GetClient(target)
	if err != nil {
		handleProxyError(c, span, target, "Failed to get HTTP client", err)
		return
	}
	// 3. 【核心黑科技】零内存分配 (Zero Allocation)
	// 从对象池里借一个空的 Request 对象和 Response 对象。
	// 就像在食堂借盘子，而不是自己造盘子。
	req, resp := fasthttp.AcquireRequest(), fasthttp.AcquireResponse()
	// 4. 【核心黑科技】用完归还
	// 函数结束时，不管成功失败，把盘子洗干净还给食堂（对象池）。
	// 这样下一个请求进来可以接着用，不用触发 GC（垃圾回收）。
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	// 5. 数据转换：Gin -> FastHTTP
	// 把用户发给网关的 HTTP 请求（Gin 格式），倒腾到刚才借来的 req 盘子里（FastHTTP 格式）。
	hp.prepareFastHTTPRequest(c, req, target, env)

	// 6. 发送请求 (Block)
	// 真正发请求给后端。因为复用了 TCP 连接，这里没有握手开销，速度极快。
	if err := client.Do(req, resp); err != nil {
		handleProxyError(c, span, target, "Backend service unavailable", err)
		return
	}

	// 7. 数据写回：FastHTTP -> Gin
	// 把后端装在 resp 盘子里的菜，倒腾回用户的碗里（Gin Context）。
	hp.writeFastHTTPResponse(c, resp)
	// 8. 收尾
	span.SetStatus(codes.Ok, "HTTP proxy completed successfully")
	health.GetGlobalHealthChecker().UpdateRequestCount(target, true)
}

// initializeLoadBalancer 初始化负载均衡器
func initializeLoadBalancer(cfg *config.Config) loadbalancer.LoadBalancer {
	lb, err := loadbalancer.NewLoadBalancer(cfg.Routing.LoadBalancer, cfg)
	if err != nil {
		logger.Error("Failed to initialize load balancer",
			zap.Error(err))
		return loadbalancer.NewRoundRobin()
	}
	return lb
}

// logPoolStatus 记录连接池状态
func logPoolStatus(enabled bool) {
	status := "disabled"
	if enabled {
		status = "enabled"
	}
	logger.Info("HTTP TCP connection pool status",
		zap.String("status", status))
}

// getEnvFromHeader 从请求头中获取环境信息
func getEnvFromHeader(c *gin.Context) string {
	if env := c.GetHeader("X-Env"); env != "" {
		return env
	}
	return defaultEnv
}

// filterRules 根据环境过滤路由规则
func (hp *HTTPProxy) filterRules(rules config.RoutingRules, env string) config.RoutingRules {
	filtered := hp.objectPool.GetRules(len(rules))
	if env == canaryEnv {
		for _, rule := range rules {
			if rule.Env == canaryEnv {
				filtered = append(filtered, rule)
			}
		}
		if len(filtered) == 0 {
			logger.Warn("No canary targets available, falling back to all rules",
				zap.String("path", rules[0].Target)) // 假设 rules 不为空
			return rules
		}
		return filtered
	}
	return append(filtered, rules...)
}

// extractTargets 从规则中提取目标列表
func (hp *HTTPProxy) extractTargets(rules config.RoutingRules) []string {
	targets := hp.objectPool.GetTargets(len(rules))
	for _, rule := range rules {
		targets = append(targets, rule.Target)
	}
	return targets
}

// selectTarget 选择目标并返回目标和环境
// 这是逻辑最密集的地方，它负责处理 “灰度发布 (Grayscale)” 和 “常规路由” 的分流。
func (hp *HTTPProxy) selectTarget(c *gin.Context, rules config.RoutingRules) (string, string) {
	// 1. 开启链路追踪
	// 记录这一步决策耗时，并在 Trace 中打上 http.method 和 path 标签。
	ctx, span := httpTracer.Start(c.Request.Context(), "HTTPProxy.selectTarget",
		trace.WithAttributes(
			attribute.String("http.method", c.Request.Method),
			attribute.String("http.path", c.Request.URL.Path),
		))
	defer span.End()

	c.Request = c.Request.WithContext(ctx)
	// 2. 获取全局配置中的“灰度开关”
	cfg := config.GetConfig()
	grayscale := cfg.Routing.Grayscale

	// --- 分支 A：没开灰度 (最常见情况) ---
	// 如果 config.yaml 里 routing.grayscale.enabled = false
	if !grayscale.Enabled {
		return hp.selectWithLoadBalancer(c, rules)
	}
	// 直接把所有规则扔给负载均衡器去选（比如轮询）

	// 灰度发布启用时的逻辑
	// --- 分支 B：开启了灰度 (复杂逻辑) ---

	// 3. 识别用户身份 (获取环境标识)
	// 检查请求头里有没有 `X-Env: canary`。
	env := getEnvFromHeader(c)
	// 4. 过滤规则 (Filter)
	// 根据 env（stable 或 canary）筛选出符合条件的后端目标。
	// 比如 env=canary，就只保留那些标记为 canary 的后端 IP。
	// 如果 canary 没人，还会自动降级（Fallback）回 stable。
	targetRules := hp.filterRulesWithFallback(rules, env, grayscale)

	// *性能优化*：对象池回收 (Object Pooling)
	// 因为 targetRules 可能是新创建的切片，用完记得放回池子，减少 GC。
	defer hp.objectPool.PutRules(targetRules)

	// 5. 准备目标列表
	targets := hp.extractTargets(targetRules)
	defer hp.objectPool.PutTargets(targets)

	// 6. 决策算法选择
	// 如果开启了“加权随机 (WeightedRandom)”模式，且有多个可选目标
	if grayscale.Enabled && grayscale.WeightedRandom && len(targetRules) > 1 {
		return hp.selectWithWeightedRandom(targetRules, c.Request.URL.Path)
	}
	// 默认还是走负载均衡器（在筛选后的 targetRules 里选）
	// 注意：这里强制指定了 env，确保选出来的目标环境一致。
	return hp.selectWithLoadBalancer(c, targetRules, targetRules[0].Env)
}

// selectWithWeightedRandom 使用权重随机选择目标
func (hp *HTTPProxy) selectWithWeightedRandom(rules config.RoutingRules, path string) (string, string) {
	// 1. 核心计算
	// 调用一个纯数学函数，根据 rules 里的 Weight 字段（如 20, 80）随机选一个。
	selectedRule := WeightedRandomSelect(rules)
	// 2. 兜底防御 (Defensive Programming)
	// 万一配置是空的，或者所有权重都是 0 导致选不出来（虽然不该发生），
	// 为了不报错崩溃，强制默认选列表里的第一个。
	if selectedRule == nil {
		logger.Warn("Weighted random selection failed, using first rule",
			zap.String("path", path))
		return rules[0].Target, rules[0].Env
	}
	// 3. 记录结果
	logger.Info("Target selected via weighted random",
		zap.String("path", path),
		zap.String("target", selectedRule.Target),
		zap.String("env", selectedRule.Env),
		zap.Int("weight", selectedRule.Weight))
	// 4. 返回选中目标的 IP 和 环境标签
	return selectedRule.Target, selectedRule.Env
	//适用场景：当你开启了灰度，并且设置了 weightedRandom: true。你想让 10% 的人去 canary，90% 的人去 stable。
}

// selectWithLoadBalancer 使用负载均衡器选择目标
func (hp *HTTPProxy) selectWithLoadBalancer(c *gin.Context, rules config.RoutingRules, envOverride ...string) (string, string) {
	//1. 开启链路追踪 (Tracing)
	// 记录这一步“选人”花了多久。
	ctx, span := httpTracer.Start(c.Request.Context(), "HTTPProxy.selectWithLoadBalancer",
		trace.WithAttributes(
			attribute.String("http.method", c.Request.Method),
			attribute.String("http.path", c.Request.URL.Path),
		))
	defer span.End()

	var targets []string

	// 2. 数据转换 (Data Transformation)
	// 负载均衡器接口 SelectTarget 只认 []string (IP列表)，不认复杂的 RoutingRules 结构体。
	// 所以这里要把 rules 里的 Target 字段提取出来，变成一个字符串切片。
	// 这里用到了对象池 (objectPool) 来复用切片内存。
	targets = hp.extractTargets(rules)
	defer hp.objectPool.PutTargets(targets)

	// 3. 更新 Context
	c.Request = c.Request.WithContext(ctx)

	// 4. 【核心调用】算法决策
	// 这里的 hp.loadBalancer 是一个接口（Interface）。
	// 它背后可能是 RoundRobin（轮询），也可能是 Hash（哈希）。
	// 它只负责：给你一堆 IP，它告诉你“这次该选谁”。
	target := hp.loadBalancer.SelectTarget(targets, c.Request)
	// 如果列表是空的，或者算法没选出来
	if target == "" {
		return "", ""
	}

	// 5. 找回丢失的“环境信息” (Context Restoration)
	// 这是一个关键点！
	// 负载均衡器只返回了一个 IP (target string)，它把 Env 信息丢了。
	// 但网关后续需要知道这个 IP 是 stable 还是 canary。
	selectedEnv := defaultEnv
	if len(envOverride) > 0 {
		// 情况 A：调用方已经明确说了环境（比如之前在 selectTarget 里已经根据 Header 过滤过了）
		// 那就直接用传进来的环境，不需要查。
		selectedEnv = envOverride[0]
	} else {
		// 情况 B：调用方没说环境。
		// 我们需要拿着选出来的 target IP，反向去 rules 列表里查：
		// “这个 IP 对应的是哪个环境？”
		for _, rule := range rules {
			if rule.Target == target {
				selectedEnv = rule.Env
				break
			}
		}
	}

	logger.Info("Target selected via load balancer",
		zap.String("path", c.Request.URL.Path),
		zap.String("target", target),
		zap.String("env", selectedEnv))
	return target, selectedEnv
}

// filterRulesWithFallback 根据环境过滤规则，并提供回退逻辑
func (hp *HTTPProxy) filterRulesWithFallback(rules config.RoutingRules, env string, grayscale config.Grayscale) config.RoutingRules {
	filtered := hp.filterRules(rules, env)
	if len(filtered) == 0 && env == grayscale.CanaryEnv {
		logger.Warn("No canary targets available, falling back to default env",
			zap.String("path", rules[0].Target)) // 假设 rules 不为空
		return hp.filterRules(rules, grayscale.DefaultEnv)
	}
	return filtered
}

// handleNoTarget 处理无可用目标的情况
func handleNoTarget(c *gin.Context, span trace.Span, path, env string) {
	span.SetStatus(codes.Error, "No available target")
	logger.Warn("No target available for request",
		zap.String("path", path),
		zap.String("env", env))
	c.JSON(http.StatusServiceUnavailable, gin.H{"error": "No available target"})
}

// handleProxyError 处理代理错误
func handleProxyError(c *gin.Context, span trace.Span, target, msg string, err error) {
	span.RecordError(err)
	span.SetStatus(codes.Error, "Proxy error")
	health.GetGlobalHealthChecker().UpdateRequestCount(target, false)
	logger.Error("HTTP proxy request failed",
		zap.String("target", target),
		zap.String("message", msg),
		zap.Error(err))
	c.JSON(http.StatusBadGateway, gin.H{"error": msg})
}

// createDirector 创建代理请求的 Director 函数
func (hp *HTTPProxy) createDirector(targetURL *url.URL, env string) func(*http.Request) {
	return func(req *http.Request) {
		// 1. 调用基础整形逻辑 (defaultDirector)
		// 这一步负责改 URL 和 Host
		defaultDirector(targetURL)(req)
		// 2. 注入环境标 (Canary)
		// 如果当前决策是去金丝雀环境，就在 Header 里盖个章。
		// 这样后端服务如果有感知能力，也能知道这是个测试请求。
		if env == canaryEnv {
			req.Header.Set("X-Env", canaryEnv)
		}
	}
}

// createErrorHandler 创建代理错误处理函数
func (hp *HTTPProxy) createErrorHandler(target string, span trace.Span) func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		// 1. 记录到链路追踪 (Tracing)
		span.RecordError(err)
		span.SetStatus(codes.Error, "Proxy error")
		// 2. 【重要】上报健康检查失败
		// 告诉 HealthChecker：“这个 IP 刚才请求失败了，你记一笔。”
		// 如果失败次数多了，HealthChecker 就会把这个 IP 踢掉。
		health.GetGlobalHealthChecker().UpdateRequestCount(target, false)
		logger.Error("HTTP proxy request failed",
			zap.String("path", r.URL.Path),
			zap.String("target", target),
			zap.Error(err))
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("Bad Gateway"))
	}
}

// prepareFastHTTPRequest 准备 FastHTTP 请求
// 这个方法负责把 gin.Context 里的数据搬运到 fasthttp.Request 对象里。
// 例子场景： 用户发了一个请求：POST /api/login?type=admin，
// Header 带了 Authorization: Bearer xyz，Body 是 {"user":"admin"}。 目标后端是：192.168.1.10:8080。
func (hp *HTTPProxy) prepareFastHTTPRequest(c *gin.Context, req *fasthttp.Request, target, env string) {
	// 1. 拼接完整的后端 URL
	// target="192.168.1.10:8080", Path="/api/login"
	// 结果 reqURI = "http://192.168.1.10:8080/api/login?type=admin"
	reqURI := "http://" + target + c.Request.URL.Path
	if c.Request.URL.RawQuery != "" {
		reqURI += "?" + c.Request.URL.RawQuery
	}
	req.SetRequestURI(reqURI) // 设置目标地址
	// 2. 搬运 Method
	req.Header.SetMethod(c.Request.Method) // "POST"

	// 3. 搬运 Headers
	// 遍历 Gin 的 Header，一个个塞进 FastHTTP 的 Header。
	for key, values := range c.Request.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	if env == canaryEnv {
		req.Header.Set("X-Env", canaryEnv)
	}
	if c.Request.Body != nil {
		if body, err := c.GetRawData(); err == nil {
			req.SetBody(body)
		}
	}
}

// writeFastHTTPResponse 写入 FastHTTP 响应
// 后端处理完了，把结果写在 resp 对象里回来了。现在要把这些数据写回给用户（Gin）。
// 例子场景： 后端返回：状态码 200 OK，Header Content-Type: application/json，Body {"status":"success"}。
func (hp *HTTPProxy) writeFastHTTPResponse(c *gin.Context, resp *fasthttp.Response) {
	// 1. 搬运状态码
	c.Status(resp.StatusCode()) // 200
	// 2. 搬运 Headers
	// VisitAll 是 fasthttp 提供的高效遍历方法
	resp.Header.VisitAll(func(key, value []byte) {
		c.Header(string(key), string(value)) // 设置 "Content-Type"
	})
	// 3. 搬运 Body
	// 把 {"status":"success"} 写入用户的响应流
	c.Writer.Write(resp.Body())
}

// defaultDirector 创建默认的代理请求 Director 函数，用于将请求转发到目标 URL
func defaultDirector(targetURL *url.URL) func(req *http.Request) {
	return func(req *http.Request) {
		// 假设 targetURL 是 "http://127.0.0.1:8081"
		// 假设 req.URL 是 "/api/user"
		req.URL.Scheme = targetURL.Scheme // 设置目标协议 // http
		req.URL.Host = targetURL.Host     // 设置目标主机 // 127.0.0.1:8081
		// 路径合并：确保 /api + /user 变成 /api/user，而不是 /api//user
		req.URL.Path = SingleJoiningSlash(targetURL.Path, req.URL.Path) // 合并路径
		//真正的高级场景（路径挂载 / Path Mounting）想象一下，你的后端服务并不是部署在根目录 / 下的，而是部署在一个子目录下的。场景假设：你有一个老旧的 Java 服务，它必须通过 http://127.0.0.1:8081/legacy/v1 才能访问，而不是直接通过根目录访问。但是，你想对用户隐藏这个丑陋的 /legacy/v1，让用户只访问 /user。配置 (Target): http://127.0.0.1:8081/legacy/v1 (注意这里带了路径！)请求 (Request): /user (用户只知道这个)如果没有 SingleJoiningSlash，直接发 /user 给后端，后端会报 404，因为它只认 /legacy/v1/user。有了这行合并代码：$$\text{Merge}("/legacy/v1", "/user") \rightarrow "/legacy/v1/user"$$结果：用户访问网关的 /user。网关自动把配置里的前缀 /legacy/v1 拼上去。后端收到了它期待的 /legacy/v1/user。这就是 “路径前缀拼接” 能力。
		// 【重要】修改 Host 头
		// 很多后端服务（如 Nginx 虚拟主机）是根据 Host 头来分发请求的。
		// 如果不改，后端收到的还是网关的域名，可能会拒收。
		req.Host = targetURL.Host        // 设置 Host 头
		forwardedURL := req.URL.String() // 获取完整转发 URL
		logger.Debug("Forwarding proxy request",
			zap.String("originalPath", req.URL.Path),
			zap.String("forwardedURL", forwardedURL),
		)
	}
}

// SingleJoiningSlash 合并两个路径段，确保它们之间恰好有一个斜杠
func SingleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/") // 检查 a 是否以斜杠结尾
	bslash := strings.HasPrefix(b, "/") // 检查 b 是否以斜杠开头
	switch {
	case aslash && bslash:
		// 如果 a 已带斜杠且 b 以斜杠开头，移除 b 的前导斜杠
		return a + b[1:]
	case !aslash && !bslash:
		// 如果两者均无斜杠，添加一个斜杠
		return a + "/" + b
	}
	// 如果两者之间已有一个斜杠，直接拼接
	return a + b
}

// WeightedRandomSelect 根据权重随机选择一个路由规则
func WeightedRandomSelect(rules config.RoutingRules) *config.RoutingRule {
	if len(rules) == 0 {
		return nil
	}
	if len(rules) == 1 {
		return &rules[0]
	}

	// 计算总权重
	totalWeight := 0
	for _, rule := range rules {
		totalWeight += rule.Weight
	}

	// 随机选择
	rand.Seed(time.Now().UnixNano()) // 初始化随机种子
	randomWeight := rand.Intn(totalWeight)

	// 根据权重区间选择目标
	cumulativeWeight := 0
	for i, rule := range rules {
		cumulativeWeight += rule.Weight
		if randomWeight < cumulativeWeight {
			return &rules[i]
		}
	}
	return &rules[len(rules)-1] // 兜底
}

// 辅助方法：根据是否注入了自定义逻辑来选择目标
func (hp *HTTPProxy) getSelectTarget(c *gin.Context, rules config.RoutingRules) (string, string) {
	// 1. 测试桩/扩展点检查
	// 这里的 selectTargetFunc 是一个函数类型的字段。
	// 设计目的：为了写单元测试（Mock）或者允许外部插件注入自己的选路逻辑。
	if hp.selectTargetFunc != nil {
		return hp.selectTargetFunc(c, rules)
	}
	// 2. 默认逻辑
	// 如果没有注入自定义逻辑，就走标准的 selectTarget 方法。
	return hp.selectTarget(c, rules)
}

// 辅助方法：根据是否注入了自定义逻辑来执行连接池代理
func (hp *HTTPProxy) getProxyWithPool(c *gin.Context, target, env string) {
	if hp.proxyWithPoolFunc != nil {
		hp.proxyWithPoolFunc(c, target, env) // 测试时的 Mock 入口
	} else {
		hp.proxyWithPool(c, target, env) // 生产环境的真实入口
	}
}

// closeNotifyResponseWriter 包装了 gin.ResponseWriter，并实现 http.CloseNotifier 接口

type closeNotifyResponseWriter struct {
	gin.ResponseWriter
}

// 这是一个空实现（Mock），或者是一个简化的实现。
// 在这个代码里，它返回了一个 make(chan bool)，其实是一个“永远不会通知”的假通道。
// 这意味着：这个网关在这个简易实现下，可能放弃了“客户端断开自动取消后端请求”的能力，
// 目的是为了让 ReverseProxy 不报错，或者为了通过类型断言。
func (w *closeNotifyResponseWriter) CloseNotify() <-chan bool {
	// 返回一个空通道即可，不会被使用到
	return make(chan bool)
}
