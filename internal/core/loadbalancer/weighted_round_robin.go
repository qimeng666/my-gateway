package loadbalancer

import (
	"net/http"
	"sync"

	"github.com/penwyp/mini-gateway/pkg/logger"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// wrrTracer 为加权轮询负载均衡模块初始化追踪器
var wrrTracer = otel.Tracer("loadbalancer:weighted-round-robin")

// TargetWeight 定义目标及其关联权重
type TargetWeight struct {
	Target string //目标地址 例如: "127.0.0.1:8081"
	Weight int    //权重值 例如: 5
}

func (cb *WeightedRoundRobin) Type() string {
	return "weighted-round-robin"
}

// WeightedRoundRobin 实现加权轮询负载均衡算法
type WeightedRoundRobin struct {
	// key: "/api/order", value: [{"127.0.0.1:8081", 5}, {"127.0.0.1:8082", 1}]
	rules  map[string][]TargetWeight // 预定义的路径到加权目标的映射规则,静态配置：记住每个路径下有哪些目标和权重
	states map[string]*wrrState      // 每个路径的运行时状态, 动态状态：记住每个路径“现在发牌发到哪儿了”
	mu     sync.Mutex                // 锁：保证并发安全
}

// wrrState 保存加权轮询选择的状态
type wrrState struct {
	targets      []string // 目标地址列表, 把 IP 单独提出来做成切片，方便下标访问: ["127.0.0.1:8081", "127.0.0.1:8082"]
	weights      []int    // 每个目标对应的权重, 对应的权重列表 [1, 2, 3]
	totalWeight  int      // 所有权重的总和, 总权重 (1+2+3=6)
	currentCount int      // 请求分发的计数器, 计数器：记录当前一共发了多少次牌
}

// NewWeightedRoundRobin 创建并初始化 WeightedRoundRobin 实例
func NewWeightedRoundRobin(rules map[string][]TargetWeight) *WeightedRoundRobin {
	wrr := &WeightedRoundRobin{
		rules:  rules,
		states: make(map[string]*wrrState),
	}

	// 根据预定义规则初始化状态
	// 遍历所有配置的路由路径
	// 假设 rules = { "/api/order": [{Target: "A", Weight: 1}, {Target: "B", Weight: 2}] }
	for path, targetRules := range rules {
		// ... 申请内存 ...
		targets := make([]string, len(targetRules))
		weights := make([]int, len(targetRules))
		totalWeight := 0
		for i, rule := range targetRules {
			// 预先计算总权重，避免每次请求都算一遍
			targets[i] = rule.Target
			weights[i] = rule.Weight
			totalWeight += rule.Weight
		}
		// 初始化状态
		wrr.states[path] = &wrrState{
			targets:      targets,
			weights:      weights,
			totalWeight:  totalWeight,
			currentCount: -1, // 从 -1 开始，第一次递增后选择索引 0
		}
	}
	logger.Info("WeightedRoundRobin load balancer initialized",
		zap.Int("ruleCount", len(rules)))
	return wrr
}

// 回答了你之前的问题：接口只传了 []string 没传权重，它怎么知道权重是多少？
// 答案是：它忽略了入参 targets 的顺序，而是根据 req.URL.Path 去内部状态 states 里查配置。
// SelectTarget 根据加权轮询选择目标，或回退到简单轮询
func (wrr *WeightedRoundRobin) SelectTarget(targets []string, req *http.Request) string {
	wrr.mu.Lock() // 加锁，防止多核 CPU 同时修改计数器导致计算错误
	defer wrr.mu.Unlock()

	// 开始追踪负载均衡选择过程
	_, span := wrrTracer.Start(req.Context(), "LoadBalancer.Select",
		trace.WithAttributes(attribute.String("type", wrr.Type())),
		trace.WithAttributes(attribute.Int("target_count", len(targets))))
	defer span.End()

	// 处理边缘情况
	// 没目标，没法选
	if len(targets) == 0 {
		logger.Warn("No targets available for weighted round-robin selection")
		span.SetAttributes(attribute.String("result", "no targets"))
		return ""
	}
	//只有一个目标，不用算，直接返回
	if len(targets) == 1 {
		target := targets[0]
		span.SetAttributes(attribute.String("selected_target", target))
		logger.Debug("Selected single available target",
			zap.String("target", target))
		return target
	}

	// 尝试使用预定义的加权规则
	// 2. 根据请求路径查找对应的 WRR 状态
	// 例子：req.URL.Path = "/api/order"
	path := req.URL.Path
	state, ok := wrr.states[path]
	// 3. 降级逻辑 (Fallback)
	// 如果 path 是 "/api/unknown"（配置文件里没配这条路径的权重规则），
	// 这里 ok 为 false。
	if !ok || len(state.targets) == 0 {
		// 如果没有预定义规则，回退到简单轮询
		count := 0
		if state != nil {
			count = state.currentCount
			state.currentCount = (state.currentCount + 1) % len(targets)
		}
		target := targets[count%len(targets)]
		span.SetAttributes(attribute.String("selected_target", target))
		logger.Debug("Selected target using simple round-robin fallback",
			zap.String("path", path),
			zap.String("target", target))
		return target
	}

	// 加权轮询选择
	if state.totalWeight == 0 {
		logger.Warn("Total weight is zero, unable to select target",
			zap.String("path", path))
		return ""
	}

	// 递增计数器并计算在总权重中的位置
	// 4. 计数器递增
	// 假设这是第 1 次请求: -1 -> 0
	state.currentCount++
	// 5. 计算当前落在总权重尺子上的哪个刻度
	// current 的取值范围永远是 [0, totalWeight - 1]
	// 也就是 [0, 5]
	current := state.currentCount % state.totalWeight
	cumulativeWeight := 0 // 累计权重（游标）

	// 根据累计权重选择目标
	// 6. 遍历寻找区间
	// 我们把权重想象成线段长度：
	// A占 [0, 1), B占 [1, 3), C占 [3, 6)
	for i, weight := range state.weights {
		cumulativeWeight += weight
		// 只要 current 落在这个区间内，就选中它
		if current < cumulativeWeight {
			target := state.targets[i]
			span.SetAttributes(attribute.String("selected_target", target))
			logger.Debug("Selected target using weighted round-robin",
				zap.String("path", path),
				zap.String("target", target),
				zap.Int("weight", weight))
			return target
		}
	}

	/**
	target1: 1
	target2: 2
	target3: 3
	totalWeight: 6 ( 1 + 2 + 3 )
	currentCount     | -1 0 1 2 3 4 5 6 7 8 9 10 11 12 13 ...
	current          |    0 1 2 3 4 5 0 1 2 3 4 5 0  1  2 ...
	cumulativeWeight |    1 3 3 6 6 6 1 3 3 6 6 6 1  3  3
	选择对象          |    1 2 2 3 3 3 1 2 2 3 3 3 1  2  2 ...
	*/

	// 回退到第一个目标（正常情况下不会发生，除非权重配置错误）
	target := state.targets[0]
	span.SetAttributes(attribute.String("selected_target", target))
	logger.Debug("Selected fallback target due to weight calculation",
		zap.String("path", path),
		zap.String("target", target))
	return target
}
