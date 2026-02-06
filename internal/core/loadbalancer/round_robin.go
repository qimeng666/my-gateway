package loadbalancer

import (
	"net/http"
	"sync"

	"github.com/penwyp/mini-gateway/config"
	"github.com/penwyp/mini-gateway/pkg/logger"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// rrTracer 为 RoundRobin 负载均衡模块初始化追踪器
var rrTracer = otel.Tracer("loadbalancer:round-robin")

// RoundRobin 实现简单的轮询负载均衡算法
type RoundRobin struct {
	next uint32     // 游标：记录下一次该发给第几个服务器了
	mu   sync.Mutex // 互斥锁：保证多线程并发时的安全
}

// NewRoundRobin 创建并初始化 RoundRobin 负载均衡器实例
func NewRoundRobin() LoadBalancer {
	rr := &RoundRobin{}
	logger.Info("RoundRobin load balancer initialized")
	return rr
}

func (rr *RoundRobin) Type() string {
	return "round-robin"
}

// SelectTarget 以轮询方式选择下一个可用目标
// // 参数 targets: 比如 ["127.0.0.1:8081", "127.0.0.1:8082"]
// 参数 r: 即使轮询不需要看 Request 内容，为了满足接口定义也必须传进来
func (rr *RoundRobin) SelectTarget(targets []string, r *http.Request) string {
	// --- A. 开启追踪 (Tracing) ---
	// 类似于我们在 Proxy 层看到的，这里也开了一个 Span。
	// 目的是让你在监控图上能看到：“哦，这次选人花了 0.01ms”。
	_, span := rrTracer.Start(r.Context(), "LoadBalancer.Select",
		trace.WithAttributes(attribute.String("type", rr.Type())),
		trace.WithAttributes(attribute.Int("target_count", len(targets))))
	defer span.End()

	// --- B. 防御性检查 ---
	// 如果后端列表是空的（比如所有服务都挂了，或者配置没写），直接返回空字符串。
	if len(targets) == 0 {
		logger.Warn("No targets available for round-robin selection")
		span.SetAttributes(attribute.String("result", "no targets"))
		return ""
	}

	// --- C. 加锁 (Critical Section) ---
	// 进入核心计算区，先关门，不让别人插队。
	rr.mu.Lock()
	defer rr.mu.Unlock()

	// 选择下一个目标并递增计数器
	// --- D. 核心算法：取模运算 (%) ---
	// 假设 targets 长度为 3。
	// next = 0 -> index = 0 % 3 = 0 (选第1台)
	// next = 1 -> index = 1 % 3 = 1 (选第2台)
	// next = 2 -> index = 2 % 3 = 2 (选第3台)
	// next = 3 -> index = 3 % 3 = 0 (回到第1台)
	index := rr.next % uint32(len(targets))
	target := targets[index] // 取出目标 IP
	rr.next++                // 游标自增，为下一次请求做准备

	// 在追踪和日志中记录所选目标
	// --- E. 记录并返回 ---
	span.SetAttributes(attribute.String("selected_target", target))
	logger.Debug("Selected target using round-robin",
		zap.String("target", target),
		zap.Uint32("index", index))
	return target
}

// UpdateTargets 对于 RoundRobin 是空操作，因其依赖运行时目标列表
func (rr *RoundRobin) UpdateTargets(cfg *config.Config) {
	// 无需配置更新，目标由每次请求提供
}
