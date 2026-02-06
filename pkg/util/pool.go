package util

import (
	"sync"

	"github.com/penwyp/mini-gateway/config"
)

// 这个文件 pkg/util/pool.go 实现了一个基于 sync.Pool 的对象池管理器 (Object Pool Manager)。
// 简单来说，它的核心目的是：为了省钱（节省内存开销）和省事（减少垃圾回收压力）。
// 在 http_proxy.go 中，每当一个请求进来，网关都需要做“挑选目标”的动作（比如从 10 个后端里筛选出 3 个灰度节点，再提取出它们的 IP）。
// 如果不使用池化，每次请求都要创建新的切片（Slice），用完就扔。在高并发场景下（比如 10 万 QPS），
// 这意味着每秒要创建和销毁 20 万个切片，Go 的垃圾回收器（GC）会忙疯，导致 CPU 飙升，请求延迟增加。
// 使用这个 pool.go，我们就可以反复利用用过的切片，而不是扔掉。
// ObjectPoolManager 管理可重用资源的对象池逻辑
type ObjectPoolManager struct {
	cfg *config.Config // 配置信息

	targetsPool sync.Pool // 目标地址切片池 专门用来存 []string (字符串切片) 的池子
	rulesPool   sync.Pool // 路由规则切片池 专门用来存 config.RoutingRules (规则结构体切片) 的池子
}

// NewPoolManager 创建并初始化对象池管理器实例
func NewPoolManager(cfg *config.Config) *ObjectPoolManager {
	pm := &ObjectPoolManager{
		cfg: cfg,
	}

	// 仅当配置中启用内存池时初始化池
	// 1. 检查开关：只在配置开启时才初始化池
	// 这是一个很好的设计，允许用户关闭优化（比如在低内存机器上或者为了调试）。
	if cfg.Performance.MemoryPool.Enabled {
		// 2. 初始化 targetsPool (存 []string)
		pm.targetsPool = sync.Pool{
			New: func() interface{} {
				return make([]string, 0, cfg.Performance.MemoryPool.RulesCapacity)
			},
			// make([]string, 0, Cap)
			// 关键点：创建一个长度为 0，但容量为 RulesCapacity 的切片。
			// 预分配容量避免了后续 append 时的扩容（内存搬迁）开销。
		}
		// 3. 初始化 rulesPool (存 RoutingRules)
		pm.rulesPool = sync.Pool{
			New: func() interface{} {
				return make(config.RoutingRules, 0, cfg.Performance.MemoryPool.TargetsCapacity)
			},
		}
	} else {
		// 未启用池时使用空池，避免空引用
		pm.targetsPool = sync.Pool{}
		pm.rulesPool = sync.Pool{}
	}
	return pm
}

// GetTargets 从池中获取可重用的目标切片或创建新切片
func (pm *ObjectPoolManager) GetTargets(capacity int) []string {
	if pm.cfg.Performance.MemoryPool.Enabled {
		// 1. 从池里拿：Get() 返回的是 interface{}，必须断言成 .([]string)
		targets := pm.targetsPool.Get().([]string)
		// 2. 【核心黑科技】重置长度：targets[:0]
		// 这行代码把切片的长度（len）变成了 0，但底层的数组（cap）还在！
		// 就像擦掉了黑板上的字，但黑板还在，下次可以直接写。
		// 这样你拿到的是一个“逻辑上为空”的切片，可以直接 append，不需要分配新内存。
		return targets[:0] // 重置长度以重用切片
	}
	return make([]string, 0, capacity) // 未启用池时分配新切片
}

// PutTargets 将目标切片归还到池中以供重用
func (pm *ObjectPoolManager) PutTargets(targets []string) {
	// 只有开启了才归还
	if pm.cfg.Performance.MemoryPool.Enabled {
		// 把切片放回池子。
		// 注意：这里不需要把切片内容清空，因为下次 Get 出来的时候会执行 [:0] 重置长度。
		pm.targetsPool.Put(targets)
	}
	// 未启用池时，切片将通过垃圾回收自动丢弃
}

// GetRules 从池中获取可重用的路由规则切片或创建新切片
func (pm *ObjectPoolManager) GetRules(capacity int) config.RoutingRules {
	if pm.cfg.Performance.MemoryPool.Enabled {
		rules := pm.rulesPool.Get().(config.RoutingRules)
		return rules[:0] // 重置长度以重用切片
	}
	return make(config.RoutingRules, 0, capacity) // 未启用池时分配新切片
}

// PutRules 将路由规则切片归还到池中以供重用
func (pm *ObjectPoolManager) PutRules(rules config.RoutingRules) {
	if pm.cfg.Performance.MemoryPool.Enabled {
		pm.rulesPool.Put(rules)
	}
	// 未启用池时，切片将通过垃圾回收自动丢弃
}

//如果不这么做：
//
//内存分配爆炸：每次请求都 make 新切片。QPS 10k = 每秒 10k 次内存分配。
//
//GC 压力：这些切片用完即丢，会变成垃圾。Go 的 GC 需要频繁扫描和清理这些垃圾，这会引起 STW (Stop The World)，导致网关偶尔卡顿几毫秒。
//
//使用对象池后：
//
//零分配 (Zero Allocation)：在理想状态下（池子热起来后），所有请求复用之前的切片，内存分配次数接近于 0。
//
//低延迟：GC 没事干了，CPU 可以专心处理业务，P99 延迟会显著降低。
