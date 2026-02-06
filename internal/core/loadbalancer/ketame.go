package loadbalancer

import (
	"crypto/md5"
	"encoding/binary"
	"net/http"
	"sort"
	"strconv"
	"sync"

	"github.com/penwyp/mini-gateway/pkg/logger"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// kTracer 为 Ketama 负载均衡模块初始化追踪器
var kTracer = otel.Tracer("loadbalancer:ketama")

// Ketama 使用 Ketama 一致性哈希算法实现的负载均衡器
type Ketama struct {
	nodes []string // 目标节点列表, 真实节点列表: ["127.0.0.1:8081", "127.0.0.1:8082"]
	// 【核心数据结构】哈希环
	// 想象一个圆环，上面刻满了数字（0 到 2^32-1）。
	// 我们把节点放在这个环上的某些刻度上。这里存的就是这些刻度值（从小到大排序）。
	hashRing []uint32 // 排序后的哈希环
	// 刻度到真实节点的映射
	// key: 12345 (刻度值), value: "127.0.0.1:8081" (节点IP)
	hashMap map[uint32]string // 哈希值到节点的映射
	// 虚拟节点数 (Virtual Nodes)
	// 这是 Ketama 算法的精髓！
	// 如果一个真实节点只在环上占 1 个点，分布会很不均匀。
	// 所以我们让每个真实节点在环上“分身”成 N 个虚拟点（比如 160 个）。
	// 这样环上的点就密密麻麻，分布更均匀了。
	replicas int          // 每个物理节点的虚拟节点数
	mu       sync.RWMutex // 保护哈希环的并发访问, 读写锁：因为重建环很慢，读的时候多，写的时候少
}

// NewKetama 创建并初始化 Ketama 负载均衡器
func NewKetama(replicas int) *Ketama {
	k := &Ketama{
		replicas: replicas,
		hashMap:  make(map[uint32]string),
		mu:       sync.RWMutex{},
	}
	logger.Info("Ketama load balancer initialized", zap.Int("replicas", replicas))
	return k
}

func (cb *Ketama) Type() string {
	return "ketama"
}

// SelectTarget 根据客户端 IP 使用一致性哈希选择目标节点
func (k *Ketama) SelectTarget(targets []string, req *http.Request) string {
	// 开始追踪负载均衡选择过程
	_, span := kTracer.Start(req.Context(), "LoadBalancer.Select",
		trace.WithAttributes(attribute.String("type", k.Type())),
		trace.WithAttributes(attribute.Int("target_count", len(targets))))
	defer span.End()

	if len(targets) == 0 {
		span.SetAttributes(attribute.String("result", "no targets"))
		logger.Warn("No targets available for selection")
		return ""
	}

	k.mu.RLock() // 先加读锁检查
	// 检查目标列表是否变化，需要重建哈希环
	needRebuild := len(k.nodes) != len(targets) || !equalSlice(k.nodes, targets)
	k.mu.RUnlock()

	if needRebuild {
		k.mu.Lock()
		// 双重检查 (Double Check Locking)：防止两个协程同时冲进来说要重建
		if len(k.nodes) != len(targets) || !equalSlice(k.nodes, targets) {
			k.buildRing(targets) // 【重建环】耗时操作
		}
		k.mu.Unlock()
	}

	k.mu.RLock()
	defer k.mu.RUnlock()

	if len(k.hashRing) == 0 {
		// 如果哈希环为空，回退到第一个目标
		target := targets[0]
		span.SetAttributes(attribute.String("selected_target", target))
		logger.Debug("Selected fallback target due to empty hash ring",
			zap.String("target", target))
		return target
	}

	// 使用客户端 IP 作为哈希键进行一致性选择
	// 2. 计算请求的哈希值
	// 这里用 req.RemoteAddr (客户端IP) 作为 Key。
	// 这意味着：同一个 IP 的用户，永远会被分给同一台机器（只要机器列表不变）。
	// 这叫“会话保持 (Session Sticky)”。
	key := k.hashKey(req.RemoteAddr)
	// 3. 在环上顺时针找最近的节点
	index := k.findNearest(key)
	// 4. 映射回真实节点
	target := k.hashMap[k.hashRing[index]]
	span.SetAttributes(attribute.String("selected_target", target))
	logger.Debug("Selected target using Ketama consistent hashing",
		zap.String("clientIP", req.RemoteAddr),
		zap.String("target", target))
	return target
}

// buildRing 根据目标列表构建 Ketama 哈希环
func (k *Ketama) buildRing(targets []string) {
	k.nodes = targets
	k.hashRing = nil // 重置哈希环
	k.hashMap = make(map[uint32]string)

	totalSlots := len(targets) * k.replicas // 总虚拟节点数
	k.hashRing = make([]uint32, 0, totalSlots)

	// 为每个目标添加虚拟节点到哈希环
	for _, node := range targets {
		// 为它创建 replicas 个分身
		for j := 0; j < k.replicas; j++ {
			// 【生成分身名字】
			// 真实节点: "192.168.1.1"
			// 分身0: "192.168.1.1-0" -> Hash: 100
			// 分身1: "192.168.1.1-1" -> Hash: 5000
			// ...
			hash := k.hash(node + "-" + strconv.Itoa(j)) // 每个虚拟节点的唯一哈希
			k.hashRing = append(k.hashRing, hash)        // 放入环
			k.hashMap[hash] = node                       // 记录映射关系：刻度 100 -> 真实节点 A
		}
	}

	// 对哈希环进行排序以支持二分查找
	// 【重要】排序
	// 为了支持二分查找，必须把环上的刻度从小到大排好。
	sort.Slice(k.hashRing, func(i, j int) bool {
		return k.hashRing[i] < k.hashRing[j]
	})
	logger.Info("Ketama hash ring rebuilt",
		zap.Int("nodes", len(targets)),
		zap.Int("totalSlots", totalSlots))
}

// hash 使用 MD5 生成 32 位哈希值
func (k *Ketama) hash(key string) uint32 {
	h := md5.Sum([]byte(key))
	return binary.BigEndian.Uint32(h[0:4]) // 使用前 4 字节作为哈希值
}

// hashKey 从客户端地址计算哈希键
// 使用 MD5 算法
// MD5 的优点是分布非常均匀，且雪崩效应好（改一个字符，hash值变很多）。
// 这里的实现只取了 MD5 的前 4 个字节，转成 uint32。
func (k *Ketama) hashKey(clientAddr string) uint32 {
	return k.hash(clientAddr)
}

// findNearest 查找哈希环中大于等于给定哈希值的最近节点索引
func (k *Ketama) findNearest(hash uint32) int {
	// 使用 Go 标准库的二分查找 (Binary Search)
	// 在 k.hashRing 数组里，找到第一个 >= hash 的元素的下标。
	//在 Go 语言的 sort.Search 中，如果切片中没有任何一个元素满足条件（即所有元素都比 hash 小），
	//它不会返回 -1 或报错，而是会返回切片的长度（len(k.hashRing)）。
	index := sort.Search(len(k.hashRing), func(i int) bool {
		return k.hashRing[i] >= hash
	})
	// 环形逻辑处理
	// 如果 hash 值很大（比如 99999），比环上最大的点（比如 88888）还大，
	// sort.Search 会返回 len(array)。
	// 这时候意味着走到了环的尽头，必须绕回起点（Index 0）。
	if index == len(k.hashRing) {
		return 0 // 如果哈希值超出所有节点，环绕到第一个节点
	}
	return index
}

// equalSlice 比较两个字符串切片是否相等
func equalSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
