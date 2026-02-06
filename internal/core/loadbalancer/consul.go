package loadbalancer

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/hashicorp/consul/api"
	"github.com/penwyp/mini-gateway/pkg/logger"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

var consulTracer = otel.Tracer("loadbalancer:consul")

// ConsulBalancer 使用 Consul 实现动态规则更新的负载均衡器
type ConsulBalancer struct {
	client *api.Client // Consul 客户端, Consul 的 SDK 客户端，用来跟 Consul 服务器打电话
	// 【核心数据】本地缓存
	// Consul 是远程的，我们不能每次请求都去查远程，太慢了。
	// 所以我们把 Consul 里的规则同步到这个 map 里。
	// key: "/api/user" (路径), value: ["10.0.0.1:8080", "10.0.0.2:8080"] (目标列表)
	rules  map[string][]string // 路径到目标列表的映射
	mu     sync.RWMutex        // 读写锁, 读写锁：watchRules 写，SelectTarget 读
	stopCh chan struct{}       // 停止信号通道, 遥控器：用来优雅地停止后台监听协程
}

// NewConsulBalancer 创建并初始化 ConsulBalancer 实例
func NewConsulBalancer(consulAddr string) (*ConsulBalancer, error) {
	// 1. 配置 Consul 客户端
	config := api.DefaultConfig()
	config.Address = consulAddr // 比如 "127.0.0.1:8500"
	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Consul client: %v", err)
	}

	cb := &ConsulBalancer{
		client: client,
		rules:  make(map[string][]string),
		stopCh: make(chan struct{}),
	}
	// 2. 【关键】启动后台监听
	// 这是一个非阻塞调用。它启动了一个 Goroutine（协程），
	// 在后台默默地去盯着 Consul 的变化，不影响主程序的启动。
	go cb.watchRules() // 启动 Consul 规则监听协程
	logger.Info("Consul load balancer initialized", zap.String("address", consulAddr))
	return cb, nil
}

func (cb *ConsulBalancer) Type() string {
	return "consul"
}

// SelectTarget 根据 Consul 规则或回退逻辑为请求选择目标, 它不连网，只查内存，所以速度很快。
func (cb *ConsulBalancer) SelectTarget(targets []string, req *http.Request) string {
	cb.mu.RLock() // 加读锁，允许多个请求同时查，但阻塞写操作
	defer cb.mu.RUnlock()

	// 开始追踪负载均衡选择过程
	_, span := consulTracer.Start(req.Context(), "LoadBalancer.Select",
		trace.WithAttributes(attribute.String("type", cb.Type())),
		trace.WithAttributes(attribute.Int("target_count", len(targets))))
	defer span.End()

	path := req.URL.Path
	// 1. 优先查 Consul 同步下来的规则
	// 假设 Consul 里配置了 "/api/pay" -> ["IP_A", "IP_B"]
	if consulTargets, ok := cb.rules[path]; ok && len(consulTargets) > 0 {
		// 如果 Consul 提供了目标列表，则使用
		// 如果找到了，从中选一个。
		// 【算法】基于时间的随机选择 (Random)
		// time.Now().UnixNano() 是一个一直在变的纳秒数。
		// 比如 count=2, unix=1234567. index = 1234567 % 2 = 1。
		count := uint32(len(consulTargets))
		index := uint32(time.Now().UnixNano()) % count // 基于时间的简单选择
		target := consulTargets[index]
		span.SetAttributes(attribute.String("selected_target", target))
		logger.Debug("Selected target from Consul rules",
			zap.String("path", path),
			zap.String("target", target))
		return target
	}

	// 如果没有匹配的 Consul 规则，回退到提供的目标列表
	// 2. 降级逻辑 (Fallback)
	// 如果 Consul 里没配这条路径，或者 Consul 挂了导致 rules 是空的。
	// 就使用函数传进来的 targets（通常是 config.yaml 里的静态配置）。
	if len(targets) == 0 {
		logger.Warn("No targets available for selection", zap.String("path", path))
		return ""
	}
	// 同样使用随机算法在备选列表中选一个
	count := uint32(len(targets))
	index := uint32(time.Now().UnixNano()) % count
	target := targets[index]
	span.SetAttributes(attribute.String("selected_target", target))
	logger.Debug("Selected target from fallback list",
		zap.String("path", path),
		zap.String("target", target))
	return target
}

// watchRules 从 Consul 持续更新负载均衡规则
func (cb *ConsulBalancer) watchRules() {
	var lastIndex uint64 // 记录上一次 Consul 数据的版本号
	for {
		select {
		case <-cb.stopCh: // 如果收到停止信号，退出循环
			logger.Info("Stopping Consul rules watcher")
			return
		default:
			// 使用长轮询从 Consul 获取规则
			// 【核心技术】长轮询 (Long Polling)
			// cb.client.KV().Get 发起 HTTP 请求给 Consul。
			// 参数 WaitIndex: lastIndex 告诉 Consul：
			// "如果 gateway/loadbalancer/rules 这个 Key 的版本号还是 lastIndex，你就别理我，卡住（Hold）这个请求。"
			// "直到版本号变了（有人修改了配置），或者超时了，你再返回。"
			kv, meta, err := cb.client.KV().Get("gateway/loadbalancer/rules", &api.QueryOptions{
				WaitIndex: lastIndex,
			})
			// ... (错误处理) ...
			if err != nil || kv == nil {
				logger.Error("Failed to retrieve load balancer rules from Consul",
					zap.Error(err))
				time.Sleep(5 * time.Second) // 失败后延迟重试
				continue
			}

			// 如果代码走到这里，说明配置【一定】发生了变化（或者超时）。
			lastIndex = meta.LastIndex // 更新版本号，下次用新的查
			// 解析 JSON
			var newRules map[string][]string
			if err := json.Unmarshal(kv.Value, &newRules); err != nil {
				logger.Error("Failed to unmarshal load balancer rules from Consul",
					zap.Error(err))
				time.Sleep(5 * time.Second) // 失败后延迟重试
				continue
			}

			// 【写锁更新】
			// 加上写锁，把解析好的新规则替换掉旧的 cb.rules
			cb.mu.Lock()
			cb.rules = newRules
			cb.mu.Unlock()

			logger.Info("Successfully updated load balancer rules from Consul",
				zap.Any("rules", newRules))
			time.Sleep(1 * time.Second) // 下次轮询前的短暂休眠
		}
	}
}

// Stop 终止 Consul 规则监听协程
func (cb *ConsulBalancer) Stop() {
	close(cb.stopCh)
	logger.Info("Consul load balancer stopped")
}
