package proxy

import (
	"net/url"
	"sync"
	"time"

	"github.com/penwyp/mini-gateway/config"
	"github.com/penwyp/mini-gateway/pkg/logger"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

const (
	defaultMaxIdleConnDuration = 30 * time.Second // 默认最大空闲连接持续时间,如果一条连接闲了30秒没用，就自动断开，释放资源
	defaultReadTimeout         = 5 * time.Second  // 默认读取超时, 后端5秒不回话，直接报错（防止网关被卡死）
	defaultWriteTimeout        = 5 * time.Second  // 默认写入超时, 发请求给后端，5秒没发完，报错
)

// HTTPConnectionPool 管理 TCP 连接池
type HTTPConnectionPool struct {
	// 【核心数据结构】
	// Key: 后端地址 (string, 如 "127.0.0.1:8080")
	// Value: *fasthttp.HostClient (专门负责连这个地址的客户端对象)
	// 为什么用 sync.Map？
	// 因为网关是高并发读多写少的（查 Client 多，创建 Client 少），sync.Map 在这种场景下比 Mutex 锁性能更好。
	clients   sync.Map // map[string]*fasthttp.HostClient，使用 sync.Map 提升并发性能
	cfg       *config.Config
	cleanupCh chan struct{} // 清理信号通道
}

// NewHTTPConnectionPool 创建并初始化连接池实例
func NewHTTPConnectionPool(cfg *config.Config) *HTTPConnectionPool {
	pool := &HTTPConnectionPool{
		cfg:       cfg,
		cleanupCh: make(chan struct{}),
	}

	if cfg.Performance.HttpPoolEnabled {
		pool.initializePool(cfg)
	} else {
		logger.Info("HTTP connection pool disabled in configuration")
	}
	return pool
}

// initializePool 根据配置初始化连接池中的目标
// 网关启动时，先把配置文件里写死的后端都连上，避免第一个用户请求进来时才去建立连接（冷启动慢）。
func (p *HTTPConnectionPool) initializePool(cfg *config.Config) {
	var initializedCount int
	rules := cfg.Routing.GetHTTPRules()

	// 遍历所有配置规则
	for _, targetRules := range rules {
		for _, rule := range targetRules {
			// 1. 归一化地址
			// 把 "http://127.0.0.1:8080" 变成 "127.0.0.1:8080"
			if host, err := normalizeTarget(rule.Target); err != nil {
				logger.Error("Invalid target address detected",
					zap.String("target", rule.Target),
					zap.Error(err))
			} else if _, loaded := p.clients.LoadOrStore(host, p.newHostClient(host)); !loaded {
				// 2. 【核心】LoadOrStore
				// 尝试获取，如果没有就存入一个新的。
				// !loaded 表示“之前没存过，这次是新创建的”。
				initializedCount++
				logger.Info("Initialized HostClient for target",
					zap.String("host", host))
			}
		}
	}

	logger.Info("HTTP connection pool initialized successfully",
		zap.Int("initializedTargets", initializedCount))
}

// GetClient 获取或创建指定目标的 HostClient
func (p *HTTPConnectionPool) GetClient(target string) (*fasthttp.HostClient, error) {
	// 1. 清洗地址
	host, err := normalizeTarget(target)
	if err != nil {
		logger.Error("Failed to normalize target address",
			zap.String("target", target),
			zap.Error(err))
		return nil, err
	}

	// 2. 【快路径】查缓存
	// 如果之前连过这个 IP，直接返回现成的 client。
	if client, ok := p.clients.Load(host); ok {
		return client.(*fasthttp.HostClient), nil
	}

	// 3. 【慢路径】动态创建 (Lazy Loading)
	// 问：既然启动时已经 initializePool 了，为什么这里还要 LoadOrStore？
	// 答：为了支持 Consul 动态更新！
	// 如果运维在运行期间通过 Consul 加了一个新 IP，这个 IP 没在启动配置里，
	// 这里就会动态创建一个新的 Client 连上去。
	client, _ := p.clients.LoadOrStore(host, p.newHostClient(host))
	logger.Info("Dynamically created new HostClient",
		zap.String("host", host))
	return client.(*fasthttp.HostClient), nil
}

// normalizeTarget 从目标 URL 中提取 host:port
func normalizeTarget(target string) (string, error) {
	u, err := url.Parse(target) // 尝试按 URL 解析

	if err != nil {
		return "", err
	}
	// 如果 target 只是 "127.0.0.1:8080"，url.Parse 可能解析不出 Host
	// 这时候直接返回原字符串
	if u.Host == "" {
		return target, nil // 处理目标已是 host:port 的情况
	}
	// 如果是 "http://127.0.0.1:8080"，就提取出 "127.0.0.1:8080"
	return u.Host, nil
}

// Close 关闭连接池
func (p *HTTPConnectionPool) Close() {
	close(p.cleanupCh)
	p.clients.Range(func(key, value interface{}) bool {
		p.clients.Delete(key)
		return true
	})
	logger.Info("HTTP connection pool closed")
}

// newHostClient 创建新的 HostClient 并应用配置设置
func (p *HTTPConnectionPool) newHostClient(addr string) *fasthttp.HostClient {
	return &fasthttp.HostClient{
		Addr: addr, // 目标 IP:Port
		// 【性能调优关键点】
		// 限制网关对这一台后端机器建立的最大连接数。
		// 防止网关把后端打挂，或者把网关自己的文件句柄耗尽。
		MaxConns: p.cfg.Performance.MaxConnsPerHost,
		// 应用之前的超时常量
		MaxIdleConnDuration: defaultMaxIdleConnDuration,
		ReadTimeout:         defaultReadTimeout,
		WriteTimeout:        defaultWriteTimeout,
	}
}
