package proxy

import (
	"sync"
	"time"

	"github.com/penwyp/mini-gateway/pkg/util"

	"github.com/gorilla/websocket"
	"github.com/penwyp/mini-gateway/config"
	"github.com/penwyp/mini-gateway/pkg/logger"
	"go.uber.org/zap"
)

// WebSocketPool 管理 WebSocket 连接池
type WebSocketPool struct {
	pool      map[string]*websocket.Conn // 目标地址到连接的映射
	mu        sync.RWMutex               // 读写锁，确保并发安全
	maxIdle   int                        // 允许的最大空闲连接数
	idleTime  time.Duration              // 空闲连接关闭的超时时间
	dialer    *websocket.Dialer          // WebSocket 拨号器,专门用来发起 WebSocket 连接的工具
	poolMgr   *util.ObjectPoolManager    // 可重用对象池管理器
	cleanupCh chan struct{}              // 清理终止信号通道, 用来通知后台清理协程“下班了”
}

// NewWebSocketPool 根据配置创建并初始化 WebSocket 连接池
func NewWebSocketPool(cfg *config.Config) *WebSocketPool {
	pool := &WebSocketPool{
		pool:      make(map[string]*websocket.Conn),
		maxIdle:   cfg.WebSocket.MaxIdleConns, // 未指定时默认为 10
		idleTime:  cfg.WebSocket.IdleTimeout,  // 未指定时默认为 5 分钟
		dialer:    websocket.DefaultDialer,
		cleanupCh: make(chan struct{}),
		poolMgr:   util.NewPoolManager(cfg), // 初始化对象池管理器
	}
	// [关键] 启动后台保洁阿姨
	// 使用 'go' 关键字，让 cleanup 逻辑在后台独立运行，不阻塞主程序
	go pool.startCleanup() // 启动后台清理协程
	logger.Info("WebSocket connection pool initialized",
		zap.Int("maxIdle", pool.maxIdle),
		zap.Duration("idleTimeout", pool.idleTime))
	return pool
}

// GetConn 获取现有 WebSocket 连接或为目标创建新连接
func (p *WebSocketPool) GetConn(target string) (*websocket.Conn, error) {
	// --- 第一阶段：只读检查 (快) ---
	p.mu.RLock() // 加读锁。允许其他协程同时也来读，但不许写。
	// 检查池子里有没有这个 target 的连接
	if conn, ok := p.pool[target]; ok && conn != nil {
		p.mu.RUnlock()   // 有的话，解锁
		return conn, nil // 直接返回现成的！复用成功！
	}
	p.mu.RUnlock() // 没有，解锁。准备进入下一阶段。

	// --- 第二阶段：独占锁定 (慢，但安全) ---
	p.mu.Lock() // 加写锁。此时别的协程既不能读也不能写，必须排队等着。
	defer p.mu.Unlock()

	// 双重检查锁，避免竞争条件
	// --- 第三阶段：双重检查 (Double Check) ---
	// [面试考点] 为什么又要查一遍？
	// 举例：
	// 协程 A 和 协程 B 同时发现池子里没有 "ws://api.com"。
	// 协程 A 手快，抢到了 Lock，创建了连接，放进去了，然后 Unlock。
	// 协程 B 刚才在排队，现在拿到了 Lock。如果不查一遍，B 就会以为还是没有，
	// 于是 B 又创建一个新的，覆盖了 A 刚刚创建的连接。A 的连接就丢了（内存泄漏）。
	if conn, ok := p.pool[target]; ok && conn != nil {
		return conn, nil
	}

	// 建立新的 WebSocket 连接
	// --- 第四阶段：真的没有，新建连接 ---
	// 调用 websocket 库拨号
	conn, resp, err := p.dialer.Dial(target, nil)
	if err != nil {
		logger.Error("Failed to establish WebSocket connection",
			zap.String("target", target),
			zap.Error(err))
		if resp != nil {
			logger.Debug("WebSocket handshake response",
				zap.Int("statusCode", resp.StatusCode))
		}
		return nil, err
	}

	// --- 第五阶段：入库 ---
	p.pool[target] = conn // 存进 map，下次别人就能复用了
	logger.Info("Successfully established WebSocket connection",
		zap.String("target", target))
	return conn, nil
}

// ReleaseConn 标记连接为待释放，实际清理由清理协程处理
func (p *WebSocketPool) ReleaseConn(target string) {
	//为什么是空的？
	//因为这里的逻辑是 “共享” 而不是 “借还”。
	//在数据库连接池里，你用完要还回去（Put），因为连接是独占的。
	//在这里，因为多个用户可能同时在用这个连接，
	//你用完了不能还（不能 Close，也不能从 map 删掉），因为别人可能还在用。
	// 不立即操作，依赖清理协程管理连接关闭
}

// Close 关闭连接池并清理所有活跃连接
func (p *WebSocketPool) Close() {
	close(p.cleanupCh) // 通知清理协程停止
	p.mu.Lock()
	defer p.mu.Unlock()

	// 3. 遍历 map，把所有连接物理断开 (TCP FIN)
	for target, conn := range p.pool {
		if err := conn.Close(); err != nil {
			logger.Warn("Failed to close WebSocket connection",
				zap.String("target", target),
				zap.Error(err))
		}
		delete(p.pool, target)
	}
	logger.Info("WebSocket connection pool closed",
		zap.Int("closedConnections", len(p.pool)))
}

// startCleanup 定期清理超出 maxIdle 限制的空闲连接
// 这是一个死循环协程，负责把超量的连接杀掉。
func (p *WebSocketPool) startCleanup() {
	// 创建一个打点器，每 1 分钟响一次
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-p.cleanupCh: // 收到 Close() 发来的下班信号
			logger.Info("WebSocket pool cleanup routine stopped")
			return // 清理通道关闭时退出
		case <-ticker.C: // 每分钟触发一次
			p.mu.Lock()
			// 检查当前连接数是否超过最大限制 (比如 maxIdle=100)
			if len(p.pool) <= p.maxIdle {
				p.mu.Unlock()
				continue // 如果连接数在限制内，跳过清理
			}

			// 使用对象池管理器获取可重用切片
			// --- 这一段逻辑比较“暴力” ---
			// 目标：连接数太多了，需要删掉一些，直到 <= maxIdle。
			targets := p.poolMgr.GetTargets(len(p.pool))
			for target := range p.pool {
				targets = append(targets, target)
			}

			// 关闭连接直到符合 maxIdle 限制
			// 2. 遍历 map (注意：map遍历是随机顺序的)
			for _, target := range targets {
				if len(p.pool) <= p.maxIdle {
					//符合标准停止
					break
				}
				// 3. 开始杀连接
				if conn, ok := p.pool[target]; ok {
					if err := conn.Close(); err != nil {
						logger.Warn("Failed to close idle WebSocket connection",
							zap.String("target", target),
							zap.Error(err))
					}
					delete(p.pool, target)
					logger.Info("Successfully closed idle WebSocket connection",
						zap.String("target", target))
				}
			}

			// 将切片归还对象池
			// 归还切片，解锁
			p.poolMgr.PutTargets(targets)
			p.mu.Unlock()
		}
	}
}
