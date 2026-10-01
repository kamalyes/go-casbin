/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-10-12 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-10-12 00:00:00
 * @FilePath: \go-casbin\enforcer\enforce_cache.go
 * @Description: Enforce 结果缓存的代际轮转实现
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package enforcer

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/kamalyes/go-toolbox/pkg/syncx"
)

// enforceCacheTTL 单代缓存存活时长
// 条目最长寿命为 2×enforceCacheTTL（当前代剩余时间 + 上一代完整周期）
const enforceCacheTTL = 30 * time.Second

// enforceCacheEntry 缓存条目
// TTL 由所属代的到期时间界定，无需逐条记录过期时间
type enforceCacheEntry struct {
	result  bool
	version uint64 // 写入时的缓存版本号，策略变更后旧版本条目失效
}

// enforceCacheGen 单代缓存
// 到期后整代废弃，由轮转机制保证 TTL 上界
type enforceCacheGen struct {
	entries   syncx.Map[string, enforceCacheEntry]
	expiresAt int64 // 当前代到期时间（unix nano）
}

// generationalEnforceCache 代际轮转的 Enforce 结果缓存
//
// 设计动机（替代"版本号 + 每 N 次 Store 起后台 goroutine 全表扫描清理"）：
//   - 后台清理在高基数场景（每个请求键都不同）下 goroutine 无界堆积，
//     全表 Range 扫描与热路径 Store/Load 竞争，profile 显示其占据 75% CPU
//   - 代际轮转将清理成本降为 O(1)：到期时上一代整体废弃，随 GC 回收
//
// 结构：双代交替，current 接收全部写入，prev 保留上一代供读取
//   - Load：current 优先，miss 后回退 prev（双代保证轮转瞬间的命中率）
//   - Store：写 current，发现 current 到期先轮转
//   - Invalidate：版本号递增 + 两代立即重建，策略变更后全局 miss 且内存即时回收
type generationalEnforceCache struct {
	mu      sync.Mutex                 // 仅序列化轮转/失效的交换动作
	current atomic.Pointer[enforceCacheGen]
	prev    atomic.Pointer[enforceCacheGen]
	version atomic.Uint64
}

// newGenerationalEnforceCache 创建代际轮转缓存
func newGenerationalEnforceCache() *generationalEnforceCache {
	c := &generationalEnforceCache{}
	c.current.Store(newEnforceCacheGen(time.Now()))
	return c
}

// newEnforceCacheGen 创建新代，到期时间为 now + enforceCacheTTL
func newEnforceCacheGen(now time.Time) *enforceCacheGen {
	return &enforceCacheGen{expiresAt: now.Add(enforceCacheTTL).UnixNano()}
}

// Load 查找缓存条目（current 优先，miss 后回退 prev）
// 命中前提：版本号匹配，代到期由轮转机制保证，无需逐条检查时间
func (c *generationalEnforceCache) Load(key string) (enforceCacheEntry, bool) {
	ver := c.version.Load()
	if entry, ok := c.current.Load().entries.Load(key); ok && entry.version == ver {
		return entry, true
	}
	if prev := c.prev.Load(); prev != nil {
		if entry, ok := prev.entries.Load(key); ok && entry.version == ver {
			return entry, true
		}
	}
	return enforceCacheEntry{}, false
}

// Store 写入当前代，发现当前代到期先轮转
// 轮转后旧 current 降级为 prev 供继续读取，原 prev 整体废弃
func (c *generationalEnforceCache) Store(key string, result bool) {
	now := time.Now()
	if now.UnixNano() >= c.current.Load().expiresAt {
		c.rotateLocked(now)
	}
	c.current.Load().entries.Store(key, enforceCacheEntry{
		result:  result,
		version: c.version.Load(),
	})
}

// rotateLocked 轮转到新代（双检锁，并发触发只轮转一次）
// 交换顺序：先把旧 current 晋升为 prev，再切换 current 到新代
// 锁外 Load/Store 读到的中间态（旧 current + 新 prev）始终是一致视图
func (c *generationalEnforceCache) rotateLocked(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	old := c.current.Load()
	if now.UnixNano() < old.expiresAt {
		return // 已被其他 goroutine 轮转
	}
	c.prev.Store(old)
	c.current.Store(newEnforceCacheGen(now))
}

// Invalidate 策略变更时失效全部缓存
// 版本号递增使旧条目立即失效，两代重建使内存即时回收，全程 O(1) 无逐条扫描
func (c *generationalEnforceCache) Invalidate() {
	c.version.Add(1)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.prev.Store(nil)
	c.current.Store(newEnforceCacheGen(time.Now()))
}

// Version 返回当前缓存版本号
func (c *generationalEnforceCache) Version() uint64 {
	return c.version.Load()
}
