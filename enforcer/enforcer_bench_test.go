/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-05-23 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-05-23 00:00:00
 * @FilePath: \go-casbin\enforcer\enforcer_bench_test.go
 * @Description: 性能基准测试，覆盖高并发场景下的吞吐和延迟
 *
 * 测试维度：
 *   1. Enforce 热路径吞吐（缓存命中 vs 未命中）
 *   2. TransactionalSyncUserRoles 并发吞吐
 *   3. enforceCache 版本号失效后的恢复性能
 *   4. 大规模策略下的 Enforce 延迟
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package enforcer

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

// abacRuleModelPath ABAC 规则策略模型路径
var abacRuleModelPath = filepath.Join("..", "resources", "abac_rule_model.conf")

// BenchmarkEnforce_CacheHit 纯缓存命中场景的吞吐
// 验证版本号机制下缓存命中的性能
func BenchmarkEnforce_CacheHit(b *testing.B) {
	e := newMemoryEnforcerB(b, rbacModelPath)
	_ = e.AddPolicy("alice", "data1", "read")

	// 预热缓存
	_, _ = e.Enforce("alice", "data1", "read")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = e.Enforce("alice", "data1", "read")
	}
}

// BenchmarkEnforce_CacheMiss_ColdStart 每次都缓存未命中（不同 key）
// 验证缓存未命中路径的性能
func BenchmarkEnforce_CacheMiss_ColdStart(b *testing.B) {
	e := newMemoryEnforcerB(b, rbacModelPath)
	_ = e.AddPolicy("alice", "data1", "read")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// 每次用不同的 key，强制缓存未命中
		_, _ = e.Enforce("alice", fmt.Sprintf("data%d", i), "read")
	}
}

// BenchmarkEnforceConcurrent 并发 Enforce 吞吐
// 模拟多 goroutine 并行鉴权
func BenchmarkEnforceConcurrent(b *testing.B) {
	e := newMemoryEnforcerB(b, rbacModelPath)
	_ = e.AddPolicy("alice", "data1", "read")

	// 预热缓存
	_, _ = e.Enforce("alice", "data1", "read")

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = e.Enforce("alice", "data1", "read")
		}
	})
}

// BenchmarkTransactionalSyncUserRoles_Concurrent 并发同步用户角色
// 模拟 resyncRoleBoundUsers 的 8 并发场景
func BenchmarkTransactionalSyncUserRoles_Concurrent(b *testing.B) {
	e := newMemoryEnforcerB(b, rbacDomainModelPath)

	// 预填充用户
	users := make([]string, 100)
	for i := range users {
		users[i] = fmt.Sprintf("user%d", i)
		_ = e.AddGroupingPolicy(users[i], "admin", "tenant1")
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var wg sync.WaitGroup
		for j, u := range users {
			wg.Add(1)
			uid := u
			roleIdx := j
			go func() {
				defer wg.Done()
				rules := [][]string{{uid, fmt.Sprintf("role%d", roleIdx%10), "tenant1"}}
				_ = e.TransactionalSyncUserRoles(context.Background(), uid, rules)
			}()
		}
		wg.Wait()
	}
}

// BenchmarkEnforceCache_VersionInvalidation 策略变更后版本号失效的性能
// 模拟高频策略变更下 Enforce 的表现
func BenchmarkEnforceCache_VersionInvalidation(b *testing.B) {
	e := newMemoryEnforcerB(b, rbacModelPath)
	_ = e.AddPolicy("alice", "data1", "read")

	// 预热缓存
	_, _ = e.Enforce("alice", "data1", "read")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// 每次 Enforce 前先变更策略，触发版本号递增
		if i%10 == 0 {
			_ = e.RemovePolicy("alice", "data1", "read")
			_ = e.AddPolicy("alice", "data1", "read")
		}
		_, _ = e.Enforce("alice", "data1", "read")
	}
}

// BenchmarkEnforce_LargePolicy 大规模策略下的 Enforce 延迟
// 验证策略数量增长对 Enforce 性能的影响
func BenchmarkEnforce_LargePolicy(b *testing.B) {
	e := newMemoryEnforcerB(b, rbacModelPath)

	// 填充 10000 条策略
	for i := 0; i < 10000; i++ {
		_ = e.AddPolicy("alice", fmt.Sprintf("data%d", i), "read")
	}

	// 预热缓存
	_, _ = e.Enforce("alice", "data9999", "read")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = e.Enforce("alice", "data9999", "read")
	}
}

// BenchmarkEnforceConcurrent_LargePolicy 大规模策略+并发 Enforce
// 最贴近真实生产场景的基准测试
func BenchmarkEnforceConcurrent_LargePolicy(b *testing.B) {
	e := newMemoryEnforcerB(b, rbacModelPath)

	// 填充 10000 条策略
	for i := 0; i < 10000; i++ {
		_ = e.AddPolicy("alice", fmt.Sprintf("data%d", i), "read")
	}

	// 预热缓存
	_, _ = e.Enforce("alice", "data9999", "read")

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = e.Enforce("alice", "data9999", "read")
		}
	})
}

// BenchmarkEnforceCache_HitRate 统计缓存命中率
// 在高并发 + 间歇性策略变更下，验证缓存命中率
func BenchmarkEnforceCache_HitRate(b *testing.B) {
	e := newMemoryEnforcerB(b, rbacModelPath)
	_ = e.AddPolicy("alice", "data1", "read")

	// 预热缓存
	_, _ = e.Enforce("alice", "data1", "read")

	var hits, total int64

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			atomic.AddInt64(&total, 1)
			_, err := e.Enforce("alice", "data1", "read")
			if err == nil {
				atomic.AddInt64(&hits, 1)
			}
		}
	})

	b.StopTimer()
	hitRate := float64(hits) / float64(total) * 100
	b.ReportMetric(hitRate, "hit_rate%")
}

// ==================== 扩展性能测试 ====================

// BenchmarkEnforce_RoleInheritance RBAC 角色继承链深度对 Enforce 性能的影响
// 构建多层继承链 alice → r1 → r2 → ... → rN → admin，测量 g() 在不同深度下的性能
func BenchmarkEnforce_RoleInheritance(b *testing.B) {
	e := newMemoryEnforcerB(b, rbacModelPath)

	// 构建深度 10 的继承链：alice → level1 → level2 → ... → level9 → admin
	_ = e.AddGroupingPolicy("alice", "level1")
	for i := 1; i < 9; i++ {
		_ = e.AddGroupingPolicy(fmt.Sprintf("level%d", i), fmt.Sprintf("level%d", i+1))
	}
	_ = e.AddGroupingPolicy("level9", "admin")

	// admin 有 data1 的读权限
	_ = e.AddPolicy("admin", "data1", "read")

	// 预热缓存
	_, _ = e.Enforce("alice", "data1", "read")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = e.Enforce("alice", "data1", "read")
	}
}

// BenchmarkEnforce_ABAC_Eval ABAC eval() 动态表达式求值性能
// 验证 eval(p.sub_rule) 路径的性能（每条策略需要独立 vars map）
func BenchmarkEnforce_ABAC_Eval(b *testing.B) {
	e := newMemoryEnforcerB(b, abacRuleModelPath)

	// 添加 ABAC 规则策略
	_ = e.AddPolicy(`r.sub == "alice"`, "data1", "read")
	_ = e.AddPolicy(`r.sub == "bob"`, "data2", "write")

	// 预热缓存
	_, _ = e.Enforce("alice", "data1", "read")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = e.Enforce("alice", "data1", "read")
	}
}

// BenchmarkEnforce_ABAC_Eval_CacheMiss ABAC eval() 缓存未命中路径
// 每次用不同 key，验证 eval 表达式求值的实际性能（无缓存）
func BenchmarkEnforce_ABAC_Eval_CacheMiss(b *testing.B) {
	e := newMemoryEnforcerB(b, abacRuleModelPath)

	// 添加多条 ABAC 规则
	for i := 0; i < 100; i++ {
		_ = e.AddPolicy(fmt.Sprintf(`r.sub == "user%d"`, i), fmt.Sprintf("data%d", i), "read")
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = e.Enforce(fmt.Sprintf("user%d", i%100), fmt.Sprintf("data%d", i%100), "read")
	}
}

// BenchmarkEnforce_Domain 多租户域场景 Enforce 性能
// 验证 g(r.sub, p.sub, r.dom) 三参数角色判断的性能
func BenchmarkEnforce_Domain(b *testing.B) {
	e := newMemoryEnforcerB(b, rbacDomainModelPath)

	// 多租户：10 个租户，每个租户 10 个用户
	for t := 0; t < 10; t++ {
		tenant := fmt.Sprintf("tenant%d", t)
		_ = e.AddPolicy("admin", tenant, "data1", "read")
		for u := 0; u < 10; u++ {
			_ = e.AddGroupingPolicy(fmt.Sprintf("user%d", u), "admin", tenant)
		}
	}

	// 预热缓存
	_, _ = e.Enforce("user0", "tenant0", "data1", "read")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = e.Enforce("user0", "tenant0", "data1", "read")
	}
}

// BenchmarkEnforce_Domain_CacheMiss 多租户域场景缓存未命中
// 每次用不同租户，验证域场景下的实际匹配性能
func BenchmarkEnforce_Domain_CacheMiss(b *testing.B) {
	e := newMemoryEnforcerB(b, rbacDomainModelPath)

	for t := 0; t < 100; t++ {
		tenant := fmt.Sprintf("tenant%d", t)
		_ = e.AddPolicy("admin", tenant, "data1", "read")
		_ = e.AddGroupingPolicy("alice", "admin", tenant)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = e.Enforce("alice", fmt.Sprintf("tenant%d", i%100), "data1", "read")
	}
}

// BenchmarkAddPolicy 批量添加策略的写操作吞吐
// 循环外创建 enforcer，每轮迭代使用不同 rule 走真实写路径（去重检查 + 索引维护 + 适配器写入）
// 旧版每轮重建 enforcer，78% 耗时耗在模型加载与关闭上，测量严重失真
func BenchmarkAddPolicy(b *testing.B) {
	e := newMemoryEnforcerB(b, rbacModelPath)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = e.AddPolicy("alice", fmt.Sprintf("data%d", i), "read")
	}
	b.StopTimer()
	e.Close()
}

// BenchmarkAddGroupingPolicy 批量添加角色分组的性能
// 验证角色链构建 + 通知 + 持久化的综合性能
func BenchmarkAddGroupingPolicy(b *testing.B) {
	e := newMemoryEnforcerB(b, rbacModelPath)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = e.AddGroupingPolicy(fmt.Sprintf("user%d", i), "admin")
	}
}

// BenchmarkEnforce_ShortCircuit_vs_NoShortCircuit 短路优化效果对比
// 短路模式：匹配到第一条 allow 即返回
// 非短路模式：遍历所有匹配策略
func BenchmarkEnforce_ShortCircuit_vs_NoShortCircuit(b *testing.B) {
	// 短路模式
	b.Run("ShortCircuit", func(b *testing.B) {
		e := newMemoryEnforcerB(b, rbacModelPath)
		// 添加 100 条匹配策略（短路只需匹配第一条）
		for i := 0; i < 100; i++ {
			_ = e.AddPolicy("alice", "data1", "read")
		}
		// 预热（用不同 key 避免缓存命中掩盖差异）
		_, _ = e.Enforce("alice", "data1", "read")

		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _ = e.Enforce("alice", "data1", "read")
		}
	})

	// 非短路模式（通过缓存未命中路径触发完整遍历）
	b.Run("CacheMiss_FullScan", func(b *testing.B) {
		e := newMemoryEnforcerB(b, rbacModelPath)
		for i := 0; i < 100; i++ {
			_ = e.AddPolicy("alice", fmt.Sprintf("data%d", i), "read")
		}

		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			// 每次用不同 key 强制遍历所有 100 条策略
			_, _ = e.Enforce("alice", fmt.Sprintf("data%d", i%100), "read")
		}
	})
}

// BenchmarkEnforceCache_CleanupHighCardinality 高基数缓存失效性能
// 填充大量不同 key 的缓存条目后触发失效，验证代际轮转 O(1) 失效的性能
func BenchmarkEnforceCache_CleanupHighCardinality(b *testing.B) {
	e := newMemoryEnforcerB(b, rbacModelPath)

	// 填充 10000 条不同 key 的缓存
	for i := 0; i < 10000; i++ {
		_, _ = e.Enforce("alice", fmt.Sprintf("data%d", i), "read")
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// 每次策略变更后整体失效（版本号递增 + 两代重建）
		e.invalidateEnforceCache()
	}
}

// BenchmarkEnforce_ContextCancelled context 取消快速返回性能
// 验证 context 已取消时不获取锁直接返回的优化效果
func BenchmarkEnforce_ContextCancelled(b *testing.B) {
	e := newMemoryEnforcerB(b, rbacModelPath)
	_ = e.AddPolicy("alice", "data1", "read")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = e.EnforceContext(ctx, "alice", "data1", "read")
	}
}

// BenchmarkEnforce_MixedReadWrite 混合读写场景
// 模拟真实生产环境：90% 读 + 10% 写
func BenchmarkEnforce_MixedReadWrite(b *testing.B) {
	e := newMemoryEnforcerB(b, rbacModelPath)
	_ = e.AddPolicy("alice", "data1", "read")

	// 预热缓存
	_, _ = e.Enforce("alice", "data1", "read")

	var writeCount int64

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if atomic.AddInt64(&writeCount, 1)%10 == 0 {
				// 10% 写操作
				_ = e.RemovePolicy("alice", "data1", "read")
				_ = e.AddPolicy("alice", "data1", "read")
			} else {
				// 90% 读操作
				_, _ = e.Enforce("alice", "data1", "read")
			}
		}
	})
}

// BenchmarkReloadPolicy 策略全量重载性能
// 验证 LoadPolicy + loadRoleLinks + initCachedFields 的综合性能
func BenchmarkReloadPolicy(b *testing.B) {
	e := newMemoryEnforcerB(b, rbacModelPath)

	// 填充 1000 条策略
	for i := 0; i < 1000; i++ {
		_ = e.AddPolicy("alice", fmt.Sprintf("data%d", i), "read")
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = e.ReloadPolicy()
	}
}

// BenchmarkEnforceConcurrent_ABAC ABAC eval 并发性能
// 验证 eval() 表达式在并发场景下的性能和线程安全
func BenchmarkEnforceConcurrent_ABAC(b *testing.B) {
	e := newMemoryEnforcerB(b, abacRuleModelPath)
	_ = e.AddPolicy(`r.sub == "alice"`, "data1", "read")

	// 预热缓存
	_, _ = e.Enforce("alice", "data1", "read")

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = e.Enforce("alice", "data1", "read")
		}
	})
}

// BenchmarkEnforceConcurrent_Domain 多租户并发 Enforce
// 验证域隔离场景下的并发吞吐
func BenchmarkEnforceConcurrent_Domain(b *testing.B) {
	e := newMemoryEnforcerB(b, rbacDomainModelPath)

	for t := 0; t < 10; t++ {
		tenant := fmt.Sprintf("tenant%d", t)
		_ = e.AddPolicy("admin", tenant, "data1", "read")
		_ = e.AddGroupingPolicy("alice", "admin", tenant)
	}

	// 预热缓存
	_, _ = e.Enforce("alice", "tenant0", "data1", "read")

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			_, _ = e.Enforce("alice", fmt.Sprintf("tenant%d", i%10), "data1", "read")
			i++
		}
	})
}
