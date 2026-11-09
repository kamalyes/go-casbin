/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\bench_test.go
 * @Description: 接入层基准测试
 *
 * 核心问题只有一个：这一层相对官方原生贵了多少，贵在哪。
 * 因此每个门面基准都配一个用同种底层引擎、同样策略集的官方基线，
 * 两边都走 Enforce(rvals ...interface{})，装箱开销对等。
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package casbin

import (
	"context"
	"fmt"
	"testing"
	"time"

	upstream "github.com/casbin/casbin/v3"
	"github.com/kamalyes/go-casbin/monitor"
)

// benchModel 基准用模型，与官方 rbac_model 等价
const benchModel = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`

// benchPolicies 生成 roles 条策略与 users 条角色绑定
func benchPolicies(roles, users int) (p [][]string, g [][]string) {
	p = make([][]string, 0, roles)
	for i := 0; i < roles; i++ {
		p = append(p, []string{fmt.Sprintf("group%d", i), fmt.Sprintf("data%d", i/10), "read"})
	}

	g = make([][]string, 0, users)
	for i := 0; i < users; i++ {
		g = append(g, []string{fmt.Sprintf("user%d", i), fmt.Sprintf("group%d", i/10)})
	}

	return p, g
}

// newBenchOfficial 构造官方基线：同种底层引擎、同样的缓存设置
func newBenchOfficial(b *testing.B, roles, users int, cache bool) *upstream.SyncedCachedEnforcer {
	b.Helper()

	m, err := NewModelFromString(benchModel)
	if err != nil {
		b.Fatalf("NewModelFromString: %v", err)
	}
	e, err := upstream.NewSyncedCachedEnforcer(m)
	if err != nil {
		b.Fatalf("NewSyncedCachedEnforcer: %v", err)
	}
	e.EnableCache(cache)

	p, g := benchPolicies(roles, users)
	if _, err := e.AddPolicies(p); err != nil {
		b.Fatalf("AddPolicies: %v", err)
	}
	if _, err := e.AddGroupingPolicies(g); err != nil {
		b.Fatalf("AddGroupingPolicies: %v", err)
	}

	return e
}

// newBenchFacade 构造门面层，策略集与官方基线完全一致
func newBenchFacade(b *testing.B, roles, users int, cache bool, opts ...Option) *Enforcer {
	b.Helper()

	base := []Option{WithModelText(benchModel), WithCache(cache)}
	e, err := NewEnforcer(append(base, opts...)...)
	if err != nil {
		b.Fatalf("NewEnforcer: %v", err)
	}
	b.Cleanup(func() { _ = e.Close() })

	p, g := benchPolicies(roles, users)
	if _, err := e.AddPolicies(p); err != nil {
		b.Fatalf("AddPolicies: %v", err)
	}
	if _, err := e.AddGroupingPolicies(g); err != nil {
		b.Fatalf("AddGroupingPolicies: %v", err)
	}

	return e
}

// benchSizes 受测策略规模
var benchSizes = []struct {
	name         string
	roles, users int
}{
	{"policies=100", 100, 1000},
	{"policies=1000", 1000, 10000},
}

// ==================== 缓存未命中：每次都真正求值 ====================

func BenchmarkEnforceOfficialNoCache(b *testing.B) {
	for _, s := range benchSizes {
		b.Run(s.name, func(b *testing.B) {
			e := newBenchOfficial(b, s.roles, s.users, false)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = e.Enforce("user501", "data9", "read")
			}
		})
	}
}

func BenchmarkEnforceFacadeNoCache(b *testing.B) {
	for _, s := range benchSizes {
		b.Run(s.name, func(b *testing.B) {
			e := newBenchFacade(b, s.roles, s.users, false)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = e.Enforce("user501", "data9", "read")
			}
		})
	}
}

// ==================== 缓存命中：网关重复鉴权的真实形态 ====================
//
// 这组最能看出门面层的开销占比：命中路径本身只有一两百纳秒，
// 多出来的 time.Now() 与原子计数在这里是可观的比例。

func BenchmarkEnforceOfficialCacheHit(b *testing.B) {
	e := newBenchOfficial(b, 1000, 10000, true)
	_, _ = e.Enforce("user501", "data9", "read") // 预热缓存

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = e.Enforce("user501", "data9", "read")
	}
}

func BenchmarkEnforceFacadeCacheHit(b *testing.B) {
	e := newBenchFacade(b, 1000, 10000, true)
	_, _ = e.Enforce("user501", "data9", "read")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = e.Enforce("user501", "data9", "read")
	}
}

func BenchmarkEnforceCtxFacadeCacheHit(b *testing.B) {
	e := newBenchFacade(b, 1000, 10000, true)
	ctx := context.Background()
	_, _ = e.EnforceCtx(ctx, "user501", "data9", "read")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = e.EnforceCtx(ctx, "user501", "data9", "read")
	}
}

// ==================== 并发：网关是多核并发鉴权 ====================

func BenchmarkEnforceOfficialParallel(b *testing.B) {
	e := newBenchOfficial(b, 1000, 10000, true)
	_, _ = e.Enforce("user501", "data9", "read")

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = e.Enforce("user501", "data9", "read")
		}
	})
}

func BenchmarkEnforceFacadeParallel(b *testing.B) {
	e := newBenchFacade(b, 1000, 10000, true)
	_, _ = e.Enforce("user501", "data9", "read")

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = e.Enforce("user501", "data9", "read")
		}
	})
}

// ==================== 门面层开销的分解 ====================

// BenchmarkMonitorRecordEnforce 指标采集在决策热路径上的成本
func BenchmarkMonitorRecordEnforce(b *testing.B) {
	m := monitor.New()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.RecordEnforce(true, nil, time.Microsecond)
	}
}

// BenchmarkTimeNow 热路径里为了算耗时付的两次 time.Now
func BenchmarkTimeNow(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		_ = time.Since(start)
	}
}

// BenchmarkContextErr 每次 EnforceCtx 都做的取消检查
func BenchmarkContextErr(b *testing.B) {
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ctx.Err()
	}
}

// ==================== 网关三路决策原语 ====================

func newGatewayFacade(b *testing.B) *Enforcer {
	b.Helper()

	e := newBenchFacade(b, 100, 1000, true,
		WithPublicPolicies([][]string{
			{"/v1/login", "POST"},
			{"/v1/refresh", "POST"},
		}),
		WithAuthSkipPolicies([][]string{
			{"/v1/auth/user-info", "GET"},
		}),
	)

	return e
}

// BenchmarkIsPublicPolicyHit 命中匿名放行
func BenchmarkIsPublicPolicyHit(b *testing.B) {
	e := newGatewayFacade(b)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = e.IsPublicPolicy("/v1/login", "POST")
	}
}

// BenchmarkIsPublicPolicyMiss 未命中，网关最常走的分支
func BenchmarkIsPublicPolicyMiss(b *testing.B) {
	e := newGatewayFacade(b)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = e.IsPublicPolicy("/v1/users/42", "GET")
	}
}

// BenchmarkIsPublicPolicyUnconfigured 没配公共策略时的短路成本
func BenchmarkIsPublicPolicyUnconfigured(b *testing.B) {
	e := newBenchFacade(b, 100, 1000, true)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = e.IsPublicPolicy("/v1/users/42", "GET")
	}
}

// BenchmarkGatewayThreeWay 一次完整的网关判定：
// 公共策略未命中 -> 免鉴权未命中 -> 正常鉴权
// 这是生产里单次请求真正付的总成本
func BenchmarkGatewayThreeWay(b *testing.B) {
	e := newGatewayFacade(b)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if ok, _ := e.IsPublicPolicyCtx(ctx, "/v1/users/42", "GET"); ok {
			continue
		}
		if ok, _ := e.IsAuthSkipPolicyCtx(ctx, "/v1/users/42", "GET"); ok {
			continue
		}
		_, _ = e.EnforceCtx(ctx, "user501", "data9", "read")
	}
}

// ==================== 存储保护路径（非决策热路径）====================

func BenchmarkGuardedNoProtection(b *testing.B) {
	e := newBenchFacade(b, 10, 10, true)
	ctx := context.Background()
	noop := func() error { return nil }

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.Guarded(ctx, noop)
	}
}

func BenchmarkGuardedWithBreakerAndRetry(b *testing.B) {
	e := newBenchFacade(b, 10, 10, true,
		WithBreaker("bench", BreakerConfig{MaxFailures: 5}),
		WithRetry(RetryConfig{MaxAttempts: 3}),
	)
	ctx := context.Background()
	noop := func() error { return nil }

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.Guarded(ctx, noop)
	}
}

func BenchmarkBreakerExecuteClosed(b *testing.B) {
	br := NewBreaker("bench", BreakerConfig{MaxFailures: 5})
	noop := func() error { return nil }

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = br.Execute(noop)
	}
}

func BenchmarkBreakerExecuteParallel(b *testing.B) {
	br := NewBreaker("bench", BreakerConfig{MaxFailures: 5})
	noop := func() error { return nil }

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = br.Execute(noop)
		}
	})
}

// BenchmarkEnforceFacadeCacheHitNoMetrics 关掉指标后的缓存命中路径
// 与 BenchmarkEnforceFacadeCacheHit 的差值即计时开销
func BenchmarkEnforceFacadeCacheHitNoMetrics(b *testing.B) {
	e := newBenchFacade(b, 1000, 10000, true, WithMetrics(false))
	_, _ = e.Enforce("user501", "data9", "read")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = e.Enforce("user501", "data9", "read")
	}
}

// BenchmarkGatewayThreeWayNoMetrics 关掉指标后的完整网关判定
func BenchmarkGatewayThreeWayNoMetrics(b *testing.B) {
	e := newBenchFacade(b, 100, 1000, true,
		WithMetrics(false),
		WithPublicPolicies([][]string{{"/v1/login", "POST"}, {"/v1/refresh", "POST"}}),
		WithAuthSkipPolicies([][]string{{"/v1/auth/user-info", "GET"}}),
	)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if ok, _ := e.IsPublicPolicyCtx(ctx, "/v1/users/42", "GET"); ok {
			continue
		}
		if ok, _ := e.IsAuthSkipPolicyCtx(ctx, "/v1/users/42", "GET"); ok {
			continue
		}
		_, _ = e.EnforceCtx(ctx, "user501", "data9", "read")
	}
}
