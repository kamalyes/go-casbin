/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\enforcer_test.go
 * @Description: 接入层测试
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package casbin

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

const rbacModelText = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && keyMatch2(r.obj, p.obj) && r.act == p.act
`

func newTestEnforcer(t *testing.T, opts ...Option) *Enforcer {
	t.Helper()

	base := []Option{WithModelText(rbacModelText)}
	e, err := NewEnforcer(append(base, opts...)...)
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}
	t.Cleanup(func() { _ = e.Close() })

	return e
}

func TestNewEnforcerRequiresModel(t *testing.T) {
	if _, err := NewEnforcer(); !errors.Is(err, ErrNoModel) {
		t.Fatalf("err = %v; want ErrNoModel", err)
	}
}

func TestEnforceAndOfficialAPIPromotion(t *testing.T) {
	e := newTestEnforcer(t)

	// 官方管理 API 经方法提升直接可用，无需 import casbin/v3
	if _, err := e.AddPolicy("admin", "/v1/users/*", "GET"); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}
	if _, err := e.AddGroupingPolicy("alice", "admin"); err != nil {
		t.Fatalf("AddGroupingPolicy: %v", err)
	}

	cases := []struct {
		sub, obj, act string
		want          bool
	}{
		{"alice", "/v1/users/42", "GET", true}, // keyMatch2 通配 + 角色继承
		{"alice", "/v1/users/42", "POST", false},
		{"bob", "/v1/users/42", "GET", false},
	}
	for _, c := range cases {
		got, err := e.Enforce(c.sub, c.obj, c.act)
		if err != nil {
			t.Fatalf("Enforce(%s,%s,%s): %v", c.sub, c.obj, c.act, err)
		}
		if got != c.want {
			t.Errorf("Enforce(%s,%s,%s) = %v; want %v", c.sub, c.obj, c.act, got, c.want)
		}
	}
}

func TestDenyAllSwitchDenies(t *testing.T) {
	e := newTestEnforcer(t, WithDenyAll(true))

	got, err := e.Enforce("alice", "/v1/users/1", "GET")
	if !errors.Is(err, ErrDenyAll) {
		t.Fatalf("err = %v; want ErrDenyAll", err)
	}
	if got {
		t.Error("the deny-all switch must deny, not allow")
	}
	if !e.IsDenyAll() {
		t.Error("IsDenyAll() = false while the switch is on")
	}

	// 运行期可关掉
	e.SetDenyAll(false)
	if _, err := e.Enforce("alice", "/v1/users/1", "GET"); err != nil {
		t.Fatalf("Enforce after clearing the switch: %v", err)
	}
}

// TestOfficialEnableEnforceAllowsEverything 钉住官方语义，防止两个开关被混用
//
// 官方 EnableEnforce(false) 是「全部放行」（源码里就是 if !e.enabled { return true, nil }），
// 与本包 WithDenyAll 方向相反。官方那个语义配得上它的名字，本包不覆盖它，
// 只是另给一个方向明确的开关。这个用例在官方改语义时会失败。
func TestOfficialEnableEnforceAllowsEverything(t *testing.T) {
	e := newTestEnforcer(t)

	// 一条策略都没有，正常必然拒绝
	if ok, err := e.Enforce("nobody", "/baseline", "GET"); err != nil || ok {
		t.Fatalf("baseline = %v, %v; want false", ok, err)
	}

	e.EnableEnforce(false) // 官方方法，经内嵌提升可直接调用

	// 必须问一个没问过的请求：官方这个开关不会失效结果缓存，见下一个用例
	ok, err := e.Enforce("nobody", "/never-asked", "GET")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if !ok {
		t.Error("upstream EnableEnforce(false) no longer allows everything; " +
			"the warning in WithDenyAll's doc comment needs revisiting")
	}
}

// TestOfficialEnableEnforceDoesNotInvalidateCache 钉住一个更隐蔽的上游行为
//
// 官方 EnableEnforce 只改一个 bool，不碰结果缓存。于是在带缓存的 enforcer 上
// 切换它，已缓存的请求仍返回旧结果、未缓存的返回新语义 —— 新旧混在一起，
// 取决于这个请求之前有没有被问过。
// 本包的 DenyAll 开关是在查缓存之前判断的，所以切换是立即且彻底的。
func TestOfficialEnableEnforceDoesNotInvalidateCache(t *testing.T) {
	e := newTestEnforcer(t)

	const obj = "/cached"
	if ok, _ := e.Enforce("nobody", obj, "GET"); ok {
		t.Fatal("baseline should deny")
	}

	e.EnableEnforce(false)

	stale, err := e.Enforce("nobody", obj, "GET")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if stale {
		t.Error("upstream now invalidates the cache on EnableEnforce; " +
			"caveats 2.4 can be dropped")
	}

	// 手动失效后才拿到新语义
	if err := e.InvalidateCache(); err != nil {
		t.Fatalf("InvalidateCache: %v", err)
	}
	if ok, _ := e.Enforce("nobody", obj, "GET"); !ok {
		t.Error("after InvalidateCache the disabled enforcer should allow")
	}
}

// TestDenyAllTakesEffectImmediatelyEvenOnCachedRequests 本包开关没有上面那个毛病
func TestDenyAllTakesEffectImmediatelyEvenOnCachedRequests(t *testing.T) {
	e := newTestEnforcer(t)
	if _, err := e.AddPolicy("alice", "/v1/users/*", "GET"); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}

	// 先问一遍让它进缓存
	if ok, _ := e.Enforce("alice", "/v1/users/1", "GET"); !ok {
		t.Fatal("baseline should allow")
	}

	e.SetDenyAll(true)

	if _, err := e.Enforce("alice", "/v1/users/1", "GET"); !errors.Is(err, ErrDenyAll) {
		t.Fatalf("err = %v; want ErrDenyAll on an already-cached request", err)
	}
}

func TestEnforceCtxHonoursCancellation(t *testing.T) {
	e := newTestEnforcer(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := e.EnforceCtx(ctx, "alice", "/v1/users/1", "GET"); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v; want context.Canceled", err)
	}
}

func TestMetricsRecordDecisions(t *testing.T) {
	e := newTestEnforcer(t)
	if _, err := e.AddPolicy("alice", "/v1/users/*", "GET"); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}

	_, _ = e.Enforce("alice", "/v1/users/1", "GET") // allow
	_, _ = e.Enforce("bob", "/v1/users/1", "GET")   // deny

	s := e.Monitor().Snapshot()
	if s.EnforceTotal != 2 || s.EnforceAllow != 1 || s.EnforceDeny != 1 {
		t.Fatalf("snapshot = %+v; want total=2 allow=1 deny=1", s)
	}
	if s.EnforceError != 0 {
		t.Errorf("EnforceError = %d; want 0", s.EnforceError)
	}
}

func TestHealthCheckReportsEmptyPolicySet(t *testing.T) {
	e := newTestEnforcer(t)

	status, results := e.HealthCheck()
	if status != "degraded" {
		t.Fatalf("status = %q; want degraded (policy set is empty)", status)
	}
	if len(results) == 0 {
		t.Fatal("expected check results")
	}

	if _, err := e.AddPolicy("alice", "/v1/users/*", "GET"); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}
	if status, _ = e.HealthCheck(); status != "healthy" {
		t.Fatalf("status = %q; want healthy", status)
	}
}

// ==================== Watcher 回调兜底 ====================

// mockWatcherEx 实现官方 WatcherEx，用于验证本层补全了官方不装的回调
type mockWatcherEx struct {
	callback atomic.Pointer[func(string)]
	closed   atomic.Bool
}

func (w *mockWatcherEx) SetUpdateCallback(fn func(string)) error {
	w.callback.Store(&fn)
	return nil
}
func (w *mockWatcherEx) Update() error { return nil }
func (w *mockWatcherEx) Close()        { w.closed.Store(true) }

func (w *mockWatcherEx) UpdateForAddPolicy(string, string, ...string) error { return nil }
func (w *mockWatcherEx) UpdateForRemovePolicy(string, string, ...string) error {
	return nil
}
func (w *mockWatcherEx) UpdateForRemoveFilteredPolicy(string, string, int, ...string) error {
	return nil
}
func (w *mockWatcherEx) UpdateForSavePolicy(Model) error { return nil }
func (w *mockWatcherEx) UpdateForAddPolicies(string, string, ...[]string) error {
	return nil
}
func (w *mockWatcherEx) UpdateForRemovePolicies(string, string, ...[]string) error {
	return nil
}

func TestWatcherExGetsUpdateCallback(t *testing.T) {
	w := &mockWatcherEx{}
	e := newTestEnforcer(t, WithWatcher(w), WithPolicyPath("resources/rbac_policy.csv"))

	// 官方 SetWatcher 对 WatcherEx 不装回调，本层必须补上
	fn := w.callback.Load()
	if fn == nil {
		t.Fatal("WatcherEx did not receive an update callback")
	}

	// 触发一次远端变更广播，应产生一次本地重载
	(*fn)("remote change")

	if reloads := e.Monitor().Snapshot().PolicyReloads; reloads != 1 {
		t.Fatalf("PolicyReloads = %d; want 1", reloads)
	}
}

func TestCloseReleasesWatcher(t *testing.T) {
	w := &mockWatcherEx{}
	e := newTestEnforcer(t, WithWatcher(w), WithPolicyPath("resources/rbac_policy.csv"))

	if err := e.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !w.closed.Load() {
		t.Error("watcher was not closed")
	}
	// 关闭后应全拒
	if _, err := e.Enforce("alice", "/v1/users/1", "GET"); !errors.Is(err, ErrDenyAll) {
		t.Errorf("err = %v; want ErrDenyAll after Close", err)
	}
}

// ==================== 存储保护 ====================

func TestGuardedRetriesThenSucceeds(t *testing.T) {
	e := newTestEnforcer(t, WithRetry(RetryConfig{MaxAttempts: 3, BaseDelay: time.Millisecond}))

	var calls int
	err := e.Guarded(context.Background(), func() error {
		calls++
		if calls < 3 {
			return errors.New("transient")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Guarded: %v", err)
	}
	if calls != 3 {
		t.Fatalf("calls = %d; want 3", calls)
	}
}

func TestGuardedTripsBreakerAndRecordsReject(t *testing.T) {
	e := newTestEnforcer(t, WithBreaker("test", BreakerConfig{
		MaxFailures:  2,
		ResetTimeout: time.Hour, // 测试期内不自动恢复
	}))

	boom := errors.New("storage down")
	for i := 0; i < 2; i++ {
		if err := e.Guarded(context.Background(), func() error { return boom }); !errors.Is(err, boom) {
			t.Fatalf("attempt %d: err = %v; want storage error", i, err)
		}
	}

	// 失败达阈值后熔断打开，后续调用不再触达下游
	var called bool
	err := e.Guarded(context.Background(), func() error {
		called = true
		return nil
	})
	if !errors.Is(err, ErrBreakerOpen) {
		t.Fatalf("err = %v; want ErrBreakerOpen", err)
	}
	if called {
		t.Error("breaker is open, fn must not be called")
	}
	if rejects := e.Monitor().Snapshot().BreakerRejects; rejects != 1 {
		t.Fatalf("BreakerRejects = %d; want 1", rejects)
	}
	if state := e.Breaker().State(); state != BreakerOpen {
		t.Fatalf("state = %v; want open", state)
	}
}

func TestEnforceIsNotGuardedByBreaker(t *testing.T) {
	// 决策是纯内存运算，存储熔断打开时不应影响决策
	e := newTestEnforcer(t, WithBreaker("test", BreakerConfig{MaxFailures: 1, ResetTimeout: time.Hour}))
	if _, err := e.AddPolicy("alice", "/v1/users/*", "GET"); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}

	boom := errors.New("storage down")
	_ = e.Guarded(context.Background(), func() error { return boom })
	if state := e.Breaker().State(); state != BreakerOpen {
		t.Fatalf("state = %v; want open", state)
	}

	got, err := e.Enforce("alice", "/v1/users/1", "GET")
	if err != nil {
		t.Fatalf("Enforce while breaker open: %v", err)
	}
	if !got {
		t.Error("in-memory decision must still work while the storage breaker is open")
	}
}

// ==================== 无存储时的操作 ====================

func TestStoreOperationsWithoutStoreReturnErrNoAdapter(t *testing.T) {
	e := newTestEnforcer(t)

	cases := map[string]func() error{
		"LoadPolicy":            e.LoadPolicy,
		"SavePolicy":            e.SavePolicy,
		"LoadPolicyCtx":         func() error { return e.LoadPolicyCtx(t.Context()) },
		"SavePolicyCtx":         func() error { return e.SavePolicyCtx(t.Context()) },
		"LoadFilteredPolicyCtx": func() error { return e.LoadFilteredPolicyCtx(t.Context(), nil) },
	}
	for name, call := range cases {
		t.Run(name, func(t *testing.T) {
			if err := call(); !errors.Is(err, ErrNoAdapter) {
				t.Fatalf("err = %v; want ErrNoAdapter", err)
			}
		})
	}
}

// TestOfficialLoadPolicyPanicsWithoutAdapter 钉住上游行为
//
// 官方 Enforcer.loadPolicyFromAdapter 没有 nil 守卫，没配适配器时
// LoadPolicy 会直接空指针 panic。本层因此在 LoadPolicyCtx 里前置判断，
// 否则 Watcher 回调一到就能把进程打挂。
// 这个用例是为了在官方哪天修了之后能察觉到 —— 届时本层的守卫可以简化。
func TestOfficialLoadPolicyPanicsWithoutAdapter(t *testing.T) {
	m, err := NewModelFromString(rbacModelText)
	if err != nil {
		t.Fatalf("NewModelFromString: %v", err)
	}
	official, err := NewSyncedCachedEnforcer(m)
	if err != nil {
		t.Fatalf("NewSyncedCachedEnforcer: %v", err)
	}

	defer func() {
		if recover() == nil {
			t.Error("upstream no longer panics on LoadPolicy without an adapter; " +
				"the guard in LoadPolicyCtx can be revisited")
		}
	}()

	_ = official.LoadPolicy()
}

func TestPolicyChangeWithoutStoreDoesNotPanic(t *testing.T) {
	// 没有存储却收到远端广播时，不能去调会 panic 的官方 LoadPolicy
	w := &mockWatcherEx{}
	e := newTestEnforcer(t, WithWatcher(w))

	fn := w.callback.Load()
	if fn == nil {
		t.Fatal("WatcherEx did not receive an update callback")
	}

	(*fn)("remote change") // 不应 panic

	if reloads := e.Monitor().Snapshot().PolicyReloads; reloads != 0 {
		t.Fatalf("PolicyReloads = %d; want 0 without a store", reloads)
	}
}
