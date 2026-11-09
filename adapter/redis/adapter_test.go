/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\adapter\redis\adapter_test.go
 * @Description: 适配器测试（基于 miniredis，不需要真实 Redis）
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package redis

import (
	"errors"
	"testing"

	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/casbin/casbin/v3"
	"github.com/casbin/casbin/v3/model"
	"github.com/kamalyes/go-casbin/adapter/base"
	"github.com/redis/go-redis/v9"
)

const modelText = `
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

func newTestAdapter(t *testing.T) (*Adapter, *miniredis.Miniredis) {
	t.Helper()

	srv := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: srv.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	a, err := NewAdapter(client, WithKeyPrefix("casbin:test"))
	if err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}

	return a, srv
}

func newTestEnforcer(t *testing.T, a *Adapter) *casbin.Enforcer {
	t.Helper()

	m, err := model.NewModelFromString(modelText)
	if err != nil {
		t.Fatalf("NewModelFromString: %v", err)
	}
	e, err := casbin.NewEnforcer(m, a)
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}

	return e
}

func TestNewAdapterRequiresClient(t *testing.T) {
	if _, err := NewAdapter(nil); !errors.Is(err, ErrNoClient) {
		t.Fatalf("err = %v; want ErrNoClient", err)
	}
}

func TestAdapterRoundTripThroughEnforcer(t *testing.T) {
	a, _ := newTestAdapter(t)
	e := newTestEnforcer(t, a)

	if _, err := e.AddPolicy("admin", "data1", "read"); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}
	if _, err := e.AddGroupingPolicy("alice", "admin"); err != nil {
		t.Fatalf("AddGroupingPolicy: %v", err)
	}

	// 换一个 enforcer 从 Redis 重新加载，验证真的落了库
	fresh := newTestEnforcer(t, a)
	ok, err := fresh.Enforce("alice", "data1", "read")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if !ok {
		t.Fatal("policy did not survive a reload from redis")
	}
}

func TestAdapterRuleWithCommaSurvives(t *testing.T) {
	// 规则字段里带逗号时，逗号拼接的编码会在解码时错位，这里验证 JSON 编码不会
	a, _ := newTestAdapter(t)
	e := newTestEnforcer(t, a)

	tricky := []string{"alice", "data,with,commas", "read"}
	if _, err := e.AddPolicy(tricky); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}

	fresh := newTestEnforcer(t, a)
	policies, err := fresh.GetPolicy()
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if len(policies) != 1 {
		t.Fatalf("len(policies) = %d; want 1", len(policies))
	}
	if policies[0][1] != "data,with,commas" {
		t.Fatalf("obj = %q; want the commas preserved", policies[0][1])
	}
}

func TestAdapterBatchAndRemove(t *testing.T) {
	a, _ := newTestAdapter(t)
	e := newTestEnforcer(t, a)

	rules := [][]string{
		{"admin", "data1", "read"},
		{"admin", "data2", "read"},
		{"viewer", "data1", "read"},
	}
	if _, err := e.AddPolicies(rules); err != nil {
		t.Fatalf("AddPolicies: %v", err)
	}

	if _, err := e.RemovePolicies([][]string{rules[0]}); err != nil {
		t.Fatalf("RemovePolicies: %v", err)
	}

	fresh := newTestEnforcer(t, a)
	got, err := fresh.GetPolicy()
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d; want 2 after removing one", len(got))
	}
}

func TestAdapterRemoveFilteredPolicy(t *testing.T) {
	a, _ := newTestAdapter(t)
	e := newTestEnforcer(t, a)

	if _, err := e.AddPolicies([][]string{
		{"admin", "data1", "read"},
		{"admin", "data2", "write"},
		{"viewer", "data1", "read"},
	}); err != nil {
		t.Fatalf("AddPolicies: %v", err)
	}

	// 删除 sub == admin 的全部策略
	if _, err := e.RemoveFilteredPolicy(0, "admin"); err != nil {
		t.Fatalf("RemoveFilteredPolicy: %v", err)
	}

	fresh := newTestEnforcer(t, a)
	got, err := fresh.GetPolicy()
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if len(got) != 1 || got[0][0] != "viewer" {
		t.Fatalf("policies = %v; want only the viewer rule", got)
	}
}

func TestAdapterUpdatePolicy(t *testing.T) {
	a, _ := newTestAdapter(t)
	e := newTestEnforcer(t, a)

	if _, err := e.AddPolicy("admin", "data1", "read"); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}
	if _, err := e.UpdatePolicy([]string{"admin", "data1", "read"}, []string{"admin", "data1", "write"}); err != nil {
		t.Fatalf("UpdatePolicy: %v", err)
	}

	fresh := newTestEnforcer(t, a)
	got, err := fresh.GetPolicy()
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if len(got) != 1 || got[0][2] != "write" {
		t.Fatalf("policies = %v; want the act updated to write", got)
	}
}

func TestAdapterSavePolicyReplacesEverything(t *testing.T) {
	a, _ := newTestAdapter(t)
	e := newTestEnforcer(t, a)

	if _, err := e.AddPolicies([][]string{{"old", "data1", "read"}}); err != nil {
		t.Fatalf("AddPolicies: %v", err)
	}

	// 清掉内存里的策略换一批，再全量写回
	e.ClearPolicy()
	if _, err := e.AddPolicies([][]string{{"new", "data2", "write"}}); err != nil {
		t.Fatalf("AddPolicies: %v", err)
	}
	if err := e.SavePolicy(); err != nil {
		t.Fatalf("SavePolicy: %v", err)
	}

	fresh := newTestEnforcer(t, a)
	got, err := fresh.GetPolicy()
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if len(got) != 1 || got[0][0] != "new" {
		t.Fatalf("policies = %v; want only the new rule", got)
	}
}

func TestAdapterLoadFilteredPolicy(t *testing.T) {
	a, _ := newTestAdapter(t)
	e := newTestEnforcer(t, a)

	if _, err := e.AddPolicies([][]string{
		{"tenant-a-admin", "data1", "read"},
		{"tenant-b-admin", "data2", "read"},
	}); err != nil {
		t.Fatalf("AddPolicies: %v", err)
	}

	fresh := newTestEnforcer(t, a)
	if err := fresh.LoadFilteredPolicy(&Filter{P: []string{"tenant-a-admin"}}); err != nil {
		t.Fatalf("LoadFilteredPolicy: %v", err)
	}
	if !a.IsFiltered() {
		t.Error("IsFiltered() = false after a filtered load")
	}

	got, err := fresh.GetPolicy()
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if len(got) != 1 || got[0][0] != "tenant-a-admin" {
		t.Fatalf("policies = %v; want only tenant-a rules", got)
	}
}

func TestAdapterKeyPrefixIsolatesTenants(t *testing.T) {
	srv := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: srv.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	tenantA, err := NewAdapter(client, WithKeyPrefix("casbin:tenant-a"))
	if err != nil {
		t.Fatalf("NewAdapter a: %v", err)
	}
	tenantB, err := NewAdapter(client, WithKeyPrefix("casbin:tenant-b"))
	if err != nil {
		t.Fatalf("NewAdapter b: %v", err)
	}

	ea := newTestEnforcer(t, tenantA)
	if _, err := ea.AddPolicy("admin", "data1", "read"); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}

	eb := newTestEnforcer(t, tenantB)
	got, err := eb.GetPolicy()
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("tenant-b sees %v; want an empty policy set", got)
	}
}

func TestEncodeDecodeRuleRoundTrip(t *testing.T) {
	in := []string{"alice", `data,with"quotes`, "read"}

	member, err := encodeRule(in)
	if err != nil {
		t.Fatalf("encodeRule: %v", err)
	}
	out, err := decodeRule(member)
	if err != nil {
		t.Fatalf("decodeRule: %v", err)
	}

	if len(out) != len(in) {
		t.Fatalf("len = %d; want %d", len(out), len(in))
	}
	for i := range in {
		if out[i] != in[i] {
			t.Fatalf("out = %v; want %v", out, in)
		}
	}
}

func TestDecodeRuleRejectsGarbage(t *testing.T) {
	if _, err := decodeRule("not json"); err == nil {
		t.Fatal("want an error for a malformed member")
	}
}

func TestKeyBuilderLayout(t *testing.T) {
	k := newKeyBuilder("casbin:tenant-a")

	if got := k.ptypesKey(); got != "casbin:tenant-a:ptypes" {
		t.Errorf("ptypesKey = %q", got)
	}
	if got := k.rulesKey("g2"); got != "casbin:tenant-a:rules:g2" {
		t.Errorf("rulesKey = %q", got)
	}
	// 空前缀回落到默认值，避免键名以冒号开头
	if got := newKeyBuilder("").ptypesKey(); got != "casbin:ptypes" {
		t.Errorf("default ptypesKey = %q", got)
	}
}

func TestNewWatcherRequiresClient(t *testing.T) {
	if _, err := NewWatcher(nil); !errors.Is(err, ErrNoClient) {
		t.Fatalf("err = %v; want ErrNoClient", err)
	}
}

func TestWatcherBroadcastsAndReloadsAcrossNodes(t *testing.T) {
	srv := miniredis.RunT(t)

	clientA := redis.NewClient(&redis.Options{Addr: srv.Addr()})
	clientB := redis.NewClient(&redis.Options{Addr: srv.Addr()})
	t.Cleanup(func() { _ = clientA.Close(); _ = clientB.Close() })

	nodeA, err := NewWatcher(clientA, WithWatcherSource("node-a"))
	if err != nil {
		t.Fatalf("NewWatcher a: %v", err)
	}
	t.Cleanup(nodeA.Close)

	nodeB, err := NewWatcher(clientB, WithWatcherSource("node-b"))
	if err != nil {
		t.Fatalf("NewWatcher b: %v", err)
	}
	t.Cleanup(nodeB.Close)

	received := make(chan string, 4)
	if err := nodeB.SetUpdateCallback(func(payload string) { received <- payload }); err != nil {
		t.Fatalf("SetUpdateCallback: %v", err)
	}
	// node-a 不该收到自己的广播
	if err := nodeA.SetUpdateCallback(func(string) { t.Error("node-a received its own broadcast") }); err != nil {
		t.Fatalf("SetUpdateCallback: %v", err)
	}

	if err := nodeA.UpdateForAddPolicy("p", "p", "alice", "data1", "read"); err != nil {
		t.Fatalf("UpdateForAddPolicy: %v", err)
	}

	select {
	case payload := <-received:
		event, err := UnmarshalEvent([]byte(payload))
		if err != nil {
			t.Fatalf("UnmarshalEvent: %v", err)
		}
		if event.Op != base.OpAddPolicy || event.Source != "node-a" {
			t.Fatalf("event = %+v", event)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("node-b never received the broadcast")
	}
}

func TestWatcherCloseIsIdempotent(t *testing.T) {
	srv := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: srv.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	w, err := NewWatcher(client)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}

	w.Close()
	w.Close() // 重复关闭不应 panic 或挂住
}
