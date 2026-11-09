/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\identity_test.go
 * @Description: 域身份绑定测试
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package casbin

import "testing"

func newDomainEnforcer(t *testing.T, opts ...Option) *Enforcer {
	t.Helper()

	base := []Option{WithModelPath("resources/rbac_with_domains_model.conf")}
	e, err := NewEnforcer(append(base, opts...)...)
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}
	t.Cleanup(func() { _ = e.Close() })

	return e
}

func TestNormalizeDomainHost(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"A.Example.com", "a.example.com"},
		{"a.example.com:8443", "a.example.com"},
		{"a.example.com.", "a.example.com"},
		{"  a.example.com  ", "a.example.com"},
		{"a.example.com, b.example.com", "a.example.com"}, // X-Forwarded-Host 取首值
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"[2001:db8::1]", "2001:db8::1"},
		{"", ""},
	}
	for _, c := range cases {
		if got := NormalizeDomainHost(c.in); got != c.want {
			t.Errorf("NormalizeDomainHost(%q) = %q; want %q", c.in, got, c.want)
		}
	}
}

func TestSyncAndResolveTenantHostBinding(t *testing.T) {
	e := newDomainEnforcer(t)

	if err := e.SyncTenantHostBindings(t.Context(), "tenant-a",
		[]string{"A.Example.com:8443", "alt.example.com"}, nil); err != nil {
		t.Fatalf("SyncTenantHostBindings: %v", err)
	}

	// 归一化后才落库，反查时同样归一化
	for _, host := range []string{"a.example.com", "A.EXAMPLE.COM", "a.example.com:9000"} {
		got, err := e.ResolveTenantByHost(host)
		if err != nil {
			t.Fatalf("ResolveTenantByHost(%q): %v", host, err)
		}
		if got != "tenant-a" {
			t.Errorf("ResolveTenantByHost(%q) = %q; want tenant-a", host, got)
		}
	}

	if got, err := e.ResolveTenantByHost("unknown.example.com"); err != nil || got != "" {
		t.Fatalf("ResolveTenantByHost(unknown) = %q, %v; want empty", got, err)
	}
}

func TestSyncIsIdempotent(t *testing.T) {
	e := newDomainEnforcer(t)

	for i := 0; i < 3; i++ {
		if err := e.SyncTenantHostBindings(t.Context(), "tenant-a", []string{"a.example.com"}, nil); err != nil {
			t.Fatalf("SyncTenantHostBindings #%d: %v", i, err)
		}
	}

	bindings, err := e.ListTenantHostBindings("tenant-a")
	if err != nil {
		t.Fatalf("ListTenantHostBindings: %v", err)
	}
	if len(bindings) != 1 {
		t.Fatalf("bindings = %v; want exactly one after repeated syncs", bindings)
	}
}

func TestEnforceTenantHostBinding(t *testing.T) {
	e := newDomainEnforcer(t)

	if err := e.SyncTenantHostBindings(t.Context(), "tenant-a", []string{"a.example.com"}, nil); err != nil {
		t.Fatalf("SyncTenantHostBindings: %v", err)
	}

	cases := []struct {
		name               string
		tenant, user, host string
		want               bool
	}{
		{"bound host", "tenant-a", "u1", "a.example.com", true},
		{"host of another tenant", "tenant-b", "u1", "a.example.com", false},
		{"unbound host", "tenant-a", "u1", "b.example.com", false},
		{"missing user", "tenant-a", "", "a.example.com", false},
		{"missing tenant", "", "u1", "a.example.com", false},
		{"missing host", "tenant-a", "u1", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := e.EnforceTenantHostBinding(t.Context(), c.tenant, c.user, c.host)
			if err != nil {
				t.Fatalf("EnforceTenantHostBinding: %v", err)
			}
			if got != c.want {
				t.Fatalf("got %v; want %v", got, c.want)
			}
		})
	}
}

func TestRemoveTenantHostBinding(t *testing.T) {
	e := newDomainEnforcer(t)

	if err := e.SyncTenantHostBindings(t.Context(), "tenant-a",
		[]string{"a.example.com", "b.example.com"}, nil); err != nil {
		t.Fatalf("SyncTenantHostBindings add: %v", err)
	}
	if err := e.SyncTenantHostBindings(t.Context(), "tenant-a",
		nil, []string{"a.example.com"}); err != nil {
		t.Fatalf("SyncTenantHostBindings remove: %v", err)
	}

	if got, err := e.ResolveTenantByHost("a.example.com"); err != nil || got != "" {
		t.Fatalf("removed host still resolves to %q (%v)", got, err)
	}
	if got, err := e.ResolveTenantByHost("b.example.com"); err != nil || got != "tenant-a" {
		t.Fatalf("remaining host resolves to %q (%v); want tenant-a", got, err)
	}
}

func TestListTenantHostBindingsFiltersByTenant(t *testing.T) {
	e := newDomainEnforcer(t)

	if err := e.SyncTenantHostBindings(t.Context(), "tenant-a", []string{"a.example.com"}, nil); err != nil {
		t.Fatalf("sync a: %v", err)
	}
	if err := e.SyncTenantHostBindings(t.Context(), "tenant-b", []string{"b.example.com"}, nil); err != nil {
		t.Fatalf("sync b: %v", err)
	}

	all, err := e.ListTenantHostBindings("")
	if err != nil {
		t.Fatalf("ListTenantHostBindings(all): %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("all = %v; want 2", all)
	}

	only, err := e.ListTenantHostBindings("tenant-b")
	if err != nil {
		t.Fatalf("ListTenantHostBindings(tenant-b): %v", err)
	}
	if len(only) != 1 || only[0].TenantID != "tenant-b" || only[0].Host != "b.example.com" {
		t.Fatalf("only = %v; want just tenant-b/b.example.com", only)
	}
}

func TestSyncSkipsEmptyTenant(t *testing.T) {
	e := newDomainEnforcer(t)

	// tenantID 为空表示该域不做域名限制，直接跳过而不是写一条空绑定
	if err := e.SyncTenantHostBindings(t.Context(), "", []string{"a.example.com"}, nil); err != nil {
		t.Fatalf("SyncTenantHostBindings: %v", err)
	}

	bindings, err := e.ListTenantHostBindings("")
	if err != nil {
		t.Fatalf("ListTenantHostBindings: %v", err)
	}
	if len(bindings) != 0 {
		t.Fatalf("bindings = %v; want none", bindings)
	}
}

func TestCustomNormalizeHostIsUsed(t *testing.T) {
	e := newDomainEnforcer(t, WithNormalizeHost(func(string) string { return "fixed.example.com" }))

	if err := e.SyncTenantHostBindings(t.Context(), "tenant-a", []string{"whatever"}, nil); err != nil {
		t.Fatalf("SyncTenantHostBindings: %v", err)
	}
	if got, err := e.ResolveTenantByHost("anything-at-all"); err != nil || got != "tenant-a" {
		t.Fatalf("ResolveTenantByHost = %q, %v; want tenant-a", got, err)
	}
}
