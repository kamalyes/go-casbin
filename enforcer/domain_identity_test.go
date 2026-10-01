/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-08-01 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-08-01 01:00:00
 * @FilePath: \go-casbin\enforcer\domain_identity_test.go
 * @Description: 域名身份绑定单元测试 + 性能基准测试
 *
 * 测试覆盖：
 *   1. NormalizeDomainHost 归一化（端口/X-Forwarded-Host/trailing dot/IPv6/大小写）
 *   2. SyncTenantHostBindings 增删联动（一致性、幂等、空 tenantID 跳过）
 *   3. EnforceTenantHostBinding 正向校验（命中/未命中/空参数）
 *   4. ResolveTenantByHost 反查租户（命中/未命中/空 host）
 *   5. 多 host 绑定同一租户场景
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package enforcer

import (
	"fmt"
	"testing"

	"github.com/kamalyes/go-casbin/policy"
	"github.com/kamalyes/go-logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// domainIdentityModelText 支持 p2（ABAC）的 RBAC 域模型
const domainIdentityModelText = `
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[policy_definition]
p2 = sub_rule, dom, obj, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && keyMatch3(r.obj, p.obj) && (r.act == p.act || p.act == "*") || eval(p2.sub_rule) && r.dom == p2.dom && keyMatch3(r.obj, p2.obj) && (r.act == p2.act || p2.act == "*")
`

// newDomainIdentityEnforcer 创建带 p2 模型的内存 enforcer
func newDomainIdentityEnforcer(t *testing.T) *Enforcer {
	t.Helper()
	e, err := NewEnforcer(
		WithModelText(domainIdentityModelText),
		WithAutoSave(true),
		WithEnabled(true),
	)
	require.NoError(t, err)
	require.NotNil(t, e)
	t.Cleanup(func() { e.Close() })
	return e
}

// ==================== NormalizeDomainHost ====================

func TestNormalizeDomainHost(t *testing.T) {
	tests := []struct {
		name string
		host string
		want string
	}{
		{"simple", "example.com", "example.com"},
		{"upper", "Example.COM", "example.com"},
		{"with_port", "example.com:443", "example.com"},
		{"with_port_upper", "Admin.Example.com:443", "admin.example.com"},
		{"forwarded_host", "example.com, cdn.example.com", "example.com"},
		{"forwarded_host_spaces", " example.com , cdn.example.com ", "example.com"},
		{"trailing_dot", "example.com.", "example.com"},
		{"ipv6_brackets", "[::1]", "::1"},
		{"ipv6_with_port", "[::1]:8080", "::1"},
		{"empty", "", ""},
		{"spaces_only", "   ", ""},
		{"mixed_case_with_port", "API.Example.COM:8443", "api.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, NormalizeDomainHost(tt.host))
		})
	}
}

// ==================== SyncTenantHostBindings ====================

func TestSyncTenantHostBindings_AddAndEnforce(t *testing.T) {
	e := newDomainIdentityEnforcer(t)

	require.NoError(t, e.SyncTenantHostBindings("t001", []string{"admin.example.com"}, nil))

	ok, err := e.EnforceTenantHostBinding("t001", "u001", "admin.example.com")
	assert.NoError(t, err)
	assert.True(t, ok, "bound host should pass enforce")
}

func TestSyncTenantHostBindings_RemoveBreaksEnforce(t *testing.T) {
	e := newDomainIdentityEnforcer(t)

	require.NoError(t, e.SyncTenantHostBindings("t001", []string{"admin.example.com"}, nil))
	require.NoError(t, e.SyncTenantHostBindings("t001", nil, []string{"admin.example.com"}))

	ok, err := e.EnforceTenantHostBinding("t001", "u001", "admin.example.com")
	assert.NoError(t, err)
	assert.False(t, ok, "removed host should fail enforce")
}

func TestSyncTenantHostBindings_Idempotent(t *testing.T) {
	e := newDomainIdentityEnforcer(t)

	// 重复添加同一 host 不报错、不重复
	require.NoError(t, e.SyncTenantHostBindings("t001", []string{"admin.example.com"}, nil))
	require.NoError(t, e.SyncTenantHostBindings("t001", []string{"admin.example.com"}, nil))

	// p2 策略只有 1 条，不会因重复添加而膨胀
	p2 := e.GetNamedPolicy("p2")
	assert.Len(t, p2, 1, "idempotent add should not duplicate policies")
}

func TestSyncTenantHostBindings_EmptyTenantID_NoOp(t *testing.T) {
	e := newDomainIdentityEnforcer(t)

	// 空 tenantID 是 no-op（OPS 域无域名限制）
	require.NoError(t, e.SyncTenantHostBindings("", []string{"admin.example.com"}, nil))

	assert.Empty(t, e.GetNamedPolicy("p2"), "empty tenantID should not write any policy")
}

func TestSyncTenantHostBindings_MultiHostSameTenant(t *testing.T) {
	e := newDomainIdentityEnforcer(t)

	// 一个租户绑定多个 host
	hosts := []string{"admin.example.com", "api.example.com:443", "portal.Example.COM"}
	require.NoError(t, e.SyncTenantHostBindings("t001", hosts, nil))

	// 每个 host 都能正向校验通过
	for _, h := range hosts {
		ok, err := e.EnforceTenantHostBinding("t001", "u001", h)
		assert.NoError(t, err)
		assert.True(t, ok, "host %s should pass enforce", h)
	}

	// 每个 host 反查都返回同一 tenantID
	for _, h := range hosts {
		tid, err := e.ResolveTenantByHost(h)
		assert.NoError(t, err)
		assert.Equal(t, "t001", tid, "host %s should resolve to t001", h)
	}
}

func TestSyncTenantHostBindings_HostNormalization(t *testing.T) {
	e := newDomainIdentityEnforcer(t)

	// 添加带端口和大写的 host
	require.NoError(t, e.SyncTenantHostBindings("t001", []string{"Admin.Example.com:443"}, nil))

	// 用不带端口的小写 host 校验（归一化后应匹配）
	ok, err := e.EnforceTenantHostBinding("t001", "u001", "admin.example.com")
	assert.NoError(t, err)
	assert.True(t, ok, "normalized host should match")

	tid, err := e.ResolveTenantByHost("admin.example.com")
	assert.NoError(t, err)
	assert.Equal(t, "t001", tid)
}

func TestSyncTenantHostBindings_BatchAddAndRemove(t *testing.T) {
	e := newDomainIdentityEnforcer(t)

	// 批量添加
	addHosts := []string{"a.example.com", "b.example.com", "c.example.com"}
	require.NoError(t, e.SyncTenantHostBindings("t001", addHosts, nil))

	// 批量移除前两个
	require.NoError(t, e.SyncTenantHostBindings("t001", nil, []string{"a.example.com", "b.example.com"}))

	// a、b 已移除
	ok, _ := e.EnforceTenantHostBinding("t001", "u001", "a.example.com")
	assert.False(t, ok)
	ok, _ = e.EnforceTenantHostBinding("t001", "u001", "b.example.com")
	assert.False(t, ok)

	// c 仍存在
	ok, _ = e.EnforceTenantHostBinding("t001", "u001", "c.example.com")
	assert.True(t, ok)
}

func TestSyncTenantHostBindings_SimultaneousAddAndRemove(t *testing.T) {
	e := newDomainIdentityEnforcer(t)

	require.NoError(t, e.SyncTenantHostBindings("t001", []string{"old.example.com"}, nil))

	// 同时添加新 host、移除旧 host
	require.NoError(t, e.SyncTenantHostBindings("t001", []string{"new.example.com"}, []string{"old.example.com"}))

	ok, _ := e.EnforceTenantHostBinding("t001", "u001", "old.example.com")
	assert.False(t, ok, "old host should be removed")

	ok, _ = e.EnforceTenantHostBinding("t001", "u001", "new.example.com")
	assert.True(t, ok, "new host should be added")
}

// ==================== EnforceTenantHostBinding ====================

func TestEnforceTenantHostBinding_UnboundHost(t *testing.T) {
	e := newDomainIdentityEnforcer(t)

	require.NoError(t, e.SyncTenantHostBindings("t001", []string{"admin.example.com"}, nil))

	ok, err := e.EnforceTenantHostBinding("t001", "u001", "other.example.com")
	assert.NoError(t, err)
	assert.False(t, ok, "unbound host should fail")
}

func TestEnforceTenantHostBinding_DifferentTenant(t *testing.T) {
	e := newDomainIdentityEnforcer(t)

	require.NoError(t, e.SyncTenantHostBindings("t001", []string{"admin.example.com"}, nil))

	// 用 t002 校验，不应通过（host 绑定在 t001 上）
	ok, err := e.EnforceTenantHostBinding("t002", "u001", "admin.example.com")
	assert.NoError(t, err)
	assert.False(t, ok, "different tenant should fail")
}

func TestEnforceTenantHostBinding_EmptyParams(t *testing.T) {
	e := newDomainIdentityEnforcer(t)

	require.NoError(t, e.SyncTenantHostBindings("t001", []string{"admin.example.com"}, nil))

	tests := []struct {
		name     string
		tenantID string
		userID   string
		host     string
	}{
		{"empty_tenant", "", "u001", "admin.example.com"},
		{"empty_user", "t001", "", "admin.example.com"},
		{"empty_host", "t001", "u001", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, err := e.EnforceTenantHostBinding(tt.tenantID, tt.userID, tt.host)
			assert.NoError(t, err)
			assert.False(t, ok, "empty param should return false")
		})
	}
}

// ==================== ResolveTenantByHost ====================

func TestResolveTenantByHost_Hit(t *testing.T) {
	e := newDomainIdentityEnforcer(t)

	require.NoError(t, e.SyncTenantHostBindings("t001", []string{"admin.example.com"}, nil))

	tid, err := e.ResolveTenantByHost("admin.example.com")
	assert.NoError(t, err)
	assert.Equal(t, "t001", tid)
}

func TestResolveTenantByHost_Miss(t *testing.T) {
	e := newDomainIdentityEnforcer(t)

	tid, err := e.ResolveTenantByHost("unbound.example.com")
	assert.NoError(t, err)
	assert.Empty(t, tid, "unbound host should resolve to empty")
}

func TestResolveTenantByHost_EmptyHost(t *testing.T) {
	e := newDomainIdentityEnforcer(t)

	tid, err := e.ResolveTenantByHost("")
	assert.NoError(t, err)
	assert.Empty(t, tid)
}

func TestResolveTenantByHost_AfterRemove(t *testing.T) {
	e := newDomainIdentityEnforcer(t)

	require.NoError(t, e.SyncTenantHostBindings("t001", []string{"admin.example.com"}, nil))
	require.NoError(t, e.SyncTenantHostBindings("t001", nil, []string{"admin.example.com"}))

	tid, err := e.ResolveTenantByHost("admin.example.com")
	assert.NoError(t, err)
	assert.Empty(t, tid, "removed host should resolve to empty")
}

// ==================== 性能基准测试 ====================

func BenchmarkEnforceTenantHostBinding(b *testing.B) {
	e, _ := NewEnforcer(
		WithModelText(domainIdentityModelText),
		WithAutoSave(true),
		WithEnabled(true),
		WithLogger(logger.NewEmptyLogger()),
	)
	defer e.Close()
	_ = e.SyncTenantHostBindings("t001", []string{"admin.example.com"}, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = e.EnforceTenantHostBinding("t001", "u001", "admin.example.com")
	}
}

func BenchmarkEnforceTenantHostBinding_MultiBindings(b *testing.B) {
	e, _ := NewEnforcer(
		WithModelText(domainIdentityModelText),
		WithAutoSave(true),
		WithEnabled(true),
		WithLogger(logger.NewEmptyLogger()),
	)
	defer e.Close()

	hosts := make([]string, 100)
	for i := 0; i < 100; i++ {
		hosts[i] = "host" + string(rune('a'+i%26)) + ".example.com"
	}
	_ = e.SyncTenantHostBindings("t001", hosts, nil)

	// 查询最后一个 host（最坏情况：遍历所有策略）
	target := hosts[len(hosts)-1]

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = e.EnforceTenantHostBinding("t001", "u001", target)
	}
}

func BenchmarkResolveTenantByHost(b *testing.B) {
	e, _ := NewEnforcer(
		WithModelText(domainIdentityModelText),
		WithAutoSave(true),
		WithEnabled(true),
		WithLogger(logger.NewEmptyLogger()),
	)
	defer e.Close()
	_ = e.SyncTenantHostBindings("t001", []string{"admin.example.com"}, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = e.ResolveTenantByHost("admin.example.com")
	}
}

func BenchmarkResolveTenantByHost_MultiBindings(b *testing.B) {
	e, _ := NewEnforcer(
		WithModelText(domainIdentityModelText),
		WithAutoSave(true),
		WithEnabled(true),
		WithLogger(logger.NewEmptyLogger()),
	)
	defer e.Close()

	hosts := make([]string, 100)
	for i := 0; i < 100; i++ {
		hosts[i] = "host" + string(rune('a'+i%26)) + ".example.com"
	}
	_ = e.SyncTenantHostBindings("t001", hosts, nil)

	target := hosts[len(hosts)-1]

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = e.ResolveTenantByHost(target)
	}
}

func BenchmarkSyncTenantHostBindings_AddRemove(b *testing.B) {
	e, _ := NewEnforcer(
		WithModelText(domainIdentityModelText),
		WithAutoSave(true),
		WithEnabled(true),
		WithLogger(logger.NewEmptyLogger()),
	)
	defer e.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.SyncTenantHostBindings("t001", []string{"bench.example.com"}, nil)
		_ = e.SyncTenantHostBindings("t001", nil, []string{"bench.example.com"})
	}
}

// ==================== ListTenantHostBindings 测试 ====================

func TestListTenantHostBindings_All(t *testing.T) {
	e := newDomainIdentityEnforcer(t)

	require.NoError(t, e.SyncTenantHostBindings("t001", []string{"a.example.com"}, nil))
	require.NoError(t, e.SyncTenantHostBindings("t002", []string{"b.example.com"}, nil))

	bindings := e.ListTenantHostBindings("")
	assert.Len(t, bindings, 2)
}

func TestListTenantHostBindings_FilterByTenant(t *testing.T) {
	e := newDomainIdentityEnforcer(t)

	require.NoError(t, e.SyncTenantHostBindings("t001", []string{"a.example.com"}, nil))
	require.NoError(t, e.SyncTenantHostBindings("t002", []string{"b.example.com"}, nil))

	bindings := e.ListTenantHostBindings("t001")
	assert.Len(t, bindings, 1)
	assert.Equal(t, "t001", bindings[0].TenantID)
	assert.Equal(t, "a.example.com", bindings[0].Host)
}

func TestListTenantHostBindings_Empty(t *testing.T) {
	e := newDomainIdentityEnforcer(t)

	bindings := e.ListTenantHostBindings("")
	assert.Empty(t, bindings)
}

func TestListTenantHostBindings_SkipsMalformed(t *testing.T) {
	e := newDomainIdentityEnforcer(t)

	require.NoError(t, e.SyncTenantHostBindings("t001", []string{"a.example.com"}, nil))

	// 手动添加格式异常的 p2 策略（len < 3、空 tenantID、空 host）
	_ = e.SelfAddPolicy("p", "p2", []string{domainIdentitySubRule, "", "domain::", domainIdentityAction})
	_ = e.SelfAddPolicy("p", "p2", []string{domainIdentitySubRule, "t001", "", domainIdentityAction})

	bindings := e.ListTenantHostBindings("")
	// 只应返回正常的 1 条绑定（空 tenantID 和空 host 的条目被跳过）
	assert.Len(t, bindings, 1)
	assert.Equal(t, "a.example.com", bindings[0].Host)
}

// ==================== addTenantHostBinding / removeTenantHostBinding 边界测试 ====================

func TestAddTenantHostBinding_EmptyParams(t *testing.T) {
	e := newDomainIdentityEnforcer(t)

	// 空 host 或 tenantID 应直接返回 nil（no-op）
	assert.NoError(t, e.addTenantHostBinding("", "admin.example.com"))
	assert.NoError(t, e.addTenantHostBinding("t001", ""))
	assert.Empty(t, e.GetNamedPolicy("p2"))
}

func TestRemoveTenantHostBinding_EmptyParams(t *testing.T) {
	e := newDomainIdentityEnforcer(t)

	// 空 host 或 tenantID 应直接返回 nil（no-op）
	assert.NoError(t, e.removeTenantHostBinding("", "admin.example.com"))
	assert.NoError(t, e.removeTenantHostBinding("t001", ""))
}

// ==================== SyncTenantHostBindings 错误路径测试 ====================

// addFailAdapter 的 AddPolicy 总是失败（用于测试 addTenantHostBinding 错误路径）
type domainAddFailAdapter struct {
	policy.MemoryAdapter
}

func (a *domainAddFailAdapter) AddPolicy(line string) error {
	return fmt.Errorf("adapter add failed")
}

func TestSyncTenantHostBindings_AddError(t *testing.T) {
	adapter := &domainAddFailAdapter{}
	e, err := NewEnforcer(
		WithModelText(domainIdentityModelText),
		WithAdapter(adapter),
		WithAutoSave(true),
		WithEnabled(true),
	)
	require.NoError(t, err)
	t.Cleanup(func() { e.Close() })

	// addTenantHostBinding 内部调用 AddNamedPolicy → adapter.AddPolicy 失败
	err = e.SyncTenantHostBindings("t001", []string{"admin.example.com"}, nil)
	assert.Error(t, err)
}

// removeFailAdapter 的 RemovePolicy 总是失败（用于测试 removeTenantHostBinding 错误路径）
type domainRemoveFailAdapter struct {
	policy.MemoryAdapter
}

func (a *domainRemoveFailAdapter) RemovePolicy(line string) error {
	return fmt.Errorf("adapter remove failed")
}

func TestSyncTenantHostBindings_RemoveError(t *testing.T) {
	adapter := &domainRemoveFailAdapter{}
	e, err := NewEnforcer(
		WithModelText(domainIdentityModelText),
		WithAdapter(adapter),
		WithAutoSave(true),
		WithEnabled(true),
	)
	require.NoError(t, err)
	t.Cleanup(func() { e.Close() })

	// 先添加绑定（MemoryAdapter 的 AddPolicy 正常工作）
	require.NoError(t, e.SyncTenantHostBindings("t001", []string{"admin.example.com"}, nil))

	// 移除时 adapter.RemovePolicy 失败
	err = e.SyncTenantHostBindings("t001", nil, []string{"admin.example.com"})
	assert.Error(t, err)
}
