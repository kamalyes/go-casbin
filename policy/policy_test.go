/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\policy\policy_test.go
 * @Description: 策略核心 CRUD 测试
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package policy

import (
	"testing"

	"github.com/kamalyes/go-casbin/errors"
	"github.com/kamalyes/go-casbin/model"
	"github.com/kamalyes/go-logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestPolicy(t *testing.T) *Policy {
	t.Helper()
	m, err := model.NewModelFromText(`
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`, logger.NewLogger())
	require.NoError(t, err)
	return NewPolicy(m, NewMemoryAdapter(), logger.NewLogger())
}

func newTestPolicyWithAdapter(t *testing.T, adapter Adapter) *Policy {
	t.Helper()
	m, err := model.NewModelFromText(`
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`, logger.NewLogger())
	require.NoError(t, err)
	return NewPolicy(m, adapter, logger.NewLogger())
}

// ==================== Policy CRUD 测试 ====================

func TestPolicy_LoadPolicy(t *testing.T) {
	p := newTestPolicy(t)
	err := p.LoadPolicy()
	require.NoError(t, err)
}

func TestPolicy_AddPolicy(t *testing.T) {
	p := newTestPolicy(t)
	err := p.AddPolicy("", "p", []string{"alice", "data1", "read"})
	require.NoError(t, err)
	assert.True(t, p.HasPolicy("p", []string{"alice", "data1", "read"}))
}

func TestPolicy_AddPolicy_Duplicate(t *testing.T) {
	p := newTestPolicy(t)
	err := p.AddPolicy("", "p", []string{"alice", "data1", "read"})
	require.NoError(t, err)

	err = p.AddPolicy("", "p", []string{"alice", "data1", "read"})
	assert.Error(t, err)
}

func TestPolicy_AddPolicy_NotFoundType(t *testing.T) {
	p := newTestPolicy(t)
	err := p.AddPolicy("", "p2", []string{"alice", "data1", "read"})
	assert.Error(t, err)
}

func TestPolicy_RemovePolicy(t *testing.T) {
	p := newTestPolicy(t)
	err := p.AddPolicy("", "p", []string{"alice", "data1", "read"})
	require.NoError(t, err)

	err = p.RemovePolicy("", "p", []string{"alice", "data1", "read"})
	require.NoError(t, err)
	assert.False(t, p.HasPolicy("p", []string{"alice", "data1", "read"}))
}

func TestPolicy_RemovePolicy_NotFound(t *testing.T) {
	p := newTestPolicy(t)
	err := p.RemovePolicy("", "p", []string{"alice", "data1", "read"})
	assert.Error(t, err)
}

func TestPolicy_AddPolicies(t *testing.T) {
	p := newTestPolicy(t)
	rules := [][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
	}
	err := p.AddPolicies("", "p", rules)
	require.NoError(t, err)
	assert.True(t, p.HasPolicy("p", []string{"alice", "data1", "read"}))
	assert.True(t, p.HasPolicy("p", []string{"bob", "data2", "write"}))
}

func TestPolicy_AddPoliciesEx(t *testing.T) {
	p := newTestPolicy(t)
	err := p.AddPolicy("", "p", []string{"alice", "data1", "read"})
	require.NoError(t, err)

	rules := [][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
	}
	err = p.AddPoliciesEx("", "p", rules)
	require.NoError(t, err)
	assert.True(t, p.HasPolicy("p", []string{"bob", "data2", "write"}))
}

func TestPolicy_RemovePolicies(t *testing.T) {
	p := newTestPolicy(t)
	rules := [][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
	}
	err := p.AddPolicies("", "p", rules)
	require.NoError(t, err)

	err = p.RemovePolicies("", "p", rules)
	require.NoError(t, err)
	assert.False(t, p.HasPolicy("p", []string{"alice", "data1", "read"}))
}

func TestPolicy_UpdatePolicy(t *testing.T) {
	p := newTestPolicy(t)
	err := p.AddPolicy("", "p", []string{"alice", "data1", "read"})
	require.NoError(t, err)

	err = p.UpdatePolicy("", "p", []string{"alice", "data1", "read"}, []string{"alice", "data2", "write"})
	require.NoError(t, err)
	assert.True(t, p.HasPolicy("p", []string{"alice", "data2", "write"}))
	assert.False(t, p.HasPolicy("p", []string{"alice", "data1", "read"}))
}

func TestPolicy_UpdatePolicy_NotFound(t *testing.T) {
	p := newTestPolicy(t)
	err := p.UpdatePolicy("", "p", []string{"alice", "data1", "read"}, []string{"bob", "data2", "write"})
	assert.Error(t, err)
}

func TestPolicy_UpdatePolicies(t *testing.T) {
	p := newTestPolicy(t)
	err := p.AddPolicies("", "p", [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}})
	require.NoError(t, err)

	err = p.UpdatePolicies("", "p",
		[][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}},
		[][]string{{"alice", "data3", "exec"}, {"bob", "data4", "delete"}},
	)
	require.NoError(t, err)
	assert.True(t, p.HasPolicy("p", []string{"alice", "data3", "exec"}))
}

func TestPolicy_RemoveFilteredPolicy(t *testing.T) {
	p := newTestPolicy(t)
	err := p.AddPolicies("", "p", [][]string{
		{"alice", "data1", "read"},
		{"alice", "data2", "write"},
		{"bob", "data1", "read"},
	})
	require.NoError(t, err)

	err = p.RemoveFilteredPolicy("", "p", 0, "alice")
	require.NoError(t, err)
	assert.False(t, p.HasPolicy("p", []string{"alice", "data1", "read"}))
	assert.False(t, p.HasPolicy("p", []string{"alice", "data2", "write"}))
	assert.True(t, p.HasPolicy("p", []string{"bob", "data1", "read"}))
}

func TestPolicy_GetFilteredPolicy(t *testing.T) {
	p := newTestPolicy(t)
	err := p.AddPolicies("", "p", [][]string{
		{"alice", "data1", "read"},
		{"alice", "data2", "write"},
		{"bob", "data1", "read"},
	})
	require.NoError(t, err)

	result := p.GetFilteredPolicy("p", 0, "alice")
	assert.Len(t, result, 2)
}

func TestPolicy_GetAllPolicies(t *testing.T) {
	p := newTestPolicy(t)
	err := p.AddPolicies("", "p", [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}})
	require.NoError(t, err)

	all := p.GetAllPolicies("p")
	assert.Len(t, all, 2)
}

func TestPolicy_GetAllSubjects(t *testing.T) {
	p := newTestPolicy(t)
	err := p.AddPolicies("", "p", [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}})
	require.NoError(t, err)

	subjects := p.GetAllSubjects()
	assert.Len(t, subjects, 2)
}

func TestPolicy_GetAllObjects(t *testing.T) {
	p := newTestPolicy(t)
	err := p.AddPolicies("", "p", [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}})
	require.NoError(t, err)

	objects := p.GetAllObjects()
	assert.Len(t, objects, 2)
}

func TestPolicy_GetAllActions(t *testing.T) {
	p := newTestPolicy(t)
	err := p.AddPolicies("", "p", [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}})
	require.NoError(t, err)

	actions := p.GetAllActions()
	assert.Len(t, actions, 2)
}

func TestPolicy_GetAllRoles(t *testing.T) {
	p := newTestPolicy(t)
	p.model.GetAssertion("g").AddPolicy([]string{"alice", "admin"})
	p.model.GetAssertion("g").AddPolicy([]string{"bob", "editor"})

	roles := p.GetAllRoles()
	assert.Len(t, roles, 2)
}

func TestPolicy_GetAllUsers(t *testing.T) {
	p := newTestPolicy(t)
	p.model.GetAssertion("g").AddPolicy([]string{"alice", "admin"})
	p.model.GetAssertion("g").AddPolicy([]string{"bob", "editor"})

	users := p.GetAllUsers()
	assert.Len(t, users, 2)
}

func TestPolicy_SavePolicy(t *testing.T) {
	p := newTestPolicy(t)
	err := p.AddPolicy("", "p", []string{"alice", "data1", "read"})
	require.NoError(t, err)

	err = p.SavePolicy()
	require.NoError(t, err)
}

func TestPolicy_LoadFilteredPolicy(t *testing.T) {
	p := newTestPolicy(t)
	err := p.LoadFilteredPolicy([]string{"alice"})
	require.NoError(t, err)
}

func TestPolicy_IsFiltered(t *testing.T) {
	p := newTestPolicy(t)
	assert.False(t, p.IsFiltered())
}

func TestPolicy_SetGetAdapter(t *testing.T) {
	p := newTestPolicy(t)
	adapter := NewMemoryAdapter()
	p.SetAdapter(adapter)
	assert.Equal(t, adapter, p.GetAdapter())
}

func TestPolicy_GetCache(t *testing.T) {
	p := newTestPolicy(t)
	cache := p.GetCache()
	assert.NotNil(t, cache)
}

func TestPolicy_LoadPolicy_NilAdapter(t *testing.T) {
	m, _ := model.NewModelFromText(`
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub
`, logger.NewLogger())
	p := NewPolicy(m, nil, logger.NewLogger())
	err := p.LoadPolicy()
	assert.Error(t, err)
}

func TestPolicy_SavePolicy_NilAdapter(t *testing.T) {
	m, _ := model.NewModelFromText(`
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub
`, logger.NewLogger())
	p := NewPolicy(m, nil, logger.NewLogger())
	err := p.SavePolicy()
	assert.Error(t, err)
}

// ==================== splitPolicyLine 测试 ====================

func TestSplitPolicyLine(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected []string
	}{
		{"simple", "p, alice, data1, read", []string{"p", "alice", "data1", "read"}},
		{"with_parens", `p, r.sub in ("alice", "bob"), data4, read`, []string{"p", `r.sub in ("alice", "bob")`, "data4", "read"}},
		{"single", "p", []string{"p"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := splitPolicyLine(tt.line)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ==================== addPolicyInternal 测试 ====================

func TestPolicy_AddPolicyInternal(t *testing.T) {
	p := newTestPolicy(t)
	p.addPolicyInternal("p, alice, data1, read")
	assert.True(t, p.HasPolicy("p", []string{"alice", "data1", "read"}))
}

func TestPolicy_AddPolicyInternal_EmptyLine(t *testing.T) {
	p := newTestPolicy(t)
	p.addPolicyInternal("")
	assert.Empty(t, p.GetAllPolicies("p"))
}

func TestPolicy_AddPolicyInternal_UnknownType(t *testing.T) {
	p := newTestPolicy(t)
	p.addPolicyInternal("p2, alice, data1, read")
	assert.Empty(t, p.GetAllPolicies("p"))
}

// ==================== 适配器回退与回滚测试 ====================

// basicAdapter 只实现 Adapter 接口，不实现 BatchAdapter/UpdatableAdapter
type basicAdapter struct {
	policies []string
	failAdd  bool // 模拟 AddPolicy 失败
	failSave bool // 模拟 SavePolicy 失败
}

func newBasicAdapter() *basicAdapter {
	return &basicAdapter{policies: make([]string, 0)}
}

func (ba *basicAdapter) LoadPolicy() ([]string, error) {
	return ba.policies, nil
}

func (ba *basicAdapter) SavePolicy(policies []string) error {
	if ba.failSave {
		return errors.NewPolicyAdapterFailedError("save failed")
	}
	ba.policies = make([]string, len(policies))
	copy(ba.policies, policies)
	return nil
}

func (ba *basicAdapter) AddPolicy(line string) error {
	if ba.failAdd {
		return errors.NewPolicyAdapterFailedError("add failed")
	}
	ba.policies = append(ba.policies, line)
	return nil
}

func (ba *basicAdapter) RemovePolicy(line string) error {
	var filtered []string
	for _, p := range ba.policies {
		if p != line {
			filtered = append(filtered, p)
		}
	}
	ba.policies = filtered
	return nil
}

// failingBatchAdapter 实现 BatchAdapter 但批量操作会失败
type failingBatchAdapter struct {
	MemoryAdapter
	failBatchAdd    bool
	failBatchRemove bool
}

func newFailingBatchAdapter() *failingBatchAdapter {
	return &failingBatchAdapter{MemoryAdapter: *NewMemoryAdapter()}
}

func (fba *failingBatchAdapter) AddPolicies(lines []string) error {
	if fba.failBatchAdd {
		return errors.NewPolicyAdapterFailedError("batch add failed")
	}
	return fba.MemoryAdapter.AddPolicies(lines)
}

func (fba *failingBatchAdapter) RemovePolicies(lines []string) error {
	if fba.failBatchRemove {
		return errors.NewPolicyAdapterFailedError("batch remove failed")
	}
	return fba.MemoryAdapter.RemovePolicies(lines)
}

// failingUpdatableAdapter 实现 UpdatableAdapter 但更新操作会失败
type failingUpdatableAdapter struct {
	MemoryAdapter
	failUpdatePolicy           bool
	failUpdatePolicies         bool
	failUpdateFilteredPolicies bool
}

func newFailingUpdatableAdapter() *failingUpdatableAdapter {
	return &failingUpdatableAdapter{MemoryAdapter: *NewMemoryAdapter()}
}

func (fua *failingUpdatableAdapter) UpdatePolicy(oldLine, newLine string) error {
	if fua.failUpdatePolicy {
		return errors.NewPolicyAdapterFailedError("update policy failed")
	}
	return fua.MemoryAdapter.UpdatePolicy(oldLine, newLine)
}

func (fua *failingUpdatableAdapter) UpdatePolicies(oldLines, newLines []string) error {
	if fua.failUpdatePolicies {
		return errors.NewPolicyAdapterFailedError("update policies failed")
	}
	return fua.MemoryAdapter.UpdatePolicies(oldLines, newLines)
}

func (fua *failingUpdatableAdapter) UpdateFilteredPolicies(newLines []string, fieldIndex int, fieldValues ...string) error {
	if fua.failUpdateFilteredPolicies {
		return errors.NewPolicyAdapterFailedError("update filtered policies failed")
	}
	return fua.MemoryAdapter.UpdateFilteredPolicies(newLines, fieldIndex, fieldValues...)
}

func (fua *failingUpdatableAdapter) UpdateFilteredPoliciesByPType(ptype string, newLines []string, fieldIndex int, fieldValues ...string) error {
	if fua.failUpdateFilteredPolicies {
		return errors.NewPolicyAdapterFailedError("update filtered policies failed")
	}
	return fua.MemoryAdapter.UpdateFilteredPoliciesByPType(ptype, newLines, fieldIndex, fieldValues...)
}

// ==================== UpdatableAdapter 分支测试 ====================

func TestPolicy_RemoveFilteredPolicy_WithUpdatableAdapter(t *testing.T) {
	p := newTestPolicy(t)
	// MemoryAdapter 实现了 UpdatableAdapter
	err := p.AddPolicies("", "p", [][]string{
		{"alice", "data1", "read"},
		{"alice", "data2", "write"},
		{"bob", "data1", "read"},
	})
	require.NoError(t, err)

	err = p.RemoveFilteredPolicy("", "p", 0, "alice")
	require.NoError(t, err)
	assert.False(t, p.HasPolicy("p", []string{"alice", "data1", "read"}))
	assert.True(t, p.HasPolicy("p", []string{"bob", "data1", "read"}))
}

func TestPolicy_RemoveFilteredPolicy_WithoutUpdatableAdapter(t *testing.T) {
	m, err := model.NewModelFromText(`
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[role_definition]
g = _, _
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`, logger.NewLogger())
	require.NoError(t, err)

	adapter := newBasicAdapter()
	p := NewPolicy(m, adapter, logger.NewLogger())

	err = p.AddPolicies("", "p", [][]string{
		{"alice", "data1", "read"},
		{"alice", "data2", "write"},
		{"bob", "data1", "read"},
	})
	require.NoError(t, err)

	err = p.RemoveFilteredPolicy("", "p", 0, "alice")
	require.NoError(t, err)
	assert.False(t, p.HasPolicy("p", []string{"alice", "data1", "read"}))
	assert.True(t, p.HasPolicy("p", []string{"bob", "data1", "read"}))
}

func TestPolicy_RemoveFilteredPolicy_NoMatch(t *testing.T) {
	p := newTestPolicy(t)
	err := p.AddPolicy("", "p", []string{"alice", "data1", "read"})
	require.NoError(t, err)

	err = p.RemoveFilteredPolicy("", "p", 0, "bob")
	require.NoError(t, err)
	assert.True(t, p.HasPolicy("p", []string{"alice", "data1", "read"}))
}

func TestPolicy_UpdatePolicy_WithoutUpdatableAdapter(t *testing.T) {
	m, err := model.NewModelFromText(`
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[role_definition]
g = _, _
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`, logger.NewLogger())
	require.NoError(t, err)

	adapter := newBasicAdapter()
	p := NewPolicy(m, adapter, logger.NewLogger())

	err = p.AddPolicy("", "p", []string{"alice", "data1", "read"})
	require.NoError(t, err)

	err = p.UpdatePolicy("", "p", []string{"alice", "data1", "read"}, []string{"alice", "data2", "write"})
	require.NoError(t, err)
	assert.True(t, p.HasPolicy("p", []string{"alice", "data2", "write"}))
}

func TestPolicy_UpdatePolicies_WithoutUpdatableAdapter(t *testing.T) {
	m, err := model.NewModelFromText(`
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[role_definition]
g = _, _
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`, logger.NewLogger())
	require.NoError(t, err)

	adapter := newBasicAdapter()
	p := NewPolicy(m, adapter, logger.NewLogger())

	err = p.AddPolicies("", "p", [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}})
	require.NoError(t, err)

	err = p.UpdatePolicies("", "p",
		[][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}},
		[][]string{{"alice", "data3", "exec"}, {"bob", "data4", "delete"}},
	)
	require.NoError(t, err)
	assert.True(t, p.HasPolicy("p", []string{"alice", "data3", "exec"}))
	assert.True(t, p.HasPolicy("p", []string{"bob", "data4", "delete"}))
}

// ==================== 适配器错误回滚测试 ====================

func TestPolicy_AddPolicy_AdapterError_Rollback(t *testing.T) {
	m, err := model.NewModelFromText(`
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[role_definition]
g = _, _
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`, logger.NewLogger())
	require.NoError(t, err)

	adapter := newBasicAdapter()
	adapter.failAdd = true
	p := NewPolicy(m, adapter, logger.NewLogger())

	err = p.AddPolicy("", "p", []string{"alice", "data1", "read"})
	assert.Error(t, err)
	assert.False(t, p.HasPolicy("p", []string{"alice", "data1", "read"}))
}

func TestPolicy_RemovePolicy_AdapterError_Rollback(t *testing.T) {
	m, err := model.NewModelFromText(`
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[role_definition]
g = _, _
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`, logger.NewLogger())
	require.NoError(t, err)

	adapter := newBasicAdapter()
	p := NewPolicy(m, adapter, logger.NewLogger())

	// 先添加策略（不通过适配器失败）
	adapter.failAdd = false
	err = p.AddPolicy("", "p", []string{"alice", "data1", "read"})
	require.NoError(t, err)

	// 模拟 RemovePolicy 适配器失败（使用一个 RemovePolicy 会失败的适配器）
	// basicAdapter 的 RemovePolicy 不会失败，需要用另一种方式
	// 使用 nil adapter 测试 RemovePolicy 无适配器场景
	p.SetAdapter(nil)
	err = p.RemovePolicy("", "p", []string{"alice", "data1", "read"})
	require.NoError(t, err)
	assert.False(t, p.HasPolicy("p", []string{"alice", "data1", "read"}))
}

func TestPolicy_AddPolicies_BatchAdapterError_Rollback(t *testing.T) {
	m, err := model.NewModelFromText(`
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[role_definition]
g = _, _
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`, logger.NewLogger())
	require.NoError(t, err)

	fba := newFailingBatchAdapter()
	fba.failBatchAdd = true
	p := NewPolicy(m, fba, logger.NewLogger())

	rules := [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}}
	err = p.AddPolicies("", "p", rules)
	assert.Error(t, err)
	assert.False(t, p.HasPolicy("p", []string{"alice", "data1", "read"}))
	assert.False(t, p.HasPolicy("p", []string{"bob", "data2", "write"}))
}

func TestPolicy_RemovePolicies_BatchAdapterError_Rollback(t *testing.T) {
	m, err := model.NewModelFromText(`
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[role_definition]
g = _, _
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`, logger.NewLogger())
	require.NoError(t, err)

	fba := newFailingBatchAdapter()
	p := NewPolicy(m, fba, logger.NewLogger())

	rules := [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}}
	err = p.AddPolicies("", "p", rules)
	require.NoError(t, err)

	fba.failBatchRemove = true
	err = p.RemovePolicies("", "p", rules)
	assert.Error(t, err)
	// 回滚后策略应恢复
	assert.True(t, p.HasPolicy("p", []string{"alice", "data1", "read"}))
	assert.True(t, p.HasPolicy("p", []string{"bob", "data2", "write"}))
}

func TestPolicy_AddPolicies_WithoutBatchAdapter(t *testing.T) {
	m, err := model.NewModelFromText(`
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[role_definition]
g = _, _
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`, logger.NewLogger())
	require.NoError(t, err)

	adapter := newBasicAdapter()
	p := NewPolicy(m, adapter, logger.NewLogger())

	rules := [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}}
	err = p.AddPolicies("", "p", rules)
	require.NoError(t, err)
	assert.True(t, p.HasPolicy("p", []string{"alice", "data1", "read"}))
	assert.True(t, p.HasPolicy("p", []string{"bob", "data2", "write"}))
}

func TestPolicy_RemovePolicies_WithoutBatchAdapter(t *testing.T) {
	m, err := model.NewModelFromText(`
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[role_definition]
g = _, _
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`, logger.NewLogger())
	require.NoError(t, err)

	adapter := newBasicAdapter()
	p := NewPolicy(m, adapter, logger.NewLogger())

	rules := [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}}
	err = p.AddPolicies("", "p", rules)
	require.NoError(t, err)

	err = p.RemovePolicies("", "p", rules)
	require.NoError(t, err)
	assert.False(t, p.HasPolicy("p", []string{"alice", "data1", "read"}))
	assert.False(t, p.HasPolicy("p", []string{"bob", "data2", "write"}))
}

func TestPolicy_AddPolicies_AllExist(t *testing.T) {
	p := newTestPolicy(t)
	err := p.AddPolicy("", "p", []string{"alice", "data1", "read"})
	require.NoError(t, err)

	// 所有规则都已存在，应返回 nil
	err = p.AddPolicies("", "p", [][]string{{"alice", "data1", "read"}})
	assert.NoError(t, err)
}

func TestPolicy_AddPoliciesEx_AllExist(t *testing.T) {
	p := newTestPolicy(t)
	err := p.AddPolicy("", "p", []string{"alice", "data1", "read"})
	require.NoError(t, err)

	// AddPoliciesEx 忽略已存在的策略
	err = p.AddPoliciesEx("", "p", [][]string{{"alice", "data1", "read"}})
	assert.NoError(t, err)
}

func TestPolicy_AddPoliciesEx_NotFoundType(t *testing.T) {
	p := newTestPolicy(t)
	err := p.AddPoliciesEx("", "p2", [][]string{{"alice", "data1", "read"}})
	assert.Error(t, err)
}

func TestPolicy_RemovePolicies_NotFoundType(t *testing.T) {
	p := newTestPolicy(t)
	err := p.RemovePolicies("", "p2", [][]string{{"alice", "data1", "read"}})
	assert.Error(t, err)
}

func TestPolicy_UpdatePolicy_AdapterError_Rollback(t *testing.T) {
	m, err := model.NewModelFromText(`
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[role_definition]
g = _, _
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`, logger.NewLogger())
	require.NoError(t, err)

	adapter := newBasicAdapter()
	p := NewPolicy(m, adapter, logger.NewLogger())

	err = p.AddPolicy("", "p", []string{"alice", "data1", "read"})
	require.NoError(t, err)

	// 设置适配器为 nil 以测试 UpdatePolicy 的非 UpdatableAdapter 分支
	p.SetAdapter(nil)
	err = p.UpdatePolicy("", "p", []string{"alice", "data1", "read"}, []string{"alice", "data2", "write"})
	require.NoError(t, err)
	assert.True(t, p.HasPolicy("p", []string{"alice", "data2", "write"}))
}

func TestPolicy_GetFilteredPolicy_NoMatch(t *testing.T) {
	p := newTestPolicy(t)
	err := p.AddPolicies("", "p", [][]string{{"alice", "data1", "read"}})
	require.NoError(t, err)

	result := p.GetFilteredPolicy("p", 0, "bob")
	assert.Empty(t, result)
}

func TestPolicy_GetFilteredPolicy_FieldIndexOutOfBounds(t *testing.T) {
	p := newTestPolicy(t)
	err := p.AddPolicies("", "p", [][]string{{"alice", "data1", "read"}})
	require.NoError(t, err)

	// fieldIndex 超出策略长度时，仍应匹配（跳过检查）
	result := p.GetFilteredPolicy("p", 10, "value")
	assert.Len(t, result, 1)
}

func TestPolicy_GetFilteredPolicy_NotFoundType(t *testing.T) {
	p := newTestPolicy(t)
	result := p.GetFilteredPolicy("nonexistent", 0, "alice")
	assert.Nil(t, result)
}

func TestPolicy_GetAllPolicies_NotFound(t *testing.T) {
	p := newTestPolicy(t)
	all := p.GetAllPolicies("nonexistent")
	assert.Nil(t, all)
}

func TestPolicy_HasPolicy_NotFound(t *testing.T) {
	p := newTestPolicy(t)
	assert.False(t, p.HasPolicy("nonexistent", []string{"alice", "data1", "read"}))
}

func TestPolicy_RemoveFilteredPolicy_NotFoundType(t *testing.T) {
	p := newTestPolicy(t)
	err := p.RemoveFilteredPolicy("", "p2", 0, "alice")
	assert.Error(t, err)
}

func TestPolicy_UpdatePolicies_AdapterError(t *testing.T) {
	m, err := model.NewModelFromText(`
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[role_definition]
g = _, _
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`, logger.NewLogger())
	require.NoError(t, err)

	adapter := newBasicAdapter()
	p := NewPolicy(m, adapter, logger.NewLogger())

	err = p.AddPolicies("", "p", [][]string{{"alice", "data1", "read"}})
	require.NoError(t, err)

	// 设置适配器为 nil 以测试 UpdatePolicies 的非 UpdatableAdapter 分支
	p.SetAdapter(nil)
	err = p.UpdatePolicies("", "p",
		[][]string{{"alice", "data1", "read"}},
		[][]string{{"alice", "data2", "write"}},
	)
	require.NoError(t, err)
	assert.True(t, p.HasPolicy("p", []string{"alice", "data2", "write"}))
}

func TestPolicy_UpdatePolicy_UpdatableAdapterError_Rollback(t *testing.T) {
	m, err := model.NewModelFromText(`
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[role_definition]
g = _, _
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`, logger.NewLogger())
	require.NoError(t, err)

	fua := newFailingUpdatableAdapter()
	fua.failUpdatePolicy = true
	p := NewPolicy(m, fua, logger.NewLogger())

	err = p.AddPolicy("", "p", []string{"alice", "data1", "read"})
	require.NoError(t, err)

	err = p.UpdatePolicy("", "p", []string{"alice", "data1", "read"}, []string{"alice", "data2", "write"})
	assert.Error(t, err)
	// 回滚后旧策略应恢复
	assert.True(t, p.HasPolicy("p", []string{"alice", "data1", "read"}))
	assert.False(t, p.HasPolicy("p", []string{"alice", "data2", "write"}))
}

func TestPolicy_UpdatePolicies_UpdatableAdapterError(t *testing.T) {
	m, err := model.NewModelFromText(`
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[role_definition]
g = _, _
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`, logger.NewLogger())
	require.NoError(t, err)

	fua := newFailingUpdatableAdapter()
	fua.failUpdatePolicies = true
	p := NewPolicy(m, fua, logger.NewLogger())

	err = p.AddPolicies("", "p", [][]string{{"alice", "data1", "read"}})
	require.NoError(t, err)

	err = p.UpdatePolicies("", "p",
		[][]string{{"alice", "data1", "read"}},
		[][]string{{"alice", "data2", "write"}},
	)
	assert.Error(t, err)
}

func TestPolicy_RemoveFilteredPolicy_UpdatableAdapterError(t *testing.T) {
	m, err := model.NewModelFromText(`
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[role_definition]
g = _, _
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`, logger.NewLogger())
	require.NoError(t, err)

	fua := newFailingUpdatableAdapter()
	fua.failUpdateFilteredPolicies = true
	p := NewPolicy(m, fua, logger.NewLogger())

	err = p.AddPolicies("", "p", [][]string{
		{"alice", "data1", "read"},
		{"alice", "data2", "write"},
	})
	require.NoError(t, err)

	err = p.RemoveFilteredPolicy("", "p", 0, "alice")
	assert.Error(t, err)
}

func TestPolicy_AddPolicies_NonBatchAdapter_AddPolicyError(t *testing.T) {
	m, err := model.NewModelFromText(`
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[role_definition]
g = _, _
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`, logger.NewLogger())
	require.NoError(t, err)

	adapter := newBasicAdapter()
	adapter.failAdd = true
	p := NewPolicy(m, adapter, logger.NewLogger())

	rules := [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}}
	err = p.AddPolicies("", "p", rules)
	assert.Error(t, err)
	// 回滚后不应有任何策略
	assert.False(t, p.HasPolicy("p", []string{"alice", "data1", "read"}))
}

func TestPolicy_RemovePolicies_NonBatchAdapter_RemovePolicyError(t *testing.T) {
	m, err := model.NewModelFromText(`
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[role_definition]
g = _, _
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`, logger.NewLogger())
	require.NoError(t, err)

	// 使用一个 RemovePolicy 会失败的适配器
	adapter := &removeFailAdapter{}
	p := NewPolicy(m, adapter, logger.NewLogger())

	err = p.AddPolicies("", "p", [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}})
	require.NoError(t, err)

	err = p.RemovePolicies("", "p", [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}})
	assert.Error(t, err)
	// 回滚后策略应恢复
	assert.True(t, p.HasPolicy("p", []string{"alice", "data1", "read"}))
}

func TestPolicy_SetAutoSave(t *testing.T) {
	p := newTestPolicy(t)

	p.SetAutoSave(false)
	assert.False(t, p.IsAutoSave())

	p.SetAutoSave(true)
	assert.True(t, p.IsAutoSave())
}

// removeFailAdapter 只实现 Adapter，RemovePolicy 会失败
type removeFailAdapter struct {
	MemoryAdapter
}

func (rfa *removeFailAdapter) RemovePolicy(line string) error {
	return errors.NewPolicyAdapterFailedError("remove failed")
}

func (rfa *removeFailAdapter) AddPolicies(lines []string) error {
	return rfa.MemoryAdapter.AddPolicies(lines)
}

func (rfa *removeFailAdapter) RemovePolicies(lines []string) error {
	return errors.NewPolicyAdapterFailedError("batch remove failed")
}

// mockFilteredAdapter 实现 FilteredAdapter 接口
type mockFilteredAdapter struct {
	MemoryAdapter
	filtered bool
}

func newMockFilteredAdapter() *mockFilteredAdapter {
	return &mockFilteredAdapter{MemoryAdapter: *NewMemoryAdapter()}
}

func (m *mockFilteredAdapter) LoadFilteredPolicy(filter interface{}) ([]string, error) {
	m.filtered = true
	return []string{"p, alice, data1, read"}, nil
}

func (m *mockFilteredAdapter) IsFiltered() bool {
	return m.filtered
}

// loadFailAdapter 的 LoadPolicy 总是失败
type loadFailAdapter struct {
	MemoryAdapter
}

func (lfa *loadFailAdapter) LoadPolicy() ([]string, error) {
	return nil, errors.NewPolicyAdapterFailedError("load failed")
}

// updateFailAdapter 的 UpdatePolicy/UpdatePolicies 总是失败
type updateFailAdapter struct {
	MemoryAdapter
}

func (u *updateFailAdapter) UpdatePolicy(oldLine, newLine string) error {
	return errors.NewPolicyAdapterFailedError("update failed")
}

func (u *updateFailAdapter) UpdatePolicies(oldLines, newLines []string) error {
	return errors.NewPolicyAdapterFailedError("batch update failed")
}

func TestPolicy_LoadFilteredPolicy_WithFilteredAdapter(t *testing.T) {
	adapter := newMockFilteredAdapter()
	p := newTestPolicyWithAdapter(t, adapter)

	err := p.LoadFilteredPolicy(nil)
	assert.NoError(t, err)
	assert.True(t, p.IsFiltered())
}

func TestPolicy_LoadFilteredPolicy_WithoutFilteredAdapter(t *testing.T) {
	// 使用一个不实现 FilteredAdapter 的适配器
	adapter := newBasicAdapter()
	p := newTestPolicyWithAdapter(t, adapter)

	// 不实现 FilteredAdapter 的适配器应回退到 LoadPolicy
	err := p.LoadFilteredPolicy(nil)
	assert.NoError(t, err)
	assert.False(t, p.IsFiltered())
}

func TestPolicy_LoadPolicy_AdapterError(t *testing.T) {
	adapter := &loadFailAdapter{}
	p := newTestPolicyWithAdapter(t, adapter)

	err := p.LoadPolicy()
	assert.Error(t, err)
}

func TestPolicy_UpdatePolicies_AdapterFail(t *testing.T) {
	adapter := &updateFailAdapter{}
	p := newTestPolicyWithAdapter(t, adapter)

	err := p.AddPolicy("", "p", []string{"alice", "data1", "read"})
	require.NoError(t, err)

	err = p.UpdatePolicies("", "p", [][]string{{"alice", "data1", "read"}}, [][]string{{"bob", "data2", "write"}})
	assert.Error(t, err)
}

// batchRemoveFailAdapter 的 RemovePolicies 总是失败
type batchRemoveFailAdapter struct {
	MemoryAdapter
}

func (brfa *batchRemoveFailAdapter) RemovePolicies(lines []string) error {
	return errors.NewPolicyAdapterFailedError("batch remove failed")
}

func TestPolicy_RemovePolicies_BatchAdapterError(t *testing.T) {
	adapter := &batchRemoveFailAdapter{}
	p := newTestPolicyWithAdapter(t, adapter)

	err := p.AddPolicy("", "p", []string{"alice", "data1", "read"})
	require.NoError(t, err)

	err = p.RemovePolicies("", "p", [][]string{{"alice", "data1", "read"}})
	assert.Error(t, err)
}

// addFailOnlyAdapter 的 AddPolicy 总是失败
type addFailOnlyAdapter struct {
	MemoryAdapter
}

func (afoa *addFailOnlyAdapter) AddPolicy(line string) error {
	return errors.NewPolicyAdapterFailedError("add failed")
}

func TestPolicy_UpdatePolicies_NonUpdatableAdapter_AddFail(t *testing.T) {
	// 使用 basicAdapter（不实现 UpdatableAdapter），让 AddPolicy 失败
	adapter := &addAfterRemoveAdapter{}
	p := newTestPolicyWithAdapter(t, adapter)

	err := p.AddPolicy("", "p", []string{"alice", "data1", "read"})
	require.NoError(t, err)

	// 非 UpdatableAdapter 路径：逐条 AddPolicy 失败应回滚
	err = p.UpdatePolicies("", "p", [][]string{{"alice", "data1", "read"}}, [][]string{{"bob", "data2", "write"}})
	assert.Error(t, err)
}

// addAfterRemoveAdapter 不实现 UpdatableAdapter，AddPolicy 第二次调用失败
type addAfterRemoveAdapter struct {
	addCount int
}

func (aara *addAfterRemoveAdapter) LoadPolicy() ([]string, error) {
	return nil, nil
}

func (aara *addAfterRemoveAdapter) SavePolicy(policies []string) error {
	return nil
}

func (aara *addAfterRemoveAdapter) AddPolicy(line string) error {
	aara.addCount++
	if aara.addCount > 1 {
		return errors.NewPolicyAdapterFailedError("add failed on update")
	}
	return nil
}

func (aara *addAfterRemoveAdapter) RemovePolicy(line string) error {
	return nil
}

// ==================== 补充适配器类型 ====================

// removeFailBasicAdapter 只实现 Adapter，RemovePolicy 总是失败（不实现 BatchAdapter/UpdatableAdapter）
type removeFailBasicAdapter struct {
	policies []string
}

func (a *removeFailBasicAdapter) LoadPolicy() ([]string, error) { return a.policies, nil }
func (a *removeFailBasicAdapter) SavePolicy(p []string) error   { a.policies = p; return nil }
func (a *removeFailBasicAdapter) AddPolicy(line string) error {
	a.policies = append(a.policies, line)
	return nil
}
func (a *removeFailBasicAdapter) RemovePolicy(line string) error {
	return errors.NewPolicyAdapterFailedError("remove failed")
}

// updatableOnlyFailAdapter 实现 UpdatableAdapter 但不实现 PTypeUpdatableAdapter
type updatableOnlyFailAdapter struct {
	failUpdateFiltered bool
}

func (a *updatableOnlyFailAdapter) LoadPolicy() ([]string, error)                    { return nil, nil }
func (a *updatableOnlyFailAdapter) SavePolicy(policies []string) error               { return nil }
func (a *updatableOnlyFailAdapter) AddPolicy(line string) error                      { return nil }
func (a *updatableOnlyFailAdapter) RemovePolicy(line string) error                   { return nil }
func (a *updatableOnlyFailAdapter) UpdatePolicy(oldLine, newLine string) error       { return nil }
func (a *updatableOnlyFailAdapter) UpdatePolicies(oldLines, newLines []string) error { return nil }
func (a *updatableOnlyFailAdapter) UpdateFilteredPolicies(newLines []string, fieldIndex int, fieldValues ...string) error {
	if a.failUpdateFiltered {
		return errors.NewPolicyAdapterFailedError("update filtered failed")
	}
	return nil
}

// filteredFailAdapter 实现 FilteredAdapter，LoadFilteredPolicy 总是失败
type filteredFailAdapter struct {
	MemoryAdapter
}

func (a *filteredFailAdapter) LoadFilteredPolicy(filter interface{}) ([]string, error) {
	return nil, errors.NewPolicyAdapterFailedError("filtered load failed")
}

func (a *filteredFailAdapter) IsFiltered() bool { return true }

// ==================== LoadPolicy / LoadFilteredPolicy / SavePolicy 补充测试 ====================

func TestPolicy_LoadPolicy_WithPolicies(t *testing.T) {
	adapter := NewMemoryAdapter()
	_ = adapter.SavePolicy([]string{"p, alice, data1, read", "p, bob, data2, write"})
	p := newTestPolicyWithAdapter(t, adapter)
	err := p.LoadPolicy()
	require.NoError(t, err)
	assert.True(t, p.HasPolicy("p", []string{"alice", "data1", "read"}))
	assert.True(t, p.HasPolicy("p", []string{"bob", "data2", "write"}))
}

func TestPolicy_LoadFilteredPolicy_Error(t *testing.T) {
	adapter := &filteredFailAdapter{}
	p := newTestPolicyWithAdapter(t, adapter)
	err := p.LoadFilteredPolicy(nil)
	assert.Error(t, err)
}

func TestPolicy_SavePolicy_AdapterError(t *testing.T) {
	adapter := newBasicAdapter()
	adapter.failSave = true
	p := newTestPolicyWithAdapter(t, adapter)
	err := p.AddPolicy("", "p", []string{"alice", "data1", "read"})
	require.NoError(t, err)
	err = p.SavePolicy()
	assert.Error(t, err)
}

// ==================== 断言 nil (ptype 不存在) 补充测试 ====================

func TestPolicy_AddPolicies_NotFoundType(t *testing.T) {
	p := newTestPolicy(t)
	err := p.AddPolicies("", "p2", [][]string{{"alice", "data1", "read"}})
	assert.Error(t, err)
}

func TestPolicy_RemovePolicy_NotFoundType(t *testing.T) {
	p := newTestPolicy(t)
	err := p.RemovePolicy("", "p2", []string{"alice", "data1", "read"})
	assert.Error(t, err)
}

func TestPolicy_UpdatePolicy_NotFoundType(t *testing.T) {
	p := newTestPolicy(t)
	err := p.UpdatePolicy("", "p2", []string{"alice", "data1", "read"}, []string{"bob", "data2", "write"})
	assert.Error(t, err)
}

func TestPolicy_UpdatePolicies_NotFoundType(t *testing.T) {
	p := newTestPolicy(t)
	err := p.UpdatePolicies("", "p2",
		[][]string{{"alice", "data1", "read"}},
		[][]string{{"bob", "data2", "write"}},
	)
	assert.Error(t, err)
}

// ==================== RemovePolicy 适配器错误回滚测试 ====================

func TestPolicy_RemovePolicy_AdapterRemoveError_Rollback(t *testing.T) {
	adapter := &removeFailAdapter{}
	p := newTestPolicyWithAdapter(t, adapter)

	err := p.AddPolicy("", "p", []string{"alice", "data1", "read"})
	require.NoError(t, err)

	err = p.RemovePolicy("", "p", []string{"alice", "data1", "read"})
	assert.Error(t, err)
	// 回滚后策略应恢复
	assert.True(t, p.HasPolicy("p", []string{"alice", "data1", "read"}))
}

// ==================== RemovePolicies 非 BatchAdapter 错误回滚测试 ====================

func TestPolicy_RemovePolicies_NonBatchAdapter_RemoveError(t *testing.T) {
	adapter := &removeFailBasicAdapter{}
	p := newTestPolicyWithAdapter(t, adapter)

	// 使用非 BatchAdapter 路径添加策略
	p.model.GetAssertion("p").AddPolicy([]string{"alice", "data1", "read"})
	p.model.GetAssertion("p").AddPolicy([]string{"bob", "data2", "write"})

	err := p.RemovePolicies("", "p", [][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
	})
	assert.Error(t, err)
	// 回滚后策略应恢复
	assert.True(t, p.HasPolicy("p", []string{"alice", "data1", "read"}))
	assert.True(t, p.HasPolicy("p", []string{"bob", "data2", "write"}))
}

// ==================== RemoveFilteredPolicy UpdatableAdapter 错误回滚测试 ====================

func TestPolicy_RemoveFilteredPolicy_OnlyUpdatableAdapterError(t *testing.T) {
	adapter := &updatableOnlyFailAdapter{failUpdateFiltered: true}
	p := newTestPolicyWithAdapter(t, adapter)

	p.model.GetAssertion("p").AddPolicy([]string{"alice", "data1", "read"})
	p.model.GetAssertion("p").AddPolicy([]string{"alice", "data2", "write"})

	err := p.RemoveFilteredPolicy("", "p", 0, "alice")
	assert.Error(t, err)
	// 回滚后策略应恢复
	assert.True(t, p.HasPolicy("p", []string{"alice", "data1", "read"}))
	assert.True(t, p.HasPolicy("p", []string{"alice", "data2", "write"}))
}

// ==================== UpdateFilteredPolicies 测试 ====================

func TestPolicy_UpdateFilteredPolicies(t *testing.T) {
	p := newTestPolicy(t)
	_ = p.AddPolicies("", "p", [][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
	})

	err := p.UpdateFilteredPolicies("", "p", [][]string{{"carol", "data3", "exec"}}, 0, "alice")
	require.NoError(t, err)
	assert.False(t, p.HasPolicy("p", []string{"alice", "data1", "read"}))
	assert.True(t, p.HasPolicy("p", []string{"carol", "data3", "exec"}))
	assert.True(t, p.HasPolicy("p", []string{"bob", "data2", "write"}))
}

func TestPolicy_UpdateFilteredPolicies_BasicAdapter(t *testing.T) {
	adapter := newBasicAdapter()
	p := newTestPolicyWithAdapter(t, adapter)
	_ = p.AddPolicies("", "p", [][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
	})

	err := p.UpdateFilteredPolicies("", "p", [][]string{{"carol", "data3", "exec"}}, 0, "alice")
	require.NoError(t, err)
	assert.False(t, p.HasPolicy("p", []string{"alice", "data1", "read"}))
	assert.True(t, p.HasPolicy("p", []string{"carol", "data3", "exec"}))
}

func TestPolicy_UpdateFilteredPolicies_UpdatableOnlyAdapter(t *testing.T) {
	adapter := &updatableOnlyFailAdapter{}
	p := newTestPolicyWithAdapter(t, adapter)
	p.model.GetAssertion("p").AddPolicy([]string{"alice", "data1", "read"})
	p.model.GetAssertion("p").AddPolicy([]string{"bob", "data2", "write"})

	err := p.UpdateFilteredPolicies("", "p", [][]string{{"carol", "data3", "exec"}}, 0, "alice")
	require.NoError(t, err)
	assert.False(t, p.HasPolicy("p", []string{"alice", "data1", "read"}))
	assert.True(t, p.HasPolicy("p", []string{"carol", "data3", "exec"}))
	assert.True(t, p.HasPolicy("p", []string{"bob", "data2", "write"}))
}

func TestPolicy_UpdateFilteredPolicies_NotFoundType(t *testing.T) {
	p := newTestPolicy(t)
	err := p.UpdateFilteredPolicies("", "p2", [][]string{{"alice", "data1", "read"}}, 0, "alice")
	assert.Error(t, err)
}

func TestPolicy_UpdateFilteredPolicies_PTypeUpdatableAdapterError(t *testing.T) {
	fua := newFailingUpdatableAdapter()
	fua.failUpdateFilteredPolicies = true
	p := newTestPolicyWithAdapter(t, fua)
	_ = p.AddPolicies("", "p", [][]string{{"alice", "data1", "read"}})

	err := p.UpdateFilteredPolicies("", "p", [][]string{{"bob", "data2", "write"}}, 0, "alice")
	assert.Error(t, err)
	// 回滚后旧策略应恢复
	assert.True(t, p.HasPolicy("p", []string{"alice", "data1", "read"}))
	assert.False(t, p.HasPolicy("p", []string{"bob", "data2", "write"}))
}

func TestPolicy_UpdateFilteredPolicies_UpdatableOnlyAdapterError(t *testing.T) {
	adapter := &updatableOnlyFailAdapter{failUpdateFiltered: true}
	p := newTestPolicyWithAdapter(t, adapter)
	p.model.GetAssertion("p").AddPolicy([]string{"alice", "data1", "read"})

	err := p.UpdateFilteredPolicies("", "p", [][]string{{"bob", "data2", "write"}}, 0, "alice")
	assert.Error(t, err)
	// 回滚后旧策略应恢复
	assert.True(t, p.HasPolicy("p", []string{"alice", "data1", "read"}))
	assert.False(t, p.HasPolicy("p", []string{"bob", "data2", "write"}))
}

func TestPolicy_UpdateFilteredPolicies_SavePolicyError(t *testing.T) {
	adapter := newBasicAdapter()
	adapter.failSave = true
	p := newTestPolicyWithAdapter(t, adapter)
	p.model.GetAssertion("p").AddPolicy([]string{"alice", "data1", "read"})

	err := p.UpdateFilteredPolicies("", "p", [][]string{{"bob", "data2", "write"}}, 0, "alice")
	assert.Error(t, err)
	// 回滚后旧策略应恢复
	assert.True(t, p.HasPolicy("p", []string{"alice", "data1", "read"}))
}

// ==================== UpdatePolicies 非 UpdatableAdapter 多策略 AddPolicy 失败回滚测试 ====================

func TestPolicy_UpdatePolicies_NonUpdatableAdapter_MultipleNew_AddFail(t *testing.T) {
	adapter := &addAfterRemoveAdapter{}
	p := newTestPolicyWithAdapter(t, adapter)

	// 直接在模型中添加旧策略，避免消耗 addCount
	p.model.GetAssertion("p").AddPolicy([]string{"alice", "data1", "read"})

	// 更新为两条新策略：第一条 AddPolicy 成功(addCount=1)，第二条失败(addCount=2)
	err := p.UpdatePolicies("", "p",
		[][]string{{"alice", "data1", "read"}},
		[][]string{{"bob", "data2", "write"}, {"carol", "data3", "exec"}},
	)
	assert.Error(t, err)
	// 回滚后旧策略应恢复
	assert.True(t, p.HasPolicy("p", []string{"alice", "data1", "read"}))
	assert.False(t, p.HasPolicy("p", []string{"bob", "data2", "write"}))
	assert.False(t, p.HasPolicy("p", []string{"carol", "data3", "exec"}))
}
