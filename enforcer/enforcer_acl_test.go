/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\enforcer\enforcer_acl_test.go
 * @Description: 测试ACL模型
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */
package enforcer

import (
	"path/filepath"
	"testing"

	"github.com/kamalyes/go-casbin/policy"
	"github.com/kamalyes/go-logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	aclModelPath         = filepath.Join("..", "resources", "acl_model.conf")
	aclPolicyPath        = filepath.Join("..", "resources", "acl_policy.csv")
	rbacModelPath        = filepath.Join("..", "resources", "rbac_model.conf")
	rbacPolicyPath       = filepath.Join("..", "resources", "rbac_policy.csv")
	rbacDomainModelPath  = filepath.Join("..", "resources", "rbac_with_domains_model.conf")
	rbacDomainPolicyPath = filepath.Join("..", "resources", "rbac_with_domains_policy.csv")
)

func newTestEnforcer(t *testing.T, modelPath, policyPath string) *Enforcer {
	t.Helper()
	fileAdapter := policy.NewFileAdapter(policyPath)
	policies, err := fileAdapter.LoadPolicy()
	require.NoError(t, err)

	memAdapter := policy.NewMemoryAdapter()
	err = memAdapter.SavePolicy(policies)
	require.NoError(t, err)

	e, err := NewEnforcer(
		WithModelPath(modelPath),
		WithAdapter(memAdapter),
		WithAutoSave(true),
	)
	require.NoError(t, err)
	require.NotNil(t, e)
	t.Cleanup(func() { e.Close() })
	return e
}

func newMemoryEnforcer(t *testing.T, modelPath string) *Enforcer {
	t.Helper()
	e, err := NewEnforcer(
		WithModelPath(modelPath),
		WithAutoSave(true),
	)
	require.NoError(t, err)
	require.NotNil(t, e)
	t.Cleanup(func() { e.Close() })
	return e
}

// newMemoryEnforcerB 用于 benchmark 的 enforcer 创建辅助函数
// 使用 testing.TB 接口，兼容 *testing.T 和 *testing.B
// 使用空日志实现，避免日志输出污染基准数据并干扰耗时测量
func newMemoryEnforcerB(tb testing.TB, modelPath string) *Enforcer {
	tb.Helper()
	e, err := NewEnforcer(
		WithModelPath(modelPath),
		WithAutoSave(true),
		WithLogger(logger.NewEmptyLogger()),
	)
	if err != nil {
		tb.Fatal(err)
	}
	return e
}

func TestACLBasicEnforce(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)

	ok, err := e.Enforce("alice", "data1", "read")
	assert.NoError(t, err)
	assert.True(t, ok, "alice should be able to read data1")

	ok, err = e.Enforce("alice", "data1", "write")
	assert.NoError(t, err)
	assert.True(t, ok, "alice should be able to write data1")

	ok, err = e.Enforce("alice", "data2", "read")
	assert.NoError(t, err)
	assert.False(t, ok, "alice should not be able to read data2")

	ok, err = e.Enforce("bob", "data2", "read")
	assert.NoError(t, err)
	assert.True(t, ok, "bob should be able to read data2")

	ok, err = e.Enforce("bob", "data1", "read")
	assert.NoError(t, err)
	assert.False(t, ok, "bob should not be able to read data1")

	ok, err = e.Enforce("bob", "data2", "write")
	assert.NoError(t, err)
	assert.False(t, ok, "bob should not be able to write data2")
}

func TestACLPolicyManagement(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)

	err := e.AddPolicy("bob", "data1", "write")
	assert.NoError(t, err)

	ok, err := e.Enforce("bob", "data1", "write")
	assert.NoError(t, err)
	assert.True(t, ok, "bob should be able to write data1 after adding policy")

	err = e.RemovePolicy("bob", "data1", "write")
	assert.NoError(t, err)

	ok, err = e.Enforce("bob", "data1", "write")
	assert.NoError(t, err)
	assert.False(t, ok, "bob should not be able to write data1 after removing policy")
}

func TestACLBatchPolicies(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)

	rules := [][]string{
		{"bob", "data1", "read"},
		{"bob", "data1", "write"},
	}
	err := e.AddPolicies(rules)
	assert.NoError(t, err)

	ok, err := e.Enforce("bob", "data1", "read")
	assert.NoError(t, err)
	assert.True(t, ok)

	ok, err = e.Enforce("bob", "data1", "write")
	assert.NoError(t, err)
	assert.True(t, ok)

	err = e.RemovePolicies(rules)
	assert.NoError(t, err)

	ok, err = e.Enforce("bob", "data1", "read")
	assert.NoError(t, err)
	assert.False(t, ok)
}

func TestACLFilteredPolicy(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)

	err := e.RemoveFilteredPolicy(0, "alice")
	assert.NoError(t, err)

	ok, err := e.Enforce("alice", "data1", "read")
	assert.NoError(t, err)
	assert.False(t, ok, "alice should not have any permission after removing all her policies")

	ok, err = e.Enforce("bob", "data2", "read")
	assert.NoError(t, err)
	assert.True(t, ok, "bob's permissions should remain intact")
}

func TestACLUpdatePolicy(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)

	err := e.UpdatePolicy([]string{"alice", "data1", "read"}, []string{"alice", "data2", "read"})
	assert.NoError(t, err)

	ok, err := e.Enforce("alice", "data1", "read")
	assert.NoError(t, err)
	assert.False(t, ok, "alice should no longer read data1")

	ok, err = e.Enforce("alice", "data2", "read")
	assert.NoError(t, err)
	assert.True(t, ok, "alice should now read data2")
}

func TestACLHasPermission(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)

	assert.True(t, e.HasPermissionForUser("alice", "data1", "read"))
	assert.True(t, e.HasPermissionForUser("alice", "data1", "write"))
	assert.False(t, e.HasPermissionForUser("alice", "data2", "read"))
	assert.False(t, e.HasPermissionForUser("bob", "data1", "read"))
}

func TestACLGetPermissions(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)

	perms := e.GetPermissionsForUser("alice")
	assert.Len(t, perms, 2)

	perms = e.GetPermissionsForUser("bob")
	assert.Len(t, perms, 1)
	assert.Equal(t, "bob", perms[0][0])
}

func TestACLDeletePermissionForUser(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)

	err := e.DeletePermissionForUser("alice", "data1", "read")
	assert.NoError(t, err)

	ok, err := e.Enforce("alice", "data1", "read")
	assert.NoError(t, err)
	assert.False(t, ok, "alice should not read data1 after deleting permission")

	ok, err = e.Enforce("alice", "data1", "write")
	assert.NoError(t, err)
	assert.True(t, ok, "alice should still write data1")
}

func TestACLDeletePermissionsForUser(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)

	err := e.DeletePermissionsForUser("alice")
	assert.NoError(t, err)

	ok, err := e.Enforce("alice", "data1", "read")
	assert.NoError(t, err)
	assert.False(t, ok)

	ok, err = e.Enforce("alice", "data1", "write")
	assert.NoError(t, err)
	assert.False(t, ok)
}
