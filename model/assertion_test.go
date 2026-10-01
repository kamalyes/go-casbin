/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\model\assertion_test.go
 * @Description: 断言定义测试
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSectionConstants(t *testing.T) {
	assert.Equal(t, "r", SectionRequestDefinition)
	assert.Equal(t, "p", SectionPolicyDefinition)
	assert.Equal(t, "g", SectionRoleDefinition)
	assert.Equal(t, "e", SectionPolicyEffect)
	assert.Equal(t, "m", SectionMatchers)
}

func TestNewAssertion(t *testing.T) {
	a := NewAssertion("r", "sub, obj, act")
	assert.Equal(t, "r", a.Key)
	assert.Equal(t, "sub, obj, act", a.Value)
	assert.Equal(t, []string{"r.sub", "r.obj", "r.act"}, a.Tokens)
}

func TestNewAssertion_EmptyValue(t *testing.T) {
	a := NewAssertion("r", "")
	assert.Nil(t, a.Tokens)
}

func TestAssertion_AddRemovePolicy(t *testing.T) {
	a := NewAssertion("p", "sub, obj, act")

	policy := []string{"alice", "data1", "read"}
	a.AddPolicy(policy)
	assert.Len(t, a.Policies, 1)
	assert.True(t, a.HasPolicy(policy))

	// 重复添加
	a.AddPolicy(policy)
	assert.Len(t, a.Policies, 1)

	// 删除
	assert.True(t, a.RemovePolicy(policy))
	assert.Len(t, a.Policies, 0)
	assert.False(t, a.HasPolicy(policy))

	// 删除不存在的
	assert.False(t, a.RemovePolicy(policy))
}

func TestAssertion_ClearPolicies(t *testing.T) {
	a := NewAssertion("p", "sub, obj, act")
	a.AddPolicy([]string{"alice", "data1", "read"})
	a.AddPolicy([]string{"bob", "data2", "write"})

	a.ClearPolicies()
	assert.Empty(t, a.Policies)
	assert.Empty(t, a.PolicyMap)
}

func TestAssertion_BuildRoleLinkCondition(t *testing.T) {
	a := NewAssertion("g", "_, _")
	result := a.BuildRoleLinkCondition("alice", "admin")
	assert.Equal(t, "alice:admin", result)
}

func TestAssertion_RebuildPolicyMap(t *testing.T) {
	a := NewAssertion("p", "sub, obj, act")
	a.AddPolicy([]string{"alice", "data1", "read"})
	a.AddPolicy([]string{"bob", "data2", "write"})

	// 手动修改 Policies 后重建索引
	a.Policies = append(a.Policies, []string{"eve", "data3", "write"})
	a.RebuildPolicyMap()

	assert.Contains(t, a.PolicyMap, "alice,data1,read")
	assert.Contains(t, a.PolicyMap, "bob,data2,write")
	assert.Contains(t, a.PolicyMap, "eve,data3,write")
}

func TestAssertion_RebuildPolicyMap_NilPolicyMap(t *testing.T) {
	// 直接构造 Assertion，PolicyMap 为 nil，触发 RebuildPolicyMap 的 nil 分支
	a := &Assertion{
		Key:      "p",
		Value:    "sub, obj, act",
		Policies: [][]string{{"alice", "data1", "read"}},
	}
	a.RebuildPolicyMap()
	assert.NotNil(t, a.PolicyMap)
	assert.Contains(t, a.PolicyMap, "alice,data1,read")
}
