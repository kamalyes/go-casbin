/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\policy\filter_test.go
 * @Description: 策略过滤器测试
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ==================== Filter 结构体测试 ====================

func TestNewFilter(t *testing.T) {
	f := NewFilter()
	assert.NotNil(t, f)
	assert.True(t, f.IsEmpty())
}

func TestFilter_ChainMethods(t *testing.T) {
	f := NewFilter().WithPType("p").WithV0("alice").WithV1("data1").WithV2("read").WithV3("allow").WithV4("extra").WithV5("ext2")
	assert.Equal(t, "p", f.PType)
	assert.Equal(t, "alice", f.V0)
	assert.Equal(t, "data1", f.V1)
	assert.Equal(t, "read", f.V2)
	assert.Equal(t, "allow", f.V3)
	assert.Equal(t, "extra", f.V4)
	assert.Equal(t, "ext2", f.V5)
	assert.False(t, f.IsEmpty())
}

func TestFilter_Values(t *testing.T) {
	f := NewFilter().WithV0("alice").WithV1("data1")
	values := f.Values()
	assert.Len(t, values, 6)
	assert.Equal(t, "alice", values[0])
	assert.Equal(t, "data1", values[1])
}

func TestFilter_AllValues(t *testing.T) {
	f := NewFilter().WithPType("p").WithV0("alice")
	all := f.AllValues()
	assert.Len(t, all, 7)
	assert.Equal(t, "p", all[0])
	assert.Equal(t, "alice", all[1])
}

func TestFilter_NonEmptyFields(t *testing.T) {
	f := NewFilter().WithPType("p").WithV0("alice")
	fields := f.NonEmptyFields()
	assert.Len(t, fields, 2)
	assert.Equal(t, "p", fields[FieldPType])
	assert.Equal(t, "alice", fields[FieldV0])
}

func TestFilter_IsEmpty(t *testing.T) {
	assert.True(t, NewFilter().IsEmpty())
	assert.False(t, NewFilter().WithPType("p").IsEmpty())
	assert.False(t, NewFilter().WithV0("alice").IsEmpty())
}

func TestFilter_FromSlice(t *testing.T) {
	f := NewFilter().FromSlice([]string{"p", "alice", "data1", "read"})
	assert.Equal(t, "p", f.PType)
	assert.Equal(t, "alice", f.V0)
	assert.Equal(t, "data1", f.V1)
	assert.Equal(t, "read", f.V2)
}

func TestFilterFromSlice(t *testing.T) {
	f := FilterFromSlice([]string{"p", "alice", "data1", "read", "tenant1", "extra", "field"})
	assert.Equal(t, "p", f.PType)
	assert.Equal(t, "alice", f.V0)
	assert.Equal(t, "data1", f.V1)
	assert.Equal(t, "read", f.V2)
	assert.Equal(t, "tenant1", f.V3)
	assert.Equal(t, "extra", f.V4)
	assert.Equal(t, "field", f.V5)
}

func TestFilter_Match(t *testing.T) {
	f := NewFilter().WithPType("p").WithV0("alice")

	assert.True(t, f.Match("p, alice, data1, read"))
	assert.False(t, f.Match("p, bob, data1, read"))
	assert.False(t, f.Match("g, alice, admin"))
}

func TestFilter_Match_Empty(t *testing.T) {
	f := NewFilter()
	assert.True(t, f.Match("p, alice, data1, read"))
}

func TestMatchByIndex(t *testing.T) {
	assert.True(t, MatchByIndex("p, alice, data1, read", 1, "alice"))
	assert.True(t, MatchByIndex("p, alice, data1, read", 1, "alice", "data1"))
	assert.False(t, MatchByIndex("p, alice, data1, read", 1, "bob"))
}

func TestFilterPolicies(t *testing.T) {
	policies := []string{
		"p, alice, data1, read",
		"p, bob, data2, write",
		"g, alice, admin",
	}

	// 按过滤器过滤
	filter := NewFilter().WithPType("p")
	result := FilterPolicies(policies, filter)
	assert.Len(t, result, 2)

	// nil 过滤器
	result = FilterPolicies(policies, nil)
	assert.Len(t, result, 3)

	// 空过滤器
	result = FilterPolicies(policies, NewFilter())
	assert.Len(t, result, 3)
}

func TestFilterPoliciesByIndex(t *testing.T) {
	policies := []string{
		"p, alice, data1, read",
		"p, bob, data2, write",
	}

	result := FilterPoliciesByIndex(policies, 1, "alice")
	assert.Len(t, result, 1)

	// 空 fieldValues
	result = FilterPoliciesByIndex(policies, 1)
	assert.Len(t, result, 2)
}

func TestExtractPType(t *testing.T) {
	assert.Equal(t, "p", ExtractPType("p, alice, data1, read"))
	assert.Equal(t, "g", ExtractPType("g, alice, admin"))
	assert.Equal(t, "p", ExtractPType("p"))
	assert.Equal(t, "", ExtractPType(""))
}

func TestInferPType(t *testing.T) {
	tests := []struct {
		name  string
		lines []string
		want  string
	}{
		{name: "empty", lines: nil, want: ""},
		{name: "single type", lines: []string{"p, alice, data1, read", "p, bob, data2, write"}, want: "p"},
		{name: "mixed types", lines: []string{"p, alice, data1, read", "g, alice, role1"}, want: ""},
		{name: "blank type", lines: []string{", alice, data1"}, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := InferPType(tt.lines); got != tt.want {
				t.Fatalf("InferPType() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPolicyValueIndexFiltering(t *testing.T) {
	lines := []string{
		"p, alice, ops, /v1/users, GET",
		"p, bob, ops, /v1/users, GET",
		"g, alice, role:admin, ops",
	}

	if !MatchPolicyValuesByIndex(lines[0], 0, "alice") {
		t.Fatal("expected V0 match")
	}
	if MatchPolicyValuesByIndex(lines[0], 0, "p") {
		t.Fatal("fieldIndex=0 must match V0, not PType")
	}
	if !MatchPolicyValuesByIndex(lines[0], 1, "ops", "/v1/users") {
		t.Fatal("expected consecutive values match")
	}
	if MatchPolicyValuesByIndex(lines[0], 4, "extra") {
		t.Fatal("out of range match should fail")
	}

	got := FilterPoliciesByValueIndex(lines, "g", 0, "alice")
	want := []string{"g, alice, role:admin, ops"}
	if !equalStrings(got, want) {
		t.Fatalf("FilterPoliciesByValueIndex() = %v, want %v", got, want)
	}

	got = FilterPoliciesByPType(lines, "p")
	want = []string{
		"p, alice, ops, /v1/users, GET",
		"p, bob, ops, /v1/users, GET",
	}
	if !equalStrings(got, want) {
		t.Fatalf("FilterPoliciesByPType() = %v, want %v", got, want)
	}
}

func TestMatchPolicyValuesByIndex_EmptyFieldValues(t *testing.T) {
	// 空 fieldValues → 直接返回 true
	if !MatchPolicyValuesByIndex("p, alice, data1, read", 0) {
		t.Fatal("expected true for empty fieldValues")
	}
}

func TestFilterPoliciesByValueIndex_EmptyAll(t *testing.T) {
	lines := []string{
		"p, alice, data1, read",
		"p, bob, data2, write",
	}
	// fieldValues 为空且 ptype 为空 → 返回原始列表的副本
	got := FilterPoliciesByValueIndex(lines, "", 0)
	if !equalStrings(got, lines) {
		t.Fatalf("FilterPoliciesByValueIndex() = %v, want %v", got, lines)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
