/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\model\assertion.go
 * @Description: 断言定义（r/p/g/e/m 模型段）
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package model

import (
	"strings"

	"github.com/kamalyes/go-toolbox/pkg/stringx"
)

const (
	SectionRequestDefinition = "r"
	SectionPolicyDefinition  = "p"
	SectionRoleDefinition    = "g"
	SectionPolicyEffect      = "e"
	SectionMatchers          = "m"
)

type Assertion struct {
	Key       string
	Value     string
	Tokens    []string
	Policies  [][]string
	PolicyMap map[string]struct{} // 策略存在性索引（key 为逗号拼接的规则值），与行位置解耦，删除无需重建
}

func NewAssertion(key, value string) *Assertion {
	a := &Assertion{
		Key:       key,
		Value:     strings.TrimSpace(value),
		PolicyMap: make(map[string]struct{}),
	}
	a.buildTokens()
	return a
}

func (a *Assertion) buildTokens() {
	if a.Value == "" {
		a.Tokens = nil
		return
	}
	parts := strings.Split(a.Value, ",")
	a.Tokens = make([]string, 0, len(parts))
	for _, p := range parts {
		t := strings.TrimSpace(p)
		if t != "" {
			a.Tokens = append(a.Tokens, a.Key+"."+t)
		}
	}
}

// AddPolicy 添加策略规则
// 已存在相同规则时幂等跳过
func (a *Assertion) AddPolicy(policy []string) {
	key := strings.Join(policy, ",")
	if _, exists := a.PolicyMap[key]; exists {
		return
	}
	a.Policies = append(a.Policies, policy)
	a.PolicyMap[key] = struct{}{}
}

// RemovePolicy 删除策略规则
// 性能优化：索引与行位置解耦后，删除仅需移除 key + 尾部交换压缩，无需全量重建索引
// 注：swap-delete 不保持行顺序（策略匹配顺序无关，无语义影响）
func (a *Assertion) RemovePolicy(policy []string) bool {
	key := strings.Join(policy, ",")
	if _, exists := a.PolicyMap[key]; !exists {
		return false
	}
	for i, p := range a.Policies {
		if strings.Join(p, ",") == key {
			a.Policies[i] = a.Policies[len(a.Policies)-1]
			a.Policies = a.Policies[:len(a.Policies)-1]
			break
		}
	}
	delete(a.PolicyMap, key)
	return true
}

func (a *Assertion) HasPolicy(policy []string) bool {
	key := strings.Join(policy, ",")
	_, exists := a.PolicyMap[key]
	return exists
}

func (a *Assertion) ClearPolicies() {
	a.Policies = nil
	a.PolicyMap = make(map[string]struct{})
}

// RebuildPolicyMap 重建 PolicyMap（用于批量修改 Policies 后一次性重建索引）
// 导出方法：供 policy 层在全量重载后调用，替代逐条 AddPolicy 的 N 次 strings.Join
func (a *Assertion) RebuildPolicyMap() {
	if a.PolicyMap == nil {
		a.PolicyMap = make(map[string]struct{}, len(a.Policies))
	} else {
		for k := range a.PolicyMap {
			delete(a.PolicyMap, k)
		}
	}
	for _, p := range a.Policies {
		a.PolicyMap[strings.Join(p, ",")] = struct{}{}
	}
}

func (a *Assertion) BuildRoleLinkCondition(name1, name2 string) string {
	return stringx.New(name1).Value() + ":" + stringx.New(name2).Value()
}
