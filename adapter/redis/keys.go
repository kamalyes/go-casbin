/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\adapter\redis\keys.go
 * @Description: 键名构造与规则编解码
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package redis

import "encoding/json"

// keyBuilder 按前缀构造各类键名
//
// 布局：
//
//	{prefix}:ptypes          SET，记录出现过哪些策略类型
//	{prefix}:rules:{ptype}   SET，该类型下的全部规则
//
// 按 ptype 分 SET 而不是全塞一个集合，是为了让过滤加载（多租户分片按需加载）
// 只读取相关类型，不必把全平台策略拉回本地再筛。
type keyBuilder struct {
	prefix string
}

func newKeyBuilder(prefix string) keyBuilder {
	if prefix == "" {
		prefix = "casbin"
	}
	return keyBuilder{prefix: prefix}
}

// ptypesKey 返回记录策略类型的集合键
func (k keyBuilder) ptypesKey() string { return k.prefix + ":ptypes" }

// rulesKey 返回某个策略类型的规则集合键
func (k keyBuilder) rulesKey(ptype string) string { return k.prefix + ":rules:" + ptype }

// encodeRule 把一条规则编码成集合成员
//
// 用 JSON 数组而非逗号拼接：规则字段里可能本身带逗号（如 ABAC 的
// eval 表达式 `r.sub == p.sub, x`），拼接会在解码时错位。
// []string 的 JSON 编码是确定性的，因此同一条规则编码结果唯一，
// SET 的天然去重正好对应策略不可重复的语义。
func encodeRule(rule []string) (string, error) {
	data, err := json.Marshal(rule)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// decodeRule 还原一条规则
func decodeRule(member string) ([]string, error) {
	var rule []string
	if err := json.Unmarshal([]byte(member), &rule); err != nil {
		return nil, err
	}
	return rule, nil
}
