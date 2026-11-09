/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\adapter\base\event.go
 * @Description: 策略变更事件定义与编解码
 *
 * 各通知器（Kafka / NATS / Redis）共用同一套事件格式，
 * 因此混用不同中间件的集群之间事件也能互相理解。
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package base

import (
	"encoding/json"

	"github.com/casbin/casbin/v3/model"
)

// Operation 策略变更类型
type Operation string

const (
	OpUpdate               Operation = "update"                 // 通用变更，接收方全量重载
	OpAddPolicy            Operation = "add_policy"             // 新增单条
	OpAddPolicies          Operation = "add_policies"           // 新增多条
	OpRemovePolicy         Operation = "remove_policy"          // 删除单条
	OpRemovePolicies       Operation = "remove_policies"        // 删除多条
	OpRemoveFilteredPolicy Operation = "remove_filtered_policy" // 按字段过滤删除
	OpSavePolicy           Operation = "save_policy"            // 全量覆盖
)

// Event 一次策略变更事件
// Source 用于过滤自环：发出事件的节点收到自己的消息时直接丢弃
type Event struct {
	ID          string     `json:"id"`
	Source      string     `json:"source"`
	Op          Operation  `json:"op"`
	Sec         string     `json:"sec,omitempty"`
	PType       string     `json:"ptype,omitempty"`
	Rules       [][]string `json:"rules,omitempty"`
	RuleCount   int        `json:"rule_count,omitempty"`
	FieldIndex  int        `json:"field_index,omitempty"`
	FieldValues []string   `json:"field_values,omitempty"`
	TimestampMs int64      `json:"ts"`
}

// Marshal 序列化事件
func (e *Event) Marshal() ([]byte, error) { return json.Marshal(e) }

// UnmarshalEvent 反序列化事件
func UnmarshalEvent(data []byte) (*Event, error) {
	var e Event
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, err
	}
	return &e, nil
}

// CountPolicies 统计模型里的策略条数（p 段与 g 段之和）
func CountPolicies(m model.Model) int {
	var total int
	for _, sec := range []string{"p", "g"} {
		for _, ast := range m[sec] {
			total += len(ast.Policy)
		}
	}

	return total
}

// SnapshotPolicies 把模型里的策略摊平成可广播的规则集，每行首列是 ptype
//
// 注意消息大小：实测 1 万条策略编码后约 340 KB，5 万条约 1.7 MB，
// 而 Kafka 的 message.max.bytes 与 NATS 的 max_payload 默认都是 1 MB，
// 超过就会被 broker 直接拒收。因此 UpdateForSavePolicy 不带快照，
// 只发信号让接收方回源全量重载。要自带快照的传输层请自行评估上限。
func SnapshotPolicies(m model.Model) [][]string {
	var rules [][]string

	for _, sec := range []string{"p", "g"} {
		for ptype, ast := range m[sec] {
			for _, rule := range ast.Policy {
				row := make([]string, 0, len(rule)+1)
				row = append(row, ptype)
				row = append(row, rule...)
				rules = append(rules, row)
			}
		}
	}

	return rules
}
