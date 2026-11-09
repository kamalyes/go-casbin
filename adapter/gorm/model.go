/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\adapter\gorm\model.go
 * @Description: 策略表模型与规则互转
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package gorm

// ruleColumns 策略值列数，对应 casbin 规则最多 6 个字段
const ruleColumns = 6

// CasbinRule 策略表行模型
//
// 这里刻意不写 gorm 的 index tag：tag 里的索引名是固定字符串，
// 而索引名在 SQLite / PostgreSQL 里是库级唯一的，按表分片时
// 第二张表建同名索引会直接失败。索引改由 schema.go 按表名动态生成。
type CasbinRule struct {
	ID    uint   `gorm:"primaryKey;autoIncrement"`
	PType string `gorm:"column:ptype;size:100"`
	V0    string `gorm:"column:v0;size:100"`
	V1    string `gorm:"column:v1;size:100"`
	V2    string `gorm:"column:v2;size:100"`
	V3    string `gorm:"column:v3;size:100"`
	V4    string `gorm:"column:v4;size:100"`
	V5    string `gorm:"column:v5;size:100"`
}

// TableName 默认表名，实际表名由适配器的 WithTableName 决定
func (CasbinRule) TableName() string { return DefaultTableName }

// ruleValueColumns 策略值列名，顺序与 CasbinRule 的 V0..V5 一致
var ruleValueColumns = [ruleColumns]string{"v0", "v1", "v2", "v3", "v4", "v5"}

// newRow 把一条 casbin 规则转成表行
// 超出 6 个字段的部分会被丢弃，与官方表结构的容量一致
func newRow(ptype string, rule []string) CasbinRule {
	row := CasbinRule{PType: ptype}

	values := [...]*string{&row.V0, &row.V1, &row.V2, &row.V3, &row.V4, &row.V5}
	for i := 0; i < len(rule) && i < ruleColumns; i++ {
		*values[i] = rule[i]
	}

	return row
}

// rule 把表行还原成 casbin 规则
// 尾部连续的空值会被裁掉：规则字段数由模型决定，补空会让 LoadPolicyArray 报长度不符
func (r *CasbinRule) rule() []string {
	values := [ruleColumns]string{r.V0, r.V1, r.V2, r.V3, r.V4, r.V5}

	end := ruleColumns
	for end > 0 && values[end-1] == "" {
		end--
	}

	return values[:end]
}

// policyArray 返回 persist.LoadPolicyArray 需要的「ptype + 规则」形式
func (r *CasbinRule) policyArray() []string {
	rule := r.rule()

	row := make([]string, 0, len(rule)+1)
	row = append(row, r.PType)
	row = append(row, rule...)

	return row
}
