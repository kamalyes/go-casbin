/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\adapter\gorm\model_test.go
 * @Description: 规则与表行互转测试
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package gorm

import (
	"errors"
	"testing"
)

func TestRuleTrimsTrailingEmptyColumns(t *testing.T) {
	full := newRow("p", []string{"alice", "data1", "read"})
	if got := full.rule(); len(got) != 3 {
		t.Fatalf("rule() = %v; want 3 fields", got)
	}

	// 中间的空值必须保留，只裁尾部
	middle := newRow("p", []string{"alice", "", "read"})
	if got := middle.rule(); len(got) != 3 || got[1] != "" {
		t.Fatalf("rule() = %v; want the middle blank preserved", got)
	}

	// 全空的规则裁成空切片
	blank := newRow("p", nil)
	if got := blank.rule(); len(got) != 0 {
		t.Fatalf("rule() = %v; want empty", got)
	}
}

func TestNewRowDropsOverflowFields(t *testing.T) {
	row := newRow("p", []string{"1", "2", "3", "4", "5", "6", "7"})

	if got := row.rule(); len(got) != ruleColumns {
		t.Fatalf("len = %d; want %d", len(got), ruleColumns)
	}
	if row.V5 != "6" {
		t.Fatalf("V5 = %q; want 6", row.V5)
	}
}

func TestPolicyArrayPrependsPType(t *testing.T) {
	row := newRow("g2", []string{"alice", "admin"})

	got := row.policyArray()
	if len(got) != 3 || got[0] != "g2" {
		t.Fatalf("policyArray = %v; want ptype first", got)
	}
}

func TestTableNameDefault(t *testing.T) {
	if got := (CasbinRule{}).TableName(); got != DefaultTableName {
		t.Fatalf("TableName = %q; want %q", got, DefaultTableName)
	}
}

func TestRuleConditionsPinsUnusedColumnsToEmpty(t *testing.T) {
	// 未提供的列必须显式匹配空串，否则会误删「前缀相同但字段更多」的规则
	got := ruleConditions("p", []string{"alice", "data1"})

	if got["ptype"] != "p" || got["v0"] != "alice" || got["v1"] != "data1" {
		t.Fatalf("conditions = %v", got)
	}
	for _, column := range []string{"v2", "v3", "v4", "v5"} {
		if got[column] != "" {
			t.Fatalf("%s = %v; want an explicit empty string", column, got[column])
		}
	}
}

func TestFilterConditionsSkipsBlanks(t *testing.T) {
	got, err := filterConditions("p", 0, []string{"alice", "", "read"})
	if err != nil {
		t.Fatalf("filterConditions: %v", err)
	}

	if got["v0"] != "alice" || got["v2"] != "read" {
		t.Fatalf("conditions = %v", got)
	}
	if _, pinned := got["v1"]; pinned {
		t.Fatal("a blank filter value must not constrain the column")
	}
}

func TestFilterConditionsRejectsOutOfRange(t *testing.T) {
	if _, err := filterConditions("p", 5, []string{"a", "b"}); !errors.Is(err, ErrFieldIndexOutOfRange) {
		t.Fatalf("err = %v; want ErrFieldIndexOutOfRange", err)
	}
	if _, err := filterConditions("p", -1, []string{"a"}); !errors.Is(err, ErrFieldIndexOutOfRange) {
		t.Fatalf("err = %v; want ErrFieldIndexOutOfRange for a negative index", err)
	}
}

func TestUpdateColumnsClearsMissingFields(t *testing.T) {
	// 用显式映射而非结构体：结构体更新会忽略零值
	row := newRow("p", []string{"alice", "data1"})

	got := updateColumns(&row)
	if got["v0"] != "alice" || got["v1"] != "data1" {
		t.Fatalf("columns = %v", got)
	}
	for _, column := range []string{"v2", "v3", "v4", "v5"} {
		if got[column] != "" {
			t.Fatalf("%s = %v; want an explicit empty string", column, got[column])
		}
	}
}
