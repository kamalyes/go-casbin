/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\adapter\base\filter.go
 * @Description: 过滤加载条件的归一化与匹配
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package base

import (
	"errors"
	"fmt"

	fileadapter "github.com/casbin/casbin/v3/persist/file-adapter"
)

var (
	// ErrUnsupportedFilter 过滤条件类型不支持
	ErrUnsupportedFilter = errors.New("go-casbin/adapter: unsupported filter type")
	// ErrNoTransport 通知器没有配置传输函数
	ErrNoTransport = errors.New("go-casbin/adapter: notifier has no transport")
)

// Filter 过滤加载条件，字段与官方 file-adapter 的 Filter 同形
//
// 每个字段是一个按位对齐的值列表：P[0] 约束 v0、P[1] 约束 v1，空串表示该位不限制
type Filter = fileadapter.Filter

// ToFilter 归一化调用方传入的过滤条件
// 支持 Filter / *Filter，nil 指针视为空过滤
func ToFilter(filter interface{}) (Filter, error) {
	switch v := filter.(type) {
	case Filter:
		return v, nil
	case *Filter:
		if v == nil {
			return Filter{}, nil
		}
		return *v, nil
	default:
		return Filter{}, fmt.Errorf("%w: %T", ErrUnsupportedFilter, filter)
	}
}

// FilterByPType 把 Filter 摊成「策略类型 -> 按位约束」的映射
// 只返回非空的分支，便于调用方按需拼查询
func FilterByPType(f Filter) map[string][]string {
	all := map[string][]string{
		"p": f.P, "g": f.G, "g1": f.G1, "g2": f.G2,
		"g3": f.G3, "g4": f.G4, "g5": f.G5,
	}

	out := make(map[string][]string, len(all))
	for ptype, values := range all {
		if len(values) > 0 {
			out[ptype] = values
		}
	}

	return out
}

// MatchesFilter 判断规则是否命中 fieldIndex 起始的字段过滤
// 空字符串表示该位置不做限制，与官方 RemoveFilteredPolicy 的语义一致
func MatchesFilter(rule []string, fieldIndex int, fieldValues []string) bool {
	for i, value := range fieldValues {
		if value == "" {
			continue
		}
		pos := fieldIndex + i
		if pos >= len(rule) || rule[pos] != value {
			return false
		}
	}

	return true
}
