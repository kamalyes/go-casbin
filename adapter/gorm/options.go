/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\adapter\gorm\options.go
 * @Description: 配置、选项与过滤条件
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package gorm

import (
	"errors"

	"github.com/kamalyes/go-casbin/adapter/base"
	"gorm.io/gorm"
)

// defaultBatchSize 批量读写的分批大小
const defaultBatchSize = 500

var (
	// ErrUnsupportedFilter 过滤条件类型不支持
	ErrUnsupportedFilter = base.ErrUnsupportedFilter
	// ErrFieldIndexOutOfRange 字段偏移超出策略表的 6 列容量
	ErrFieldIndexOutOfRange = errors.New("go-casbin/gorm: field index out of range")
	// ErrRuleCountMismatch 新旧规则数量不一致
	ErrRuleCountMismatch = errors.New("go-casbin/gorm: old and new rule counts differ")
)

// 日志接口与过滤条件沿用公共骨架
type (
	// Logger 最小日志接口，与 go-logger 的 *Logger 签名一致，可直接传入
	Logger = base.Logger
	// Filter 过滤加载条件，字段与官方 file-adapter 的 Filter 同形
	Filter = base.Filter
)

// Option 可选配置
// autoMigrate 以指针传入，便于 WithAutoMigrate 在构造前改写建表行为
type Option func(a *Adapter, autoMigrate *bool)

// WithTableName 设置策略表名，默认 casbin_rule
// 多租户按表隔离：每个租户一张独立表，决策集合缩到单租户
func WithTableName(name string) Option {
	return func(a *Adapter, _ *bool) {
		if name != "" {
			a.tableName = name
		}
	}
}

// WithAutoMigrate 设置是否在创建适配器时自动建表并对齐索引，默认开启
// 由 DBA 统一管控 DDL 的环境请关闭
func WithAutoMigrate(enabled bool) Option {
	return func(_ *Adapter, autoMigrate *bool) { *autoMigrate = enabled }
}

// WithLogger 设置日志记录器
func WithLogger(l Logger) Option {
	return func(a *Adapter, _ *bool) {
		if l != nil {
			a.log = l
		}
	}
}

// filterQuery 把过滤条件下推成 SQL
//
// Filter 的每个字段是一个按位对齐的值列表：P[0] 约束 v0、P[1] 约束 v1，
// 空串表示该位不限制。官方 file-adapter 是把整表读回内存再筛，
// 这里下推到 WHERE，大租户不必为一次分片加载拉回全表。
func filterQuery(query *gorm.DB, filter interface{}) (*gorm.DB, error) {
	f, err := base.ToFilter(filter)
	if err != nil {
		return nil, err
	}

	// 每种策略类型一个 OR 分支，彼此独立；全部为空时退化为无约束
	var (
		clauses []*gorm.DB
		session = query.Session(&gorm.Session{NewDB: true})
	)
	for ptype, values := range base.FilterByPType(f) {
		conditions := map[string]interface{}{"ptype": ptype}
		for i, value := range values {
			if value == "" || i >= ruleColumns {
				continue
			}
			conditions[ruleValueColumns[i]] = value
		}
		clauses = append(clauses, session.Where(conditions))
	}

	if len(clauses) == 0 {
		return query, nil
	}

	combined := clauses[0]
	for _, c := range clauses[1:] {
		combined = combined.Or(c)
	}

	return query.Where(combined), nil
}
