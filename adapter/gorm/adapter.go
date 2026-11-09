/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\adapter\gorm\adapter.go
 * @Description: 基于 GORM 的策略存储适配器
 *
 * 实现官方 persist.Adapter / BatchAdapter / UpdatableAdapter / FilteredAdapter
 * 及其 Context 变体。支持按表隔离的多租户分片：每个租户一张独立策略表，
 * 决策集合从「全平台」缩到「单租户」。
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package gorm

import (
	"context"
	"errors"

	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
	"github.com/kamalyes/go-casbin/adapter/base"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// DefaultTableName 默认策略表名
const DefaultTableName = "casbin_rule"

// ErrNoDB 未提供 gorm 实例
var ErrNoDB = errors.New("go-casbin/gorm: a *gorm.DB is required")

// Adapter GORM 策略存储适配器
type Adapter struct {
	db        *gorm.DB
	tableName string
	log       Logger

	filtered bool
}

// 编译期确认实现了官方接口
var (
	_ persist.Adapter                 = (*Adapter)(nil)
	_ persist.BatchAdapter            = (*Adapter)(nil)
	_ persist.UpdatableAdapter        = (*Adapter)(nil)
	_ persist.FilteredAdapter         = (*Adapter)(nil)
	_ persist.ContextAdapter          = (*Adapter)(nil)
	_ persist.ContextBatchAdapter     = (*Adapter)(nil)
	_ persist.ContextUpdatableAdapter = (*Adapter)(nil)
	_ persist.ContextFilteredAdapter  = (*Adapter)(nil)
)

// NewAdapter 用已有 gorm 实例创建适配器
//
//	a, err := gormadapter.NewAdapter(db, gormadapter.WithTableName("casbin_rule_tenant_a"))
//	e, err := casbin.NewEnforcer(casbin.WithModelPath(...), casbin.WithAdapter(a))
//
// 默认建表；不希望适配器碰 DDL 时用 WithAutoMigrate(false)。
func NewAdapter(db *gorm.DB, opts ...Option) (*Adapter, error) {
	if db == nil {
		return nil, ErrNoDB
	}

	a := &Adapter{
		db:        db,
		tableName: DefaultTableName,
		log:       base.NopLogger{},
	}
	autoMigrate := true
	for _, opt := range opts {
		opt(a, &autoMigrate)
	}

	if autoMigrate {
		if err := EnsureTable(context.Background(), a.db, a.tableName); err != nil {
			return nil, err
		}
	}

	return a, nil
}

// TableName 返回本适配器使用的表名
func (a *Adapter) TableName() string { return a.tableName }

// DB 返回底层 gorm 实例
func (a *Adapter) DB() *gorm.DB { return a.db }

// scope 返回绑定了表名与上下文的查询会话
func (a *Adapter) scope(ctx context.Context) *gorm.DB {
	return a.db.WithContext(ctx).Table(a.tableName)
}

// ==================== persist.Adapter ====================

// LoadPolicy 加载全部策略
func (a *Adapter) LoadPolicy(m model.Model) error {
	return a.LoadPolicyCtx(context.Background(), m)
}

// LoadPolicyCtx 加载全部策略
func (a *Adapter) LoadPolicyCtx(ctx context.Context, m model.Model) error {
	if err := a.load(ctx, m, a.scope(ctx)); err != nil {
		return err
	}
	a.filtered = false

	return nil
}

// SavePolicy 全量覆盖存储中的策略
func (a *Adapter) SavePolicy(m model.Model) error {
	return a.SavePolicyCtx(context.Background(), m)
}

// SavePolicyCtx 全量覆盖存储中的策略
// 清空与写入在同一事务里完成，中途失败会整体回滚，不会留下空表
func (a *Adapter) SavePolicyCtx(ctx context.Context, m model.Model) error {
	rows := make([]CasbinRule, 0, 64)
	for _, sec := range []string{"p", "g"} {
		for ptype, ast := range m[sec] {
			for _, rule := range ast.Policy {
				rows = append(rows, newRow(ptype, rule))
			}
		}
	}

	return a.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Table(a.tableName).Where("1 = 1").Delete(&CasbinRule{}).Error; err != nil {
			return err
		}
		if len(rows) == 0 {
			return nil
		}
		return tx.Table(a.tableName).CreateInBatches(rows, defaultBatchSize).Error
	})
}

// AddPolicy 新增一条策略
func (a *Adapter) AddPolicy(sec string, ptype string, rule []string) error {
	return a.AddPolicyCtx(context.Background(), sec, ptype, rule)
}

// AddPolicyCtx 新增一条策略
func (a *Adapter) AddPolicyCtx(ctx context.Context, sec string, ptype string, rule []string) error {
	row := newRow(ptype, rule)
	return a.scope(ctx).Create(&row).Error
}

// RemovePolicy 删除一条策略
func (a *Adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	return a.RemovePolicyCtx(context.Background(), sec, ptype, rule)
}

// RemovePolicyCtx 删除一条策略
func (a *Adapter) RemovePolicyCtx(ctx context.Context, sec string, ptype string, rule []string) error {
	return a.scope(ctx).Where(ruleConditions(ptype, rule)).Delete(&CasbinRule{}).Error
}

// RemoveFilteredPolicy 按字段过滤删除策略
func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	return a.RemoveFilteredPolicyCtx(context.Background(), sec, ptype, fieldIndex, fieldValues...)
}

// RemoveFilteredPolicyCtx 按字段过滤删除策略
func (a *Adapter) RemoveFilteredPolicyCtx(ctx context.Context, sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	conditions, err := filterConditions(ptype, fieldIndex, fieldValues)
	if err != nil {
		return err
	}

	return a.scope(ctx).Where(conditions).Delete(&CasbinRule{}).Error
}

// ==================== persist.BatchAdapter ====================

// AddPolicies 批量新增策略
func (a *Adapter) AddPolicies(sec string, ptype string, rules [][]string) error {
	return a.AddPoliciesCtx(context.Background(), sec, ptype, rules)
}

// AddPoliciesCtx 批量新增策略
func (a *Adapter) AddPoliciesCtx(ctx context.Context, sec string, ptype string, rules [][]string) error {
	if len(rules) == 0 {
		return nil
	}

	rows := make([]CasbinRule, 0, len(rules))
	for _, rule := range rules {
		rows = append(rows, newRow(ptype, rule))
	}

	return a.scope(ctx).CreateInBatches(rows, defaultBatchSize).Error
}

// RemovePolicies 批量删除策略
func (a *Adapter) RemovePolicies(sec string, ptype string, rules [][]string) error {
	return a.RemovePoliciesCtx(context.Background(), sec, ptype, rules)
}

// RemovePoliciesCtx 批量删除策略
// 逐条删除但共用一个事务：部分失败时整体回滚，避免删一半的中间态
func (a *Adapter) RemovePoliciesCtx(ctx context.Context, sec string, ptype string, rules [][]string) error {
	if len(rules) == 0 {
		return nil
	}

	return a.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, rule := range rules {
			if err := tx.Table(a.tableName).Where(ruleConditions(ptype, rule)).Delete(&CasbinRule{}).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// ==================== persist.UpdatableAdapter ====================

// UpdatePolicy 原地替换一条策略
func (a *Adapter) UpdatePolicy(sec string, ptype string, oldRule, newRule []string) error {
	return a.UpdatePolicyCtx(context.Background(), sec, ptype, oldRule, newRule)
}

// UpdatePolicyCtx 原地替换一条策略
func (a *Adapter) UpdatePolicyCtx(ctx context.Context, sec string, ptype string, oldRule, newRule []string) error {
	row := newRow(ptype, newRule)

	return a.scope(ctx).Where(ruleConditions(ptype, oldRule)).Updates(updateColumns(&row)).Error
}

// UpdatePolicies 原地替换多条策略
func (a *Adapter) UpdatePolicies(sec string, ptype string, oldRules, newRules [][]string) error {
	return a.UpdatePoliciesCtx(context.Background(), sec, ptype, oldRules, newRules)
}

// UpdatePoliciesCtx 原地替换多条策略
func (a *Adapter) UpdatePoliciesCtx(ctx context.Context, sec string, ptype string, oldRules, newRules [][]string) error {
	if len(oldRules) != len(newRules) {
		return ErrRuleCountMismatch
	}

	return a.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for i := range oldRules {
			row := newRow(ptype, newRules[i])
			if err := tx.Table(a.tableName).Where(ruleConditions(ptype, oldRules[i])).Updates(updateColumns(&row)).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// UpdateFilteredPolicies 删除命中过滤的策略并写入新策略，返回被删除的旧策略
func (a *Adapter) UpdateFilteredPolicies(sec string, ptype string, newRules [][]string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	return a.UpdateFilteredPoliciesCtx(context.Background(), sec, ptype, newRules, fieldIndex, fieldValues...)
}

// UpdateFilteredPoliciesCtx 删除命中过滤的策略并写入新策略，返回被删除的旧策略
func (a *Adapter) UpdateFilteredPoliciesCtx(ctx context.Context, sec string, ptype string, newRules [][]string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	conditions, err := filterConditions(ptype, fieldIndex, fieldValues)
	if err != nil {
		return nil, err
	}

	rows := make([]CasbinRule, 0, len(newRules))
	for _, rule := range newRules {
		rows = append(rows, newRow(ptype, rule))
	}

	var removed [][]string
	err = a.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var doomed []CasbinRule
		if err := tx.Table(a.tableName).Where(conditions).Find(&doomed).Error; err != nil {
			return err
		}
		for i := range doomed {
			removed = append(removed, doomed[i].rule())
		}

		if err := tx.Table(a.tableName).Where(conditions).Delete(&CasbinRule{}).Error; err != nil {
			return err
		}
		if len(rows) == 0 {
			return nil
		}
		return tx.Table(a.tableName).CreateInBatches(rows, defaultBatchSize).Error
	})
	if err != nil {
		return nil, err
	}

	return removed, nil
}

// ==================== persist.FilteredAdapter ====================

// LoadFilteredPolicy 按过滤条件加载策略
func (a *Adapter) LoadFilteredPolicy(m model.Model, filter interface{}) error {
	return a.LoadFilteredPolicyCtx(context.Background(), m, filter)
}

// LoadFilteredPolicyCtx 按过滤条件加载策略
//
// filter 支持 *Filter / Filter（与官方 file-adapter 的 Filter 同形），
// 过滤下推到 SQL，不会把整表拉回本地再筛；传 nil 等价于全量加载。
func (a *Adapter) LoadFilteredPolicyCtx(ctx context.Context, m model.Model, filter interface{}) error {
	if filter == nil {
		return a.LoadPolicyCtx(ctx, m)
	}

	query, err := filterQuery(a.scope(ctx), filter)
	if err != nil {
		return err
	}

	if err := a.load(ctx, m, query); err != nil {
		return err
	}
	a.filtered = true

	return nil
}

// IsFiltered 返回当前加载的策略是否经过过滤
func (a *Adapter) IsFiltered() bool { return a.filtered }

// IsFilteredCtx 返回当前加载的策略是否经过过滤
func (a *Adapter) IsFilteredCtx(context.Context) bool { return a.filtered }

// ==================== 内部实现 ====================

// load 按游标分批读取并灌入模型
// 用 FindInBatches 而不是一次 Find：大租户的策略表可能几十万行，
// 一次性读回来会让内存出现一个与表等大的尖峰
func (a *Adapter) load(ctx context.Context, m model.Model, query *gorm.DB) error {
	var batch []CasbinRule

	return query.Order(clause.OrderByColumn{Column: clause.Column{Name: "id"}}).
		FindInBatches(&batch, defaultBatchSize, func(tx *gorm.DB, _ int) error {
			for i := range batch {
				// 不跳过坏行：策略行被悄悄丢掉会直接改变决策结果
				// （带 deny 效果的模型里，丢一条 deny 就是一次错误放行），
				// 宁可让加载失败暴露出来，也不要带着残缺的策略集对外服务
				if err := persist.LoadPolicyArray(batch[i].policyArray(), m); err != nil {
					a.log.ErrorContextKV(ctx, "casbin gorm found an unloadable rule",
						"table", a.tableName, "id", batch[i].ID, "ptype", batch[i].PType)
					return err
				}
			}
			return nil
		}).Error
}

// ruleConditions 构造精确匹配一条规则的查询条件
func ruleConditions(ptype string, rule []string) map[string]interface{} {
	conditions := map[string]interface{}{"ptype": ptype}

	// 未提供的列必须显式匹配空串，否则会误删「前缀相同但字段更多」的规则
	for i, column := range ruleValueColumns {
		if i < len(rule) {
			conditions[column] = rule[i]
		} else {
			conditions[column] = ""
		}
	}

	return conditions
}

// filterConditions 构造按字段偏移过滤的查询条件
// 空字符串表示该位置不做限制，与官方 RemoveFilteredPolicy 的语义一致
func filterConditions(ptype string, fieldIndex int, fieldValues []string) (map[string]interface{}, error) {
	if fieldIndex < 0 || fieldIndex+len(fieldValues) > ruleColumns {
		return nil, ErrFieldIndexOutOfRange
	}

	conditions := map[string]interface{}{"ptype": ptype}
	for i, value := range fieldValues {
		if value == "" {
			continue
		}
		conditions[ruleValueColumns[fieldIndex+i]] = value
	}

	return conditions, nil
}

// updateColumns 构造 Updates 用的列值映射
// 用显式映射而非结构体：结构体更新会忽略零值，把字段改成空串的更新会被丢掉
func updateColumns(row *CasbinRule) map[string]interface{} {
	rule := row.rule()

	columns := map[string]interface{}{"ptype": row.PType}
	for i, column := range ruleValueColumns {
		if i < len(rule) {
			columns[column] = rule[i]
		} else {
			columns[column] = ""
		}
	}

	return columns
}
