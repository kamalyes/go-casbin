/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\adapter\redis\adapter.go
 * @Description: 基于 Redis 的策略存储适配器
 *
 * 实现官方 persist.Adapter / BatchAdapter / UpdatableAdapter / FilteredAdapter
 * 及其 Context 变体，可直接传给官方 casbin 或 go-casbin 的 WithAdapter。
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package redis

import (
	"context"
	"errors"

	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
	"github.com/kamalyes/go-casbin/adapter/base"
	"github.com/redis/go-redis/v9"
)

// ErrNoClient 未提供 Redis 客户端
var ErrNoClient = errors.New("go-casbin/redis: a redis client is required")

// Adapter Redis 策略存储适配器
type Adapter struct {
	client redis.UniversalClient
	keys   keyBuilder
	log    Logger

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

// NewAdapter 用已有客户端创建适配器
//
//	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:6379"})
//	a, err := redis.NewAdapter(client, redis.WithKeyPrefix("casbin:tenant-a"))
//	e, err := casbin.NewEnforcer(casbin.WithModelPath(...), casbin.WithAdapter(a))
//
// 多租户按前缀隔离：每个租户一个前缀，决策集合从全平台缩到单租户。
func NewAdapter(client redis.UniversalClient, opts ...Option) (*Adapter, error) {
	if client == nil {
		return nil, ErrNoClient
	}

	a := &Adapter{
		client: client,
		keys:   newKeyBuilder(""),
		log:    base.NopLogger{},
	}
	for _, opt := range opts {
		opt(a)
	}

	return a, nil
}

// ==================== persist.Adapter ====================

// LoadPolicy 加载全部策略
func (a *Adapter) LoadPolicy(m model.Model) error {
	return a.LoadPolicyCtx(context.Background(), m)
}

// LoadPolicyCtx 加载全部策略
func (a *Adapter) LoadPolicyCtx(ctx context.Context, m model.Model) error {
	ptypes, err := a.client.SMembers(ctx, a.keys.ptypesKey()).Result()
	if err != nil {
		return err
	}

	for _, ptype := range ptypes {
		if err := a.loadPType(ctx, m, ptype, nil); err != nil {
			return err
		}
	}
	a.filtered = false

	return nil
}

// SavePolicy 全量覆盖存储中的策略
func (a *Adapter) SavePolicy(m model.Model) error {
	return a.SavePolicyCtx(context.Background(), m)
}

// SavePolicyCtx 全量覆盖存储中的策略
func (a *Adapter) SavePolicyCtx(ctx context.Context, m model.Model) error {
	// 先收集再写入：避免清空后写入失败导致策略全丢
	payload := map[string][]interface{}{}
	for _, sec := range []string{"p", "g"} {
		for ptype, ast := range m[sec] {
			for _, rule := range ast.Policy {
				member, err := encodeRule(rule)
				if err != nil {
					return err
				}
				payload[ptype] = append(payload[ptype], member)
			}
		}
	}

	stale, err := a.client.SMembers(ctx, a.keys.ptypesKey()).Result()
	if err != nil {
		return err
	}

	pipe := a.client.TxPipeline()
	for _, ptype := range stale {
		pipe.Del(ctx, a.keys.rulesKey(ptype))
	}
	pipe.Del(ctx, a.keys.ptypesKey())

	for ptype, members := range payload {
		pipe.SAdd(ctx, a.keys.rulesKey(ptype), members...)
		pipe.SAdd(ctx, a.keys.ptypesKey(), ptype)
	}

	_, err = pipe.Exec(ctx)

	return err
}

// AddPolicy 新增一条策略
func (a *Adapter) AddPolicy(sec string, ptype string, rule []string) error {
	return a.AddPolicyCtx(context.Background(), sec, ptype, rule)
}

// AddPolicyCtx 新增一条策略
func (a *Adapter) AddPolicyCtx(ctx context.Context, sec string, ptype string, rule []string) error {
	return a.AddPoliciesCtx(ctx, sec, ptype, [][]string{rule})
}

// RemovePolicy 删除一条策略
func (a *Adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	return a.RemovePolicyCtx(context.Background(), sec, ptype, rule)
}

// RemovePolicyCtx 删除一条策略
func (a *Adapter) RemovePolicyCtx(ctx context.Context, sec string, ptype string, rule []string) error {
	return a.RemovePoliciesCtx(ctx, sec, ptype, [][]string{rule})
}

// RemoveFilteredPolicy 按字段过滤删除策略
func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	return a.RemoveFilteredPolicyCtx(context.Background(), sec, ptype, fieldIndex, fieldValues...)
}

// RemoveFilteredPolicyCtx 按字段过滤删除策略
func (a *Adapter) RemoveFilteredPolicyCtx(ctx context.Context, sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	_, err := a.removeFiltered(ctx, ptype, fieldIndex, fieldValues)
	return err
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

	members, err := encodeRules(rules)
	if err != nil {
		return err
	}

	pipe := a.client.TxPipeline()
	pipe.SAdd(ctx, a.keys.rulesKey(ptype), members...)
	pipe.SAdd(ctx, a.keys.ptypesKey(), ptype)
	_, err = pipe.Exec(ctx)

	return err
}

// RemovePolicies 批量删除策略
func (a *Adapter) RemovePolicies(sec string, ptype string, rules [][]string) error {
	return a.RemovePoliciesCtx(context.Background(), sec, ptype, rules)
}

// RemovePoliciesCtx 批量删除策略
func (a *Adapter) RemovePoliciesCtx(ctx context.Context, sec string, ptype string, rules [][]string) error {
	if len(rules) == 0 {
		return nil
	}

	members, err := encodeRules(rules)
	if err != nil {
		return err
	}

	return a.client.SRem(ctx, a.keys.rulesKey(ptype), members...).Err()
}

// ==================== persist.UpdatableAdapter ====================

// UpdatePolicy 原地替换一条策略
func (a *Adapter) UpdatePolicy(sec string, ptype string, oldRule, newRule []string) error {
	return a.UpdatePolicyCtx(context.Background(), sec, ptype, oldRule, newRule)
}

// UpdatePolicyCtx 原地替换一条策略
func (a *Adapter) UpdatePolicyCtx(ctx context.Context, sec string, ptype string, oldRule, newRule []string) error {
	return a.UpdatePoliciesCtx(ctx, sec, ptype, [][]string{oldRule}, [][]string{newRule})
}

// UpdatePolicies 原地替换多条策略
func (a *Adapter) UpdatePolicies(sec string, ptype string, oldRules, newRules [][]string) error {
	return a.UpdatePoliciesCtx(context.Background(), sec, ptype, oldRules, newRules)
}

// UpdatePoliciesCtx 原地替换多条策略
// 删除与写入在同一个事务里提交，避免中途失败留下「旧的已删、新的没写」的空档
func (a *Adapter) UpdatePoliciesCtx(ctx context.Context, sec string, ptype string, oldRules, newRules [][]string) error {
	oldMembers, err := encodeRules(oldRules)
	if err != nil {
		return err
	}
	newMembers, err := encodeRules(newRules)
	if err != nil {
		return err
	}

	pipe := a.client.TxPipeline()
	if len(oldMembers) > 0 {
		pipe.SRem(ctx, a.keys.rulesKey(ptype), oldMembers...)
	}
	if len(newMembers) > 0 {
		pipe.SAdd(ctx, a.keys.rulesKey(ptype), newMembers...)
		pipe.SAdd(ctx, a.keys.ptypesKey(), ptype)
	}
	_, err = pipe.Exec(ctx)

	return err
}

// UpdateFilteredPolicies 删除命中过滤的策略并写入新策略，返回被删除的旧策略
func (a *Adapter) UpdateFilteredPolicies(sec string, ptype string, newRules [][]string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	return a.UpdateFilteredPoliciesCtx(context.Background(), sec, ptype, newRules, fieldIndex, fieldValues...)
}

// UpdateFilteredPoliciesCtx 删除命中过滤的策略并写入新策略，返回被删除的旧策略
func (a *Adapter) UpdateFilteredPoliciesCtx(ctx context.Context, sec string, ptype string, newRules [][]string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	removed, err := a.removeFiltered(ctx, ptype, fieldIndex, fieldValues)
	if err != nil {
		return nil, err
	}

	if err := a.AddPoliciesCtx(ctx, sec, ptype, newRules); err != nil {
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
// filter 支持 *Filter / Filter（与官方 file-adapter 的 Filter 结构同形），
// 传 nil 等价于全量加载。
func (a *Adapter) LoadFilteredPolicyCtx(ctx context.Context, m model.Model, filter interface{}) error {
	if filter == nil {
		return a.LoadPolicyCtx(ctx, m)
	}

	f, err := base.ToFilter(filter)
	if err != nil {
		return err
	}
	byPType := base.FilterByPType(f)

	ptypes, err := a.client.SMembers(ctx, a.keys.ptypesKey()).Result()
	if err != nil {
		return err
	}

	for _, ptype := range ptypes {
		if err := a.loadPType(ctx, m, ptype, byPType[ptype]); err != nil {
			return err
		}
	}
	a.filtered = true

	return nil
}

// IsFiltered 返回当前加载的策略是否经过过滤
func (a *Adapter) IsFiltered() bool { return a.filtered }

// IsFilteredCtx 返回当前加载的策略是否经过过滤
func (a *Adapter) IsFilteredCtx(context.Context) bool { return a.filtered }

// ==================== 内部实现 ====================

// loadPType 加载某个策略类型，values 非空时按位过滤
func (a *Adapter) loadPType(ctx context.Context, m model.Model, ptype string, values []string) error {
	members, err := a.client.SMembers(ctx, a.keys.rulesKey(ptype)).Result()
	if err != nil {
		return err
	}

	for _, member := range members {
		rule, err := decodeRule(member)
		if err != nil {
			a.log.WarnContextKV(ctx, "casbin redis skipped a malformed rule",
				"ptype", ptype, "member", member, "error", err.Error())
			continue
		}
		if len(values) > 0 && !base.MatchesFilter(rule, 0, values) {
			continue
		}

		row := make([]string, 0, len(rule)+1)
		row = append(row, ptype)
		row = append(row, rule...)
		if err := persist.LoadPolicyArray(row, m); err != nil {
			return err
		}
	}

	return nil
}

// removeFiltered 删除命中过滤的策略，返回被删除的规则
func (a *Adapter) removeFiltered(ctx context.Context, ptype string, fieldIndex int, fieldValues []string) ([][]string, error) {
	members, err := a.client.SMembers(ctx, a.keys.rulesKey(ptype)).Result()
	if err != nil {
		return nil, err
	}

	var (
		removed  [][]string
		doomed   []interface{}
		hasMatch bool
	)
	for _, member := range members {
		rule, err := decodeRule(member)
		if err != nil {
			continue
		}
		if !base.MatchesFilter(rule, fieldIndex, fieldValues) {
			continue
		}

		removed = append(removed, rule)
		doomed = append(doomed, member)
		hasMatch = true
	}

	if !hasMatch {
		return nil, nil
	}

	if err := a.client.SRem(ctx, a.keys.rulesKey(ptype), doomed...).Err(); err != nil {
		return nil, err
	}

	return removed, nil
}

// encodeRules 批量编码
func encodeRules(rules [][]string) ([]interface{}, error) {
	members := make([]interface{}, 0, len(rules))
	for _, rule := range rules {
		member, err := encodeRule(rule)
		if err != nil {
			return nil, err
		}
		members = append(members, member)
	}

	return members, nil
}
