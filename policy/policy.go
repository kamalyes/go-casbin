/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\policy\policy.go
 * @Description: 核心策略定义与操作（含批量、过滤、更新）
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package policy

import (
	"strings"

	"github.com/kamalyes/go-casbin/errors"
	"github.com/kamalyes/go-casbin/model"
	"github.com/kamalyes/go-logger"
)

// Policy 核心策略管理器
// 负责策略的加载、保存、增删改查操作
// 支持自动保存、缓存失效、适配器回退等机制
type Policy struct {
	model    *model.Model   // 关联的权限模型
	adapter  Adapter        // 策略存储适配器
	cache    *PolicyCache   // 策略缓存（基于 syncx.Map）
	logger   logger.ILogger // 日志记录器
	autoSave bool           // 是否自动持久化到适配器（默认 true）
}

// NewPolicy 创建策略管理器
func NewPolicy(m *model.Model, adapter Adapter, log logger.ILogger) *Policy {
	return &Policy{
		model:    m,
		adapter:  adapter,
		cache:    NewPolicyCache(),
		logger:   log,
		autoSave: true,
	}
}

// SetAutoSave 设置是否自动持久化到适配器
func (p *Policy) SetAutoSave(autoSave bool) {
	p.autoSave = autoSave
}

// IsAutoSave 返回是否自动持久化到适配器
func (p *Policy) IsAutoSave() bool {
	return p.autoSave
}

// LoadPolicy 从适配器加载所有策略到内存模型
// 加载前会清空现有策略，加载后使缓存全部失效
func (p *Policy) LoadPolicy() error {
	if p.adapter == nil {
		return errors.NewPolicyAdapterFailedError("adapter is nil")
	}

	policies, err := p.adapter.LoadPolicy()
	if err != nil {
		return errors.WrapError("LoadPolicy", err)
	}

	p.model.ClearPolicies()
	for _, line := range policies {
		p.addPolicyInternal(line)
	}

	p.cache.InvalidateAll()
	p.logger.InfoKV("Policy loaded", "count", len(policies))
	return nil
}

// LoadFilteredPolicy 按过滤条件从适配器加载策略
// 如果适配器不支持过滤接口，则回退到加载全部策略
func (p *Policy) LoadFilteredPolicy(filter interface{}) error {
	fa, ok := p.adapter.(FilteredAdapter)
	if !ok {
		return p.LoadPolicy()
	}

	policies, err := fa.LoadFilteredPolicy(filter)
	if err != nil {
		return errors.WrapError("LoadFilteredPolicy", err)
	}

	p.model.ClearPolicies()
	for _, line := range policies {
		p.addPolicyInternal(line)
	}

	p.cache.InvalidateAll()
	p.logger.InfoKV("Filtered policy loaded", "count", len(policies))
	return nil
}

// IsFiltered 返回适配器是否已使用过滤加载
func (p *Policy) IsFiltered() bool {
	fa, ok := p.adapter.(FilteredAdapter)
	if !ok {
		return false
	}
	return fa.IsFiltered()
}

// SavePolicy 将内存模型中的所有策略保存到适配器
func (p *Policy) SavePolicy() error {
	if p.adapter == nil {
		return errors.NewPolicyAdapterFailedError("adapter is nil")
	}

	policies := p.allPolicyLines()

	if err := p.adapter.SavePolicy(policies); err != nil {
		return errors.WrapError("SavePolicy", err)
	}

	p.logger.InfoKV("Policy saved", "count", len(policies))
	return nil
}

// AddPolicy 添加单条策略到内存模型和适配器
// 如果适配器写入失败，会回滚内存中的策略
func (p *Policy) AddPolicy(sec, ptype string, policy []string) error {
	assertion := p.model.GetAssertion(ptype)
	if assertion == nil {
		return errors.NewPolicyNotFoundError(ptype)
	}

	if assertion.HasPolicy(policy) {
		return errors.NewPolicyAlreadyExistsError(strings.Join(policy, ", "))
	}

	assertion.AddPolicy(policy)

	if p.autoSave && p.adapter != nil {
		line := ptype + ", " + strings.Join(policy, ", ")
		if err := p.adapter.AddPolicy(line); err != nil {
			assertion.RemovePolicy(policy)
			return errors.WrapError("AddPolicy", err)
		}
	}

	p.cache.Invalidate(ptype)
	p.logger.InfoKV("Policy added", "type", ptype, "policy", strings.Join(policy, ", "))
	return nil
}

// AddPolicies 批量添加策略，支持适配器回退和回滚
func (p *Policy) AddPolicies(sec, ptype string, rules [][]string) error {
	assertion := p.model.GetAssertion(ptype)
	if assertion == nil {
		return errors.NewPolicyNotFoundError(ptype)
	}

	var toAdd [][]string
	for _, rule := range rules {
		if !assertion.HasPolicy(rule) {
			toAdd = append(toAdd, rule)
		}
	}

	if len(toAdd) == 0 {
		return nil
	}

	for _, rule := range toAdd {
		assertion.AddPolicy(rule)
	}

	if p.autoSave && p.adapter != nil {
		if ba, ok := p.adapter.(BatchAdapter); ok {
			var lines []string
			for _, rule := range toAdd {
				lines = append(lines, ptype+", "+strings.Join(rule, ", "))
			}
			if err := ba.AddPolicies(lines); err != nil {
				for _, rule := range toAdd {
					assertion.RemovePolicy(rule)
				}
				return errors.WrapError("AddPolicies", err)
			}
		} else {
			for _, rule := range toAdd {
				line := ptype + ", " + strings.Join(rule, ", ")
				if err := p.adapter.AddPolicy(line); err != nil {
					for _, r := range toAdd {
						assertion.RemovePolicy(r)
					}
					return errors.WrapError("AddPolicies", err)
				}
			}
		}
	}

	p.cache.Invalidate(ptype)
	p.logger.InfoKV("Policies added", "type", ptype, "count", len(toAdd))
	return nil
}

// AddPoliciesEx 批量添加策略（忽略已存在的策略）
func (p *Policy) AddPoliciesEx(sec, ptype string, rules [][]string) error {
	assertion := p.model.GetAssertion(ptype)
	if assertion == nil {
		return errors.NewPolicyNotFoundError(ptype)
	}

	var toAdd [][]string
	for _, rule := range rules {
		if !assertion.HasPolicy(rule) {
			toAdd = append(toAdd, rule)
		}
	}

	if len(toAdd) == 0 {
		return nil
	}

	return p.AddPolicies(sec, ptype, toAdd)
}

// RemovePolicy 从内存模型和适配器中删除单条策略
func (p *Policy) RemovePolicy(sec, ptype string, policy []string) error {
	assertion := p.model.GetAssertion(ptype)
	if assertion == nil {
		return errors.NewPolicyNotFoundError(ptype)
	}

	if !assertion.RemovePolicy(policy) {
		return errors.NewPolicyNotFoundError(strings.Join(policy, ", "))
	}

	if p.autoSave && p.adapter != nil {
		line := ptype + ", " + strings.Join(policy, ", ")
		if err := p.adapter.RemovePolicy(line); err != nil {
			assertion.AddPolicy(policy)
			return errors.WrapError("RemovePolicy", err)
		}
	}

	p.cache.Invalidate(ptype)
	p.logger.InfoKV("Policy removed", "type", ptype, "policy", strings.Join(policy, ", "))
	return nil
}

// RemovePolicies 批量删除策略
func (p *Policy) RemovePolicies(sec, ptype string, rules [][]string) error {
	assertion := p.model.GetAssertion(ptype)
	if assertion == nil {
		return errors.NewPolicyNotFoundError(ptype)
	}

	removed := make([][]string, 0)
	for _, rule := range rules {
		if assertion.RemovePolicy(rule) {
			removed = append(removed, rule)
		}
	}

	if p.autoSave && p.adapter != nil {
		if ba, ok := p.adapter.(BatchAdapter); ok {
			var lines []string
			for _, rule := range removed {
				lines = append(lines, ptype+", "+strings.Join(rule, ", "))
			}
			if err := ba.RemovePolicies(lines); err != nil {
				for _, rule := range removed {
					assertion.AddPolicy(rule)
				}
				return errors.WrapError("RemovePolicies", err)
			}
		} else {
			for _, rule := range removed {
				line := ptype + ", " + strings.Join(rule, ", ")
				if err := p.adapter.RemovePolicy(line); err != nil {
					for _, r := range removed {
						assertion.AddPolicy(r)
					}
					return errors.WrapError("RemovePolicies", err)
				}
			}
		}
	}

	p.cache.Invalidate(ptype)
	p.logger.InfoKV("Policies removed", "type", ptype, "count", len(removed))
	return nil
}

// RemoveFilteredPolicy 按字段索引和值过滤删除策略
// 从内存模型中删除所有匹配 fieldIndex 位置开始的 fieldValues 的策略
// 如果适配器支持 UpdatableAdapter，使用 UpdateFilteredPolicies 高效更新
// 否则逐条调用 RemovePolicy
func (p *Policy) RemoveFilteredPolicy(sec, ptype string, fieldIndex int, fieldValues ...string) error {
	assertion := p.model.GetAssertion(ptype)
	if assertion == nil {
		return errors.NewPolicyNotFoundError(ptype)
	}

	// in-place compaction：保留不匹配的策略，仅深拷贝匹配的策略用于回滚
	// 替代之前的 clear-all + re-add，避免 N 次 AddPolicy 的 strings.Join 分配
	// 索引与行位置解耦后，仅需删除被移除策略的 key，无需全量重建
	var removed [][]string
	writeIdx := 0
	for _, policy := range assertion.Policies {
		match := true
		for i, value := range fieldValues {
			if fieldIndex+i < len(policy) && policy[fieldIndex+i] != value {
				match = false
				break
			}
		}
		if match {
			removed = append(removed, append([]string(nil), policy...))
			delete(assertion.PolicyMap, strings.Join(policy, ","))
		} else {
			assertion.Policies[writeIdx] = policy
			writeIdx++
		}
	}

	if len(removed) == 0 {
		return nil
	}

	assertion.Policies = assertion.Policies[:writeIdx]

	if p.autoSave && p.adapter != nil {
		if pa, ok := p.adapter.(PTypeUpdatableAdapter); ok {
			if err := pa.UpdateFilteredPoliciesByPType(ptype, nil, fieldIndex, fieldValues...); err != nil {
				// 回滚内存：恢复被删除的策略
				assertion.Policies = append(assertion.Policies, removed...)
				for _, rule := range removed {
					assertion.PolicyMap[strings.Join(rule, ",")] = struct{}{}
				}
				return errors.WrapError("RemoveFilteredPolicy", err)
			}
		} else if ua, ok := p.adapter.(UpdatableAdapter); ok {
			if err := ua.UpdateFilteredPolicies(nil, fieldIndex, fieldValues...); err != nil {
				// 回滚内存：恢复被删除的策略
				assertion.Policies = append(assertion.Policies, removed...)
				for _, rule := range removed {
					assertion.PolicyMap[strings.Join(rule, ",")] = struct{}{}
				}
				return errors.WrapError("RemoveFilteredPolicy", err)
			}
		} else {
			for _, rule := range removed {
				line := ptype + ", " + strings.Join(rule, ", ")
				_ = p.adapter.RemovePolicy(line)
			}
		}
	}

	p.cache.Invalidate(ptype)
	p.logger.InfoKV("Filtered policies removed", "type", ptype, "count", len(removed))
	return nil
}

// allPolicyLines 获取所有策略的行表示
func (p *Policy) allPolicyLines() []string {
	var policies []string
	for key, assertion := range p.model.GetAssertions() {
		for _, policy := range assertion.Policies {
			policies = append(policies, key+", "+strings.Join(policy, ", "))
		}
	}
	return policies
}

// UpdateFilteredPolicies 按字段索引和值过滤更新策略
// 先移除匹配的旧策略，再追加新策略
// 适用于需要按策略类型更新 p 和 g 规则的场景
func (p *Policy) UpdateFilteredPolicies(sec, ptype string, newPolicies [][]string, fieldIndex int, fieldValues ...string) error {
	assertion := p.model.GetAssertion(ptype)
	if assertion == nil {
		return errors.NewPolicyNotFoundError(ptype)
	}

	// in-place compaction：保留不匹配的策略，仅深拷贝匹配的策略用于回滚
	// 替代之前的深拷贝全部策略 + clear-all + re-add，避免 O(N) 次 AddPolicy 分配
	// 索引与行位置解耦后，仅需删除被移除策略的 key，无需全量重建
	var oldMatched [][]string
	writeIdx := 0
	for _, rule := range assertion.Policies {
		match := true
		for i, value := range fieldValues {
			if fieldIndex+i < len(rule) && rule[fieldIndex+i] != value {
				match = false
				break
			}
		}
		if match {
			oldMatched = append(oldMatched, append([]string(nil), rule...))
			delete(assertion.PolicyMap, strings.Join(rule, ","))
		} else {
			assertion.Policies[writeIdx] = rule
			writeIdx++
		}
	}
	compactedLen := writeIdx
	assertion.Policies = assertion.Policies[:compactedLen]

	// 追加新策略
	// newlyAdded 记录本次真正写入的规则，回滚时精确删除其 key，避免误删原有策略索引
	var newlyAdded [][]string
	for _, rule := range newPolicies {
		if !assertion.HasPolicy(rule) {
			assertion.Policies = append(assertion.Policies, rule)
			assertion.PolicyMap[strings.Join(rule, ",")] = struct{}{}
			newlyAdded = append(newlyAdded, rule)
		}
	}

	if p.autoSave && p.adapter != nil {
		var newLines []string
		for _, rule := range newPolicies {
			newLines = append(newLines, ptype+", "+strings.Join(rule, ", "))
		}

		var err error
		if pa, ok := p.adapter.(PTypeUpdatableAdapter); ok {
			err = pa.UpdateFilteredPoliciesByPType(ptype, newLines, fieldIndex, fieldValues...)
		} else if ua, ok := p.adapter.(UpdatableAdapter); ok {
			err = ua.UpdateFilteredPolicies(newLines, fieldIndex, fieldValues...)
		} else {
			err = p.adapter.SavePolicy(p.allPolicyLines())
		}
		if err != nil {
			// 回滚：截断新增策略，恢复被删除的策略
			assertion.Policies = assertion.Policies[:compactedLen]
			assertion.Policies = append(assertion.Policies, oldMatched...)
			for _, rule := range newlyAdded {
				delete(assertion.PolicyMap, strings.Join(rule, ","))
			}
			for _, rule := range oldMatched {
				assertion.PolicyMap[strings.Join(rule, ",")] = struct{}{}
			}
			return errors.WrapError("UpdateFilteredPolicies", err)
		}
	}

	p.cache.Invalidate(ptype)
	p.logger.InfoKV("Filtered policies updated", "type", ptype, "count", len(newPolicies))
	return nil
}

// UpdatePolicy 更新单条策略（旧策略替换为新策略）
// 如果适配器写入失败，会回滚内存中的策略
func (p *Policy) UpdatePolicy(sec, ptype string, oldPolicy, newPolicy []string) error {
	assertion := p.model.GetAssertion(ptype)
	if assertion == nil {
		return errors.NewPolicyNotFoundError(ptype)
	}

	if !assertion.HasPolicy(oldPolicy) {
		return errors.NewPolicyNotFoundError(strings.Join(oldPolicy, ", "))
	}

	assertion.RemovePolicy(oldPolicy)
	assertion.AddPolicy(newPolicy)

	if p.autoSave && p.adapter != nil {
		oldLine := ptype + ", " + strings.Join(oldPolicy, ", ")
		newLine := ptype + ", " + strings.Join(newPolicy, ", ")
		if ua, ok := p.adapter.(UpdatableAdapter); ok {
			if err := ua.UpdatePolicy(oldLine, newLine); err != nil {
				assertion.RemovePolicy(newPolicy)
				assertion.AddPolicy(oldPolicy)
				return errors.WrapError("UpdatePolicy", err)
			}
		} else {
			_ = p.adapter.RemovePolicy(oldLine)
			_ = p.adapter.AddPolicy(newLine)
		}
	}

	p.cache.Invalidate(ptype)
	p.logger.InfoKV("Policy updated", "type", ptype)
	return nil
}

// UpdatePolicies 批量更新策略
// 先删除旧策略，再添加新策略，支持适配器回退
// 适配器写入失败时会回滚内存中的策略变更
func (p *Policy) UpdatePolicies(sec, ptype string, oldPolicies, newPolicies [][]string) error {
	assertion := p.model.GetAssertion(ptype)
	if assertion == nil {
		return errors.NewPolicyNotFoundError(ptype)
	}

	// 先在内存中执行变更
	for _, old := range oldPolicies {
		assertion.RemovePolicy(old)
	}
	for _, newP := range newPolicies {
		assertion.AddPolicy(newP)
	}

	if p.autoSave && p.adapter != nil {
		if ua, ok := p.adapter.(UpdatableAdapter); ok {
			var oldLines, newLines []string
			for i, old := range oldPolicies {
				oldLines = append(oldLines, ptype+", "+strings.Join(old, ", "))
				newLines = append(newLines, ptype+", "+strings.Join(newPolicies[i], ", "))
			}
			if err := ua.UpdatePolicies(oldLines, newLines); err != nil {
				// 回滚内存：撤销变更
				for _, newP := range newPolicies {
					assertion.RemovePolicy(newP)
				}
				for _, old := range oldPolicies {
					assertion.AddPolicy(old)
				}
				return errors.WrapError("UpdatePolicies", err)
			}
		} else {
			// 非批量适配器：逐条操作，失败时回滚
			for i, newP := range newPolicies {
				line := ptype + ", " + strings.Join(newP, ", ")
				if err := p.adapter.AddPolicy(line); err != nil {
					// 回滚已添加的新策略
					for j := 0; j < i; j++ {
						_ = p.adapter.RemovePolicy(ptype + ", " + strings.Join(newPolicies[j], ", "))
					}
					// 回滚内存
					for _, np := range newPolicies {
						assertion.RemovePolicy(np)
					}
					for _, old := range oldPolicies {
						assertion.AddPolicy(old)
					}
					return errors.WrapError("UpdatePolicies", err)
				}
			}
			for _, old := range oldPolicies {
				_ = p.adapter.RemovePolicy(ptype + ", " + strings.Join(old, ", "))
			}
		}
	}

	p.cache.Invalidate(ptype)
	p.logger.InfoKV("Policies updated", "type", ptype, "count", len(oldPolicies))
	return nil
}

// GetFilteredPolicy 按字段索引和值过滤获取策略列表
func (p *Policy) GetFilteredPolicy(ptype string, fieldIndex int, fieldValues ...string) [][]string {
	assertion := p.model.GetAssertion(ptype)
	if assertion == nil {
		return nil
	}

	var result [][]string
	for _, policy := range assertion.Policies {
		match := true
		for i, value := range fieldValues {
			if fieldIndex+i < len(policy) && policy[fieldIndex+i] != value {
				match = false
				break
			}
		}
		if match {
			result = append(result, policy)
		}
	}
	return result
}

// GetAllPolicies 获取指定类型的所有策略
func (p *Policy) GetAllPolicies(ptype string) [][]string {
	assertion := p.model.GetAssertion(ptype)
	if assertion == nil {
		return nil
	}
	return assertion.Policies
}

// HasPolicy 检查指定类型的策略是否存在
func (p *Policy) HasPolicy(ptype string, policy []string) bool {
	assertion := p.model.GetAssertion(ptype)
	if assertion == nil {
		return false
	}
	return assertion.HasPolicy(policy)
}

// GetAllSubjects 获取所有策略主体（p 段第 0 个字段）
func (p *Policy) GetAllSubjects() []string {
	return p.getAllFieldValues(model.SectionPolicyDefinition, 0)
}

// GetAllObjects 获取所有策略资源（p 段第 1 个字段）
func (p *Policy) GetAllObjects() []string {
	return p.getAllFieldValues(model.SectionPolicyDefinition, 1)
}

// GetAllActions 获取所有策略操作（p 段第 2 个字段）
func (p *Policy) GetAllActions() []string {
	return p.getAllFieldValues(model.SectionPolicyDefinition, 2)
}

// GetAllRoles 获取所有角色（g 段第 1 个字段）
func (p *Policy) GetAllRoles() []string {
	return p.getAllFieldValues(model.SectionRoleDefinition, 1)
}

// GetAllUsers 获取所有用户（g 段第 0 个字段）
func (p *Policy) GetAllUsers() []string {
	return p.getAllFieldValues(model.SectionRoleDefinition, 0)
}

// getAllFieldValues 从指定段的所有断言中提取指定字段的去重值列表
func (p *Policy) getAllFieldValues(section string, fieldIndex int) []string {
	seen := make(map[string]bool)
	var result []string

	for key, assertion := range p.model.GetAssertions() {
		if strings.HasPrefix(key, section) {
			for _, policy := range assertion.Policies {
				if fieldIndex < len(policy) {
					val := policy[fieldIndex]
					if !seen[val] {
						seen[val] = true
						result = append(result, val)
					}
				}
			}
		}
	}
	return result
}

// addPolicyInternal 内部方法：解析策略行并添加到模型
// 策略行格式为 "p, alice, data1, read"，解析后添加到对应类型的断言中
// 支持括号内包含逗号的表达式，如 r.sub in ("alice", "bob")
func (p *Policy) addPolicyInternal(line string) {
	tokens := splitPolicyLine(line)

	if len(tokens) < 2 {
		return
	}

	ptype := tokens[0]
	policy := tokens[1:]

	assertion := p.model.GetAssertion(ptype)
	if assertion != nil {
		assertion.AddPolicy(policy)
	}
}

// splitPolicyLine 智能分割策略行
// 只分割顶层逗号，忽略括号内的逗号
// 例如：p, r.sub in ("alice", "bob"), data4, read
// → ["p", "r.sub in (\"alice\", \"bob\")", "data4", "read"]
func splitPolicyLine(line string) []string {
	var tokens []string
	var current strings.Builder
	depth := 0

	for _, ch := range line {
		if ch == '(' || ch == '[' || ch == '{' {
			depth++
			current.WriteRune(ch)
		} else if ch == ')' || ch == ']' || ch == '}' {
			depth--
			current.WriteRune(ch)
		} else if ch == ',' && depth == 0 {
			tokens = append(tokens, strings.TrimSpace(current.String()))
			current.Reset()
		} else {
			current.WriteRune(ch)
		}
	}

	if current.Len() > 0 {
		tokens = append(tokens, strings.TrimSpace(current.String()))
	}

	return tokens
}

// SetAdapter 设置策略存储适配器
func (p *Policy) SetAdapter(adapter Adapter) {
	p.adapter = adapter
}

// GetAdapter 获取当前策略存储适配器
func (p *Policy) GetAdapter() Adapter {
	return p.adapter
}

// GetCache 获取策略缓存
func (p *Policy) GetCache() *PolicyCache {
	return p.cache
}
