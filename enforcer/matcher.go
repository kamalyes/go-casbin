/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-08-07 02:08:57
 * @FilePath: \go-casbin\enforcer\matcher.go
 * @Description: 匹配引擎（基于 go-toolbox）
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package enforcer

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/kamalyes/go-casbin/model"
	"github.com/kamalyes/go-casbin/policy"
	"github.com/kamalyes/go-casbin/role"
	"github.com/kamalyes/go-logger"
	"github.com/kamalyes/go-toolbox/pkg/safe"
	"github.com/kamalyes/go-toolbox/pkg/syncx"
)

// MatchContext 匹配上下文
// 封装一次匹配操作所需的所有数据
type MatchContext struct {
	Request       map[string]interface{}    // 请求参数（r 段的键值对，如 r.sub="alice"）
	Policies      [][]string                // 策略列表（p 段的所有策略行）
	RoleMgr       *role.RoleManager         // 角色管理器（用于 g() 函数的角色继承判断）
	Assertion     *model.Assertion          // 策略断言（包含字段名映射，如 p.sub/p.obj/p.act）
	CustomFuncs   map[string]BuiltinFunc    // 自定义函数映射（如 eval() 函数）
	ExtraPolicies map[string]*PolicySegment // 额外策略段映射（如 extra_policies）
	ShortCircuit  bool                      // 短路优化：匹配到 allow 后立即返回（适用于 some(where(p.eft==allow)) 模式）
	HasEval       bool                      // 表达式是否包含 eval()（预计算，避免每条策略重复 strings.Contains）
	HasGFunc      bool                      // 表达式是否包含 g()（预计算，避免每条策略重复 strings.Contains）
	EffectIndex   int                       // p.eft 在 assertion.Tokens 中的索引（-1 表示无 eft 字段），extractEffect O(1)
}

// PolicySegment 策略段
// 封装额外的策略列表和断言，用于匹配
type PolicySegment struct {
	Policies  [][]string
	Assertion *model.Assertion
}

// MatcherEngine 匹配器引擎
// 负责将请求与策略进行匹配，支持三种匹配模式：
//   - 基本匹配：ACL 模式，直接比较 r.sub == p.sub
//   - 角色匹配：RBAC 模式，通过 g(r.sub, p.sub) 判断角色继承
//   - 表达式求值：ABAC 规则模式，通过 eval(p.sub_rule) 动态执行条件表达式
type MatcherEngine struct {
	logger       logger.ILogger
	customFuncs  map[string]BuiltinFunc
	compileCache sync.Map // key: expr string, value: *compiledNode，避免每次 Match 重复编译表达式
}

// NewMatcherEngine 创建匹配器引擎
func NewMatcherEngine(log logger.ILogger) *MatcherEngine {
	return &MatcherEngine{logger: log}
}

// gFuncRegex 匹配 g() 函数调用，如 g(r.sub, p.sub) 或 g(r.sub, p.sub, r.dom)
var gFuncRegex = regexp.MustCompile(`g\(([^,]+),\s*([^,)]+)(?:,\s*([^,)]+))?\)`)

// evalRegex 匹配 eval() 函数调用，如 eval(p.sub_rule)
var evalRegex = regexp.MustCompile(`eval\(([^)]+)\)`)

// funcArgsPool 复用自定义函数调用的 args 切片，减少每条策略的堆分配
// keyMatch3/regexMatch 等函数在每条策略评估时都会调用，pool 化后零分配
var funcArgsPool = syncx.NewPool(func() []interface{} {
	return make([]interface{}, 0, 4)
})

// varsMapPool 复用变量映射表，减少每次匹配的 map 分配
// eval 求值全程只读 vars（kindEval 展开的子表达式亦只读），clear 后归还即可安全复用
var varsMapPool = syncx.NewPool(func() map[string]interface{} {
	return make(map[string]interface{}, 8)
})

// Match 执行匹配，返回是否匹配以及匹配策略的效果列表
// 核心匹配流程：
//   - 如果有策略，遍历每条策略评估 matcher 表达式
//   - 如果没有策略（纯 ABAC 属性匹配），直接用请求参数评估 matcher
//
// 性能优化：使用编译表达式（AST）替代每次 evalExpr 的递归字符串扫描
// 表达式编译一次，缓存复用，每条策略只做 O(1) 树遍历求值
func (me *MatcherEngine) Match(mc *MatchContext, matcherExpr string) (bool, []string, error) {
	me.customFuncs = mc.CustomFuncs

	// 短路模式下延迟分配 matchedEffects：命中 allow 直接返回单元素切片
	// 非短路模式预分配以收集所有匹配效果
	var matchedEffects []string
	if !mc.ShortCircuit {
		matchedEffects = make([]string, 0, len(mc.Policies))
	}

	hasEval := mc.HasEval
	// EffectIndex 默认 0 与 p.eft 在 index 0 二义，始终从 assertion 重算确保正确
	effectIdx := computeEffectIndex(mc.Assertion)

	if len(mc.Policies) == 0 && len(mc.ExtraPolicies) == 0 {
		vars := me.acquireVars(mc.Request, nil, nil)
		compiled := me.getCompiledExpr(matcherExpr)
		result := compiled.eval(me, vars, mc.RoleMgr)
		releaseVars(vars)
		if result {
			return true, []string{"allow"}, nil
		}
		return false, nil, nil
	}

	if len(mc.ExtraPolicies) > 0 {
		return me.matchWithExtraPolicies(mc, matcherExpr, matchedEffects)
	}

	// vars map 池化复用：无 eval() 场景，预构建含 request 字段的复用 map
	// 每条策略只更新 p.* 字段（r.* 不变），省去 N 次 map 分配 + request 拷贝
	// 编译表达式 eval 只读 vars 不写，复用安全；有 eval() 时必须每条策略独立 vars（p.sub_rule 值不同）
	var reusableVars map[string]interface{}
	if !hasEval {
		reusableVars = me.acquireVars(mc.Request, nil, mc.Assertion)
		defer releaseVars(reusableVars)
	}

	compiled := me.getCompiledExpr(matcherExpr)

	for _, p := range mc.Policies {
		var vars map[string]interface{}
		if hasEval {
			// 有 eval()：每条策略的 p.sub_rule 值不同，必须独立 vars，用完即归还
			vars = me.acquireVars(mc.Request, p, mc.Assertion)
		} else {
			// 无 eval()：复用 vars，只更新 p.* 字段（覆盖旧值）
			// 同一 ptype 的策略字段数固定（模型定义），不会残留多余字段
			vars = reusableVars
			if mc.Assertion != nil {
				for i, token := range mc.Assertion.Tokens {
					if i < len(p) {
						vars[token] = p[i]
					}
				}
			}
		}

		matched := compiled.eval(me, vars, mc.RoleMgr)
		if hasEval {
			releaseVars(vars)
		}
		if matched {
			eft := extractEffectFast(p, effectIdx)

			// 短路优化：对于 some(where(p.eft==allow)) 模式，
			// 匹配到第一条 allow 策略即可立即返回，无需遍历剩余策略
			if mc.ShortCircuit && eft == "allow" {
				return true, []string{eft}, nil
			}
			matchedEffects = append(matchedEffects, eft)
		}
	}

	if len(matchedEffects) > 0 {
		return true, matchedEffects, nil
	}
	return false, nil, nil
}

// matchWithExtraPolicies 匹配额外策略段
// 处理包含额外策略段的 matcher 表达式，如 p1 || p2
func (me *MatcherEngine) matchWithExtraPolicies(mc *MatchContext, matcherExpr string, matchedEffects []string) (bool, []string, error) {
	topOr := me.findTopLevelOp(matcherExpr, "||")
	if topOr < 0 {
		return me.matchSingleSegment(mc, matcherExpr, mc.Policies, mc.Assertion, matchedEffects)
	}

	leftExpr := strings.TrimSpace(matcherExpr[:topOr])
	rightExpr := strings.TrimSpace(matcherExpr[topOr+2:])

	leftHasP2 := me.exprReferencesSegment(leftExpr, policy.PTypePolicy2)
	rightHasP2 := me.exprReferencesSegment(rightExpr, policy.PTypePolicy2)

	me.logger.DebugKV("matchWithExtraPolicies", "leftHasP2", leftHasP2, "rightHasP2", rightHasP2, "leftExpr", leftExpr, "rightExpr", rightExpr)

	if leftHasP2 || rightHasP2 {
		var rbacExpr, pbacExpr string
		var rbacPolicies [][]string
		var rbacAssertion *model.Assertion
		var pbacPolicies [][]string
		var pbacAssertion *model.Assertion

		if leftHasP2 {
			rbacExpr = rightExpr
			rbacPolicies = mc.Policies
			rbacAssertion = mc.Assertion
			pbacExpr = leftExpr
		} else {
			rbacExpr = leftExpr
			rbacPolicies = mc.Policies
			rbacAssertion = mc.Assertion
			pbacExpr = rightExpr
		}

		if p2, ok := mc.ExtraPolicies[policy.PTypePolicy2]; ok {
			pbacPolicies = p2.Policies
			pbacAssertion = p2.Assertion
		}

		me.logger.DebugKV("matchWithExtraPolicies-rbac", "rbacExpr", rbacExpr, "policies_count", len(rbacPolicies))
		me.logger.DebugKV("matchWithExtraPolicies-pbac", "pbacExpr", pbacExpr, "policies_count", len(pbacPolicies), "pbacPolicies", fmt.Sprintf("%v", pbacPolicies))

		ok, effects, _ := me.matchSingleSegment(mc, rbacExpr, rbacPolicies, rbacAssertion, nil)
		me.logger.DebugKV("matchWithExtraPolicies-rbac-result", "ok", ok)
		if ok {
			matchedEffects = append(matchedEffects, effects...)
			return true, matchedEffects, nil
		}

		ok, effects, _ = me.matchSingleSegment(mc, pbacExpr, pbacPolicies, pbacAssertion, nil)
		me.logger.DebugKV("matchWithExtraPolicies-pbac-result", "ok", ok)
		if ok {
			matchedEffects = append(matchedEffects, effects...)
			return true, matchedEffects, nil
		}

		return false, nil, nil
	}

	return me.matchSingleSegment(mc, matcherExpr, mc.Policies, mc.Assertion, matchedEffects)
}

// matchSingleSegment 匹配单策略段
// 处理不包含额外策略段的 matcher 表达式，如 p.sub == alice
//
// 性能优化：与 Match 方法一致，无 eval() 场景复用 vars map，每条策略只更新 p.* 字段
// 使用编译表达式（AST）替代每次 evalExpr 的递归字符串扫描
func (me *MatcherEngine) matchSingleSegment(mc *MatchContext, expr string, policies [][]string, assertion *model.Assertion, matchedEffects []string) (bool, []string, error) {
	if matchedEffects == nil {
		matchedEffects = make([]string, 0)
	}

	hasEval := mc.HasEval
	effectIdx := computeEffectIndex(assertion)

	if len(policies) == 0 {
		vars := me.acquireVars(mc.Request, nil, nil)
		compiled := me.getCompiledExpr(expr)
		result := compiled.eval(me, vars, mc.RoleMgr)
		releaseVars(vars)
		if result {
			return true, []string{"allow"}, nil
		}
		return false, nil, nil
	}

	// vars map 池化复用：无 eval() 场景，预构建含 request 字段的复用 map
	// 每条策略只更新 p.* 字段，省去 N 次 map 分配 + request 拷贝
	var reusableVars map[string]interface{}
	if !hasEval {
		reusableVars = me.acquireVars(mc.Request, nil, assertion)
		defer releaseVars(reusableVars)
	}

	compiled := me.getCompiledExpr(expr)

	for _, p := range policies {
		var vars map[string]interface{}
		if hasEval {
			vars = me.acquireVars(mc.Request, p, assertion)
		} else {
			vars = reusableVars
			if assertion != nil {
				for i, token := range assertion.Tokens {
					if i < len(p) {
						vars[token] = p[i]
					}
				}
			}
		}

		matched := compiled.eval(me, vars, mc.RoleMgr)
		if hasEval {
			releaseVars(vars)
		}
		if matched {
			eft := extractEffectFast(p, effectIdx)
			matchedEffects = append(matchedEffects, eft)

			// 短路优化
			if mc.ShortCircuit && eft == "allow" {
				return true, matchedEffects, nil
			}
		}
	}

	if len(matchedEffects) > 0 {
		return true, matchedEffects, nil
	}
	return false, nil, nil
}

// exprReferencesSegment 检查表达式是否引用了额外策略段
// 例如：p1 || p2.sub == alice
func (me *MatcherEngine) exprReferencesSegment(expr string, segment string) bool {
	return strings.Contains(expr, segment+".")
}

// expandEval 将 eval(p.sub_rule) 替换为策略中对应的条件表达式值
// 例如：eval(p.sub_rule) → r.sub == "alice"
// 安全防护：对展开的值进行校验，防止注入恶意表达式
func (me *MatcherEngine) expandEval(expr string, vars map[string]interface{}) string {
	return evalRegex.ReplaceAllStringFunc(expr, func(match string) string {
		// 提取括号内的变量名
		inner := evalRegex.FindStringSubmatch(match)
		if len(inner) < 2 {
			return match
		}
		varName := strings.TrimSpace(inner[1])
		if val, ok := vars[varName]; ok {
			expanded := valueToString(val)
			// 安全校验：拒绝包含危险操作符的 eval 值，防止表达式注入
			if containsDangerousExpr(expanded) {
				me.logger.WarnKV("Dangerous eval expression blocked", "value", expanded)
				return "false"
			}
			return expanded
		}
		return match
	})
}

// containsDangerousExpr 检查表达式值是否包含危险操作符
// 防止通过策略字段注入恶意代码（如系统调用、文件操作等）
func containsDangerousExpr(expr string) bool {
	dangerous := []string{"os.", "runtime.", "exec(", "system(", "import(", "panic(",
		"recover(", "unsafe.", "reflect.", "syscall."}
	lower := strings.ToLower(expr)
	for _, d := range dangerous {
		if strings.Contains(lower, d) {
			return true
		}
	}
	return false
}

// extractEffect 从策略行中提取 eft（效果）字段
// 如果策略定义中包含 p.eft 字段，则取对应值；否则默认为 "allow"
func (me *MatcherEngine) extractEffect(policyLine []string, assertion *model.Assertion) string {
	if assertion == nil {
		return "allow"
	}
	for i, token := range assertion.Tokens {
		if token == "p.eft" && i < len(policyLine) {
			return policyLine[i]
		}
	}
	return "allow"
}

// evalExpr 评估一个完整的 matcher 表达式
// 支持 &&、||、==、!=、g() 函数调用
func (me *MatcherEngine) evalExpr(expr string, vars map[string]interface{}, roleMgr *role.RoleManager) bool {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return false
	}

	// 去除最外层配对括号，如 (r.act == p.act || p.act == "*") → r.act == p.act || p.act == "*"
	for {
		if !strings.HasPrefix(expr, "(") || !strings.HasSuffix(expr, ")") {
			break
		}
		depth := 0
		matched := true
		for i, ch := range expr {
			if ch == '(' {
				depth++
			} else if ch == ')' {
				depth--
			}
			if depth == 0 && i < len(expr)-1 {
				matched = false
				break
			}
		}
		if matched {
			expr = strings.TrimSpace(expr[1 : len(expr)-1])
		} else {
			break
		}
	}

	// 处理 || 和 && — 单次遍历查找顶层运算符
	// || 优先级低于 &&，先拆分 || 确保 a && b || c && d 被解析为 (a && b) || (c && d)
	if topOr, topAnd := me.findTopLevelOps(expr); topOr >= 0 {
		left := expr[:topOr]
		right := expr[topOr+2:]
		return me.evalExpr(left, vars, roleMgr) || me.evalExpr(right, vars, roleMgr)
	} else if topAnd >= 0 {
		left := expr[:topAnd]
		right := expr[topAnd+2:]
		return me.evalExpr(left, vars, roleMgr) && me.evalExpr(right, vars, roleMgr)
	}

	// 处理 g() 函数调用
	if strings.Contains(expr, "g(") {
		return me.evalGFunction(expr, vars, roleMgr)
	}

	// 处理自定义函数调用，如 keyMatch3(r.obj, p.obj)
	if fnName, fnArgs, ok := me.parseFunctionCall(expr); ok {
		if fn, exists := me.customFuncs[fnName]; exists {
			resolvedArgs := make([]interface{}, len(fnArgs))
			for i, arg := range fnArgs {
				resolvedArgs[i] = me.resolveValue(strings.TrimSpace(arg), vars)
			}
			result, err := fn(resolvedArgs...)
			if err != nil {
				return false
			}
			if b, ok := result.(bool); ok {
				return b
			}
			return false
		}
	}

	// 处理 == 比较
	if idx := strings.Index(expr, "=="); idx >= 0 {
		left := me.resolveValue(strings.TrimSpace(expr[:idx]), vars)
		right := me.resolveValue(strings.TrimSpace(expr[idx+2:]), vars)
		return valueToString(left) == valueToString(right)
	}

	// 处理 != 比较
	if idx := strings.Index(expr, "!="); idx >= 0 {
		left := me.resolveValue(strings.TrimSpace(expr[:idx]), vars)
		right := me.resolveValue(strings.TrimSpace(expr[idx+2:]), vars)
		return valueToString(left) != valueToString(right)
	}

	// 处理 in 运算符：r.sub in ("alice","bob")
	if strings.Contains(expr, " in ") {
		return me.evalInExpr(expr, vars)
	}

	return false
}

// findTopLevelOps 单次遍历同时查找顶层 || 和 && 运算符位置
// 返回 (orPos, andPos)，-1 表示未找到
// 合并两次遍历为一次，减少热路径上的字符串扫描开销
func (me *MatcherEngine) findTopLevelOps(expr string) (int, int) {
	depth := 0
	orPos := -1
	andPos := -1
	for i := 0; i < len(expr); i++ {
		ch := expr[i]
		switch ch {
		case '(':
			depth++
		case ')':
			depth--
		}
		if depth == 0 && i+1 < len(expr) {
			two := expr[i : i+2]
			if two == "||" && orPos < 0 {
				orPos = i
			} else if two == "&&" && andPos < 0 {
				andPos = i
			}
		}
	}
	return orPos, andPos
}

// findTopLevelOp 查找顶层（不在括号内）的运算符位置
// 用于正确处理包含括号的表达式，如 g(r.sub, p.sub) && r.obj == p.obj
func (me *MatcherEngine) findTopLevelOp(expr string, op string) int {
	depth := 0
	for i := 0; i <= len(expr)-len(op); i++ {
		ch := expr[i]
		switch ch {
		case '(':
			depth++
		case ')':
			depth--
		}
		if depth == 0 && expr[i:i+len(op)] == op {
			return i
		}
	}
	return -1
}

// evalInExpr 评估 in 运算符表达式
// 语法：value in ("item1","item2","item3")
// 判断 value 是否在给定的集合中
func (me *MatcherEngine) evalInExpr(expr string, vars map[string]interface{}) bool {
	inIdx := strings.Index(expr, " in ")
	if inIdx < 0 {
		return false
	}

	leftToken := strings.TrimSpace(expr[:inIdx])
	rightPart := strings.TrimSpace(expr[inIdx+4:])

	leftVal := valueToString(me.resolveValue(leftToken, vars))

	if !strings.HasPrefix(rightPart, "(") || !strings.HasSuffix(rightPart, ")") {
		return false
	}
	inner := rightPart[1 : len(rightPart)-1]
	items := strings.Split(inner, ",")
	for _, item := range items {
		item = strings.TrimSpace(item)
		item = strings.Trim(item, `"'`)
		if leftVal == item {
			return true
		}
	}
	return false
}

// evalGFunction 评估 g() 角色继承函数
// 支持 g(name1, name2) 和 g(name1, name2, domain) 两种形式
// g(r.sub, p.sub) 判断 r.sub 是否继承自 p.sub（即 r.sub 是否拥有 p.sub 角色）
// g(r.sub, p.sub, r.dom) 在指定域中判断角色继承
func (me *MatcherEngine) evalGFunction(expr string, vars map[string]interface{}, roleMgr *role.RoleManager) bool {
	matches := gFuncRegex.FindStringSubmatch(expr)
	if len(matches) < 3 {
		return false
	}

	name1Raw := strings.TrimSpace(matches[1])
	name2Raw := strings.TrimSpace(matches[2])

	name1 := valueToString(me.resolveValue(name1Raw, vars))
	name2 := valueToString(me.resolveValue(name2Raw, vars))

	if len(matches) >= 4 && matches[3] != "" {
		domain := valueToString(me.resolveValue(strings.TrimSpace(matches[3]), vars))
		return me.evaluateRoleFunctionWithDomain(name1, name2, domain, roleMgr)
	}

	return me.evaluateRoleFunction(name1, name2, roleMgr)
}

// evaluateRoleFunction 判断 name1 是否继承自 name2（无域）
func (me *MatcherEngine) evaluateRoleFunction(name1, name2 string, roleMgr *role.RoleManager) bool {
	if roleMgr == nil {
		return name1 == name2
	}
	return roleMgr.HasLink(name1, name2)
}

// evaluateRoleFunctionWithDomain 判断 name1 在指定域中是否继承自 name2
func (me *MatcherEngine) evaluateRoleFunctionWithDomain(name1, name2, domain string, roleMgr *role.RoleManager) bool {
	if roleMgr == nil {
		return name1 == name2
	}
	return roleMgr.HasLink(name1, name2, domain)
}

// acquireVars 从池获取变量表，clear 残留后填充请求参数（r 段）和策略行（p 段）
// 例如：{r.sub: "alice", r.obj: "data1", p.sub: "admin", p.obj: "data1"}
// 替代每次 make 新 map：miss 路径每请求一次 map 分配是显著热点
// 池中 map 已增长到稳态容量，clear 仅重置长度不缩容，稳态零分配
func (me *MatcherEngine) acquireVars(request map[string]interface{}, policyLine []string, assertion *model.Assertion) map[string]interface{} {
	vars := varsMapPool.Get()
	clear(vars)

	for key, val := range request {
		vars[key] = val
	}

	if assertion != nil && len(policyLine) > 0 {
		for i, token := range assertion.Tokens {
			if i < len(policyLine) {
				vars[token] = policyLine[i]
			}
		}
	}

	return vars
}

// releaseVars 清空并归还变量表（nil 安全）
// Put 前 clear 斩断值引用，避免请求中的大对象因池滞留而延迟回收
func releaseVars(vars map[string]interface{}) {
	if vars == nil {
		return
	}
	clear(vars)
	varsMapPool.Put(vars)
}

// parseFunctionCall 解析函数调用表达式
// 例如：keyMatch3(r.obj, p.obj) → fnName="keyMatch3", fnArgs=["r.obj", "p.obj"]
func (me *MatcherEngine) parseFunctionCall(expr string) (string, []string, bool) {
	expr = strings.TrimSpace(expr)

	// 找到左括号位置
	lpIdx := strings.Index(expr, "(")
	if lpIdx < 0 {
		return "", nil, false
	}

	// 确认右括号在末尾
	if !strings.HasSuffix(expr, ")") {
		return "", nil, false
	}

	fnName := strings.TrimSpace(expr[:lpIdx])
	if fnName == "" || fnName == "g" || fnName == "eval" {
		return "", nil, false
	}

	inner := expr[lpIdx+1 : len(expr)-1]

	var args []string
	depth := 0
	var current strings.Builder

	for _, ch := range inner {
		if ch == '(' || ch == '[' {
			depth++
			current.WriteRune(ch)
		} else if ch == ')' || ch == ']' {
			depth--
			current.WriteRune(ch)
		} else if ch == ',' && depth == 0 {
			args = append(args, strings.TrimSpace(current.String()))
			current.Reset()
		} else {
			current.WriteRune(ch)
		}
	}

	if current.Len() > 0 {
		args = append(args, strings.TrimSpace(current.String()))
	}

	if len(args) == 0 {
		return "", nil, false
	}

	return fnName, args, true
}

// resolveValue 解析变量值
// 支持三种解析方式：
//  1. 直接变量查找：vars["r.sub"] → "alice"
//  2. 嵌套属性访问：vars["r.obj"] 是结构体 → 访问 r.obj.Owner
//     对于 r.obj.Owner，先找 vars["r.obj"]，再访问其 Owner 字段
//  3. 字面量：不在 vars 中的值视为字面量，去掉引号后返回
func (me *MatcherEngine) resolveValue(token string, vars map[string]interface{}) interface{} {
	// 直接查找
	if val, ok := vars[token]; ok {
		return val
	}

	// 嵌套属性访问：尝试逐级查找
	// 例如 r.obj.Owner → 先找 r.obj，再访问 Owner
	if strings.Contains(token, ".") {
		parts := strings.Split(token, ".")
		// 从最长前缀开始尝试
		for i := len(parts) - 1; i >= 1; i-- {
			prefix := strings.Join(parts[:i], ".")
			if root, ok := vars[prefix]; ok {
				remaining := strings.Join(parts[i:], ".")
				accessor := safe.Safe(root)
				result := accessor.Field(remaining)
				if result.IsValid() {
					return result.Value()
				}
				// 尝试逐级访问
				current := root
				for j := i; j < len(parts); j++ {
					a := safe.Safe(current)
					r := a.Field(parts[j])
					if !r.IsValid() {
						break
					}
					current = r.Value()
					if j == len(parts)-1 {
						return current
					}
				}
			}
		}
	}

	// 字面量处理：去掉引号
	if (strings.HasPrefix(token, `"`) && strings.HasSuffix(token, `"`)) ||
		(strings.HasPrefix(token, `'`) && strings.HasSuffix(token, `'`)) {
		return token[1 : len(token)-1]
	}

	return token
}

// valueToString 将 interface{} 转为字符串，避免 fmt.Sprintf 的反射和分配开销
// 热路径上每条策略的 == 和 != 比较都会调用此函数
func valueToString(v interface{}) string {
	switch val := v.(type) {
	case string:
		return val
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", val)
	}
}

// ==================== 编译表达式（AST） ====================
//
// 传统 evalExpr 对每条策略递归字符串扫描（findTopLevelOps、strings.Index、strings.Contains），
// N 条策略 = N 次完整表达式解析。编译表达式将解析结果缓存为 AST 树，
// 每条策略只做 O(1) 树遍历求值，消除热路径上的所有字符串扫描开销
//
// 支持的表达式语法：
//   - 逻辑运算：a && b, a || b
//   - 比较运算：r.sub == p.sub, r.sub != p.sub
//   - 角色函数：g(r.sub, p.sub), g(r.sub, p.sub, r.dom)
//   - 自定义函数：keyMatch3(r.obj, p.obj) 等
//   - eval 展开：eval(p.sub_rule) — 每条策略展开为不同子表达式，子表达式同样编译缓存
//   - in 运算符：r.sub in ("alice","bob")
//   - 括号分组：(a || b) && c

// nodeKind 标识编译表达式的节点类型
type nodeKind int

const (
	kindAnd     nodeKind = iota // a && b
	kindOr                      // a || b
	kindCompare                 // a == b, a != b
	kindGFunc                   // g(name1, name2, [domain])
	kindFunc                    // keyMatch3(r.obj, p.obj) 等自定义函数
	kindIn                      // r.sub in ("a","b")
	kindEval                    // eval(p.sub_rule) — 每条策略动态展开
)

// compiledNode 预编译表达式节点
// 由 compileExpr 一次性解析表达式生成，eval 方法做 O(1) 树遍历求值
type compiledNode struct {
	kind  nodeKind
	left  *compiledNode // and/or 的左子树
	right *compiledNode // and/or 的右子树
	// compare 节点
	op       string // "==", "!="
	leftTok  string // 左操作数 token（如 "r.sub"）
	rightTok string // 右操作数 token（如 "p.sub" 或字面量）
	// gFunc 节点（复用 leftTok/rightTok 作为 name1/name2）
	gDomain string // 域 token，空表示无域
	// func 节点
	fnName string   // 函数名（如 "keyMatch3"）
	fnArgs []string // 函数参数 token 列表
	// eval 节点
	evalVar string // eval 引用的变量名（如 "p.sub_rule"）
	// in 节点（复用 leftTok 作为左值）
	inItems []string // in 的候选项列表
}

// eval 求值编译表达式
// vars: 变量映射表（r.* 和 p.* 字段）
// roleMgr: 角色管理器（用于 g() 函数）
// me: 匹配器引擎（用于 resolveValue 和 customFuncs 查找）
// resolveVarInline 内联 map 查找，命中则直接返回，未命中 fallback 到 resolveValue
// 99% 场景 token 直接在 vars 中（r.sub/p.obj 等），省去 resolveValue 函数调用开销
// 仅 ABAC 嵌套属性（r.obj.Owner）走 resolveValue 的 strings.Split 逻辑
func resolveVarInline(me *MatcherEngine, token string, vars map[string]interface{}) interface{} {
	if val, ok := vars[token]; ok {
		return val
	}
	return me.resolveValue(token, vars)
}

// toStringInline 内联 valueToString，string 类型直接断言返回，非 string 走 valueToString
func toStringInline(val interface{}) string {
	if s, ok := val.(string); ok {
		return s
	}
	return valueToString(val)
}

func (n *compiledNode) eval(me *MatcherEngine, vars map[string]interface{}, roleMgr *role.RoleManager) bool {
	switch n.kind {
	case kindAnd:
		return n.left.eval(me, vars, roleMgr) && n.right.eval(me, vars, roleMgr)
	case kindOr:
		return n.left.eval(me, vars, roleMgr) || n.right.eval(me, vars, roleMgr)
	case kindCompare:
		// 内联 map 查找 + valueToString：99% 场景零函数调用开销
		left := toStringInline(resolveVarInline(me, n.leftTok, vars))
		right := toStringInline(resolveVarInline(me, n.rightTok, vars))
		if n.op == "==" {
			return left == right
		}
		return left != right
	case kindGFunc:
		// 内联 map 查找 + valueToString
		name1 := toStringInline(resolveVarInline(me, n.leftTok, vars))
		name2 := toStringInline(resolveVarInline(me, n.rightTok, vars))
		if n.gDomain != "" {
			domain := toStringInline(resolveVarInline(me, n.gDomain, vars))
			return me.evaluateRoleFunctionWithDomain(name1, name2, domain, roleMgr)
		}
		return me.evaluateRoleFunction(name1, name2, roleMgr)
	case kindFunc:
		fn, exists := me.customFuncs[n.fnName]
		if !exists {
			return false
		}
		// pool 复用 args 切片，减少每条策略的堆分配
		args := funcArgsPool.Get()[:0]
		for _, arg := range n.fnArgs {
			args = append(args, resolveVarInline(me, arg, vars))
		}
		result, err := fn(args...)
		funcArgsPool.Put(args)
		if err != nil {
			return false
		}
		if b, ok := result.(bool); ok {
			return b
		}
		return false
	case kindIn:
		// 内联 map 查找 + valueToString
		leftVal := toStringInline(resolveVarInline(me, n.leftTok, vars))
		for _, item := range n.inItems {
			if leftVal == item {
				return true
			}
		}
		return false
	case kindEval:
		// eval() 每条策略展开为不同子表达式，子表达式同样编译缓存后求值
		val, ok := vars[n.evalVar]
		if !ok {
			return false
		}
		expanded := toStringInline(val)
		if containsDangerousExpr(expanded) {
			me.logger.WarnKV("Dangerous eval expression blocked", "value", expanded)
			return false
		}
		return getCompiledEvalExpr(expanded).eval(me, vars, roleMgr)
	}
	return false
}

// evalCompileCache 缓存 eval 展开后的子表达式编译结果
// key: 展开后的表达式字符串（如 r.sub == "alice"），value: *compiledNode
// 相同 sub_rule 值的策略共享编译结果，避免重复解析
var evalCompileCache sync.Map

// getCompiledExpr 获取或编译表达式
// 从 MatcherEngine.compileCache 查找，命中则直接返回，未命中则编译并缓存
func (me *MatcherEngine) getCompiledExpr(expr string) *compiledNode {
	if cached, ok := me.compileCache.Load(expr); ok {
		return cached.(*compiledNode)
	}
	node := me.compileExpr(expr)
	if node == nil {
		// 无法编译的表达式降级为恒 false，避免 nil panic
		node = &compiledNode{kind: kindCompare, op: "==", leftTok: "false", rightTok: "true"}
	}
	me.compileCache.Store(expr, node)
	return node
}

// getCompiledEvalExpr 获取或编译 eval 展开后的子表达式
// 使用全局 evalCompileCache，跨 MatchContext 共享
func getCompiledEvalExpr(expanded string) *compiledNode {
	if cached, ok := evalCompileCache.Load(expanded); ok {
		return cached.(*compiledNode)
	}
	// eval 展开的子表达式用空 MatcherEngine 编译（compileExpr 不依赖引擎状态）
	node := (&MatcherEngine{}).compileExpr(expanded)
	if node == nil {
		node = &compiledNode{kind: kindCompare, op: "==", leftTok: "false", rightTok: "true"}
	}
	evalCompileCache.Store(expanded, node)
	return node
}

// compileExpr 编译表达式为 AST
// 递归解析顶层 || 和 &&，叶子节点解析为 compare/gFunc/func/eval/in
func (me *MatcherEngine) compileExpr(expr string) *compiledNode {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil
	}

	// 去除最外层配对括号
	expr = stripOuterParens(expr)

	// 查找顶层 || 或 &&
	orPos, andPos := me.findTopLevelOps(expr)
	if orPos >= 0 {
		return &compiledNode{
			kind:  kindOr,
			left:  me.compileExpr(expr[:orPos]),
			right: me.compileExpr(expr[orPos+2:]),
		}
	}
	if andPos >= 0 {
		return &compiledNode{
			kind:  kindAnd,
			left:  me.compileExpr(expr[:andPos]),
			right: me.compileExpr(expr[andPos+2:]),
		}
	}

	// 叶子：g() 函数
	if strings.HasPrefix(expr, "g(") && strings.HasSuffix(expr, ")") {
		return me.compileGFunc(expr)
	}

	// 叶子：eval() 函数
	if strings.HasPrefix(expr, "eval(") && strings.HasSuffix(expr, ")") {
		varName := strings.TrimSpace(expr[5 : len(expr)-1])
		return &compiledNode{kind: kindEval, evalVar: varName}
	}

	// 叶子：in 运算符（必须在 parseFunctionCall 之前，否则 r.sub in (...) 会被误识别为函数调用）
	if strings.Contains(expr, " in ") {
		return me.compileInExpr(expr)
	}

	// 叶子：自定义函数调用（keyMatch3、regexMatch 等）
	if fnName, fnArgs, ok := me.parseFunctionCall(expr); ok {
		return &compiledNode{kind: kindFunc, fnName: fnName, fnArgs: fnArgs}
	}

	// 叶子：== 比较
	if idx := strings.Index(expr, "=="); idx >= 0 {
		return &compiledNode{
			kind:     kindCompare,
			op:       "==",
			leftTok:  strings.TrimSpace(expr[:idx]),
			rightTok: strings.TrimSpace(expr[idx+2:]),
		}
	}

	// 叶子：!= 比较
	if idx := strings.Index(expr, "!="); idx >= 0 {
		return &compiledNode{
			kind:     kindCompare,
			op:       "!=",
			leftTok:  strings.TrimSpace(expr[:idx]),
			rightTok: strings.TrimSpace(expr[idx+2:]),
		}
	}

	// 无法识别的表达式，降级为恒 false
	return &compiledNode{kind: kindCompare, op: "==", leftTok: "false", rightTok: "true"}
}

// compileGFunc 编译 g() 函数调用
func (me *MatcherEngine) compileGFunc(expr string) *compiledNode {
	matches := gFuncRegex.FindStringSubmatch(expr)
	if len(matches) < 3 {
		return &compiledNode{kind: kindCompare, op: "==", leftTok: "false", rightTok: "true"}
	}
	node := &compiledNode{
		kind:     kindGFunc,
		leftTok:  strings.TrimSpace(matches[1]),
		rightTok: strings.TrimSpace(matches[2]),
	}
	if len(matches) >= 4 && matches[3] != "" {
		node.gDomain = strings.TrimSpace(matches[3])
	}
	return node
}

// compileInExpr 编译 in 运算符表达式
func (me *MatcherEngine) compileInExpr(expr string) *compiledNode {
	inIdx := strings.Index(expr, " in ")
	if inIdx < 0 {
		return &compiledNode{kind: kindCompare, op: "==", leftTok: "false", rightTok: "true"}
	}
	leftTok := strings.TrimSpace(expr[:inIdx])
	rightPart := strings.TrimSpace(expr[inIdx+4:])
	if !strings.HasPrefix(rightPart, "(") || !strings.HasSuffix(rightPart, ")") {
		return &compiledNode{kind: kindCompare, op: "==", leftTok: "false", rightTok: "true"}
	}
	inner := rightPart[1 : len(rightPart)-1]
	rawItems := strings.Split(inner, ",")
	items := make([]string, 0, len(rawItems))
	for _, item := range rawItems {
		item = strings.TrimSpace(item)
		item = strings.Trim(item, `"'`)
		items = append(items, item)
	}
	return &compiledNode{kind: kindIn, leftTok: leftTok, inItems: items}
}

// stripOuterParens 去除最外层配对括号
// 如 (r.act == p.act || p.act == "*") → r.act == p.act || p.act == "*"
func stripOuterParens(expr string) string {
	for {
		if !strings.HasPrefix(expr, "(") || !strings.HasSuffix(expr, ")") {
			break
		}
		depth := 0
		matched := true
		for i, ch := range expr {
			if ch == '(' {
				depth++
			} else if ch == ')' {
				depth--
			}
			if depth == 0 && i < len(expr)-1 {
				matched = false
				break
			}
		}
		if matched {
			expr = strings.TrimSpace(expr[1 : len(expr)-1])
		} else {
			break
		}
	}
	return expr
}

// computeEffectIndex 计算 p.eft 在 assertion.Tokens 中的索引
// 返回 -1 表示无 eft 字段，extractEffectFast 据此做 O(1) 提取
func computeEffectIndex(assertion *model.Assertion) int {
	if assertion == nil {
		return -1
	}
	for i, token := range assertion.Tokens {
		if token == "p.eft" {
			return i
		}
	}
	return -1
}

// extractEffectFast O(1) 效果提取（使用预计算的索引）
// 替代 extractEffect 的 O(n) token 遍历，热路径上每条匹配策略都调用
func extractEffectFast(policyLine []string, effectIdx int) string {
	if effectIdx >= 0 && effectIdx < len(policyLine) {
		return policyLine[effectIdx]
	}
	return "allow"
}
