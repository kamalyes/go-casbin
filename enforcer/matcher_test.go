/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-05-23 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-05-25 02:11:39
 * @FilePath: \go-casbin\enforcer\matcher_test.go
 * @Description: 测试匹配引擎核心逻辑
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */
package enforcer

import (
	"fmt"
	"testing"

	"github.com/kamalyes/go-casbin/model"
	"github.com/kamalyes/go-casbin/role"
	"github.com/kamalyes/go-logger"
	"github.com/stretchr/testify/assert"
)

// 测试用 matcher 表达式常量
const (
	matcherACL      = "r.sub == p.sub && r.obj == p.obj && r.act == p.act"
	matcherACLShort = "r.sub == p.sub && r.obj == p.obj"
	matcherSimple   = "r.sub == p.sub"
	matcherEval     = "eval(p.sub_rule)"
)

func newTestMatcherEngine() *MatcherEngine {
	return NewMatcherEngine(logger.NewLogger())
}

// ==================== 基本匹配测试 ====================

func TestMatcherEngine_Match_NoPolicies(t *testing.T) {
	me := newTestMatcherEngine()

	mc := &MatchContext{
		Request: map[string]interface{}{
			"r.sub": "alice", "r.obj": "data1", "r.act": "read",
		},
		Policies:    [][]string{},
		CustomFuncs: map[string]BuiltinFunc{},
	}

	// 无策略时，纯 ABAC 表达式匹配
	ok, effects, err := me.Match(mc, `r.sub == "alice"`)
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, []string{"allow"}, effects)

	// 不匹配的表达式
	ok, effects, err = me.Match(mc, `r.sub == "bob"`)
	assert.NoError(t, err)
	assert.False(t, ok)
	assert.Nil(t, effects)
}

func TestMatcherEngine_Match_BasicACL(t *testing.T) {
	me := newTestMatcherEngine()

	assertion := &model.Assertion{
		Tokens: []string{"p.sub", "p.obj", "p.act"},
	}

	mc := &MatchContext{
		Request: map[string]interface{}{
			"r.sub": "alice", "r.obj": "data1", "r.act": "read",
		},
		Policies: [][]string{
			{"alice", "data1", "read"},
			{"bob", "data2", "write"},
		},
		Assertion:   assertion,
		CustomFuncs: map[string]BuiltinFunc{},
	}

	ok, effects, err := me.Match(mc, matcherACL)
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.Contains(t, effects, "allow")
}

func TestMatcherEngine_Match_NoMatch(t *testing.T) {
	me := newTestMatcherEngine()

	assertion := &model.Assertion{
		Tokens: []string{"p.sub", "p.obj", "p.act"},
	}

	mc := &MatchContext{
		Request: map[string]interface{}{
			"r.sub": "alice", "r.obj": "data2", "r.act": "write",
		},
		Policies: [][]string{
			{"bob", "data2", "write"},
		},
		Assertion:   assertion,
		CustomFuncs: map[string]BuiltinFunc{},
	}

	ok, effects, err := me.Match(mc, matcherACL)
	assert.NoError(t, err)
	assert.False(t, ok)
	assert.Nil(t, effects)
}

// ==================== 角色继承测试 ====================

func TestMatcherEngine_Match_RoleInheritance(t *testing.T) {
	me := newTestMatcherEngine()

	rm := role.NewRoleManager(logger.NewLogger())
	rm.AddLink("alice", "admin")

	assertion := &model.Assertion{
		Tokens: []string{"p.sub", "p.obj", "p.act"},
	}

	mc := &MatchContext{
		Request: map[string]interface{}{
			"r.sub": "alice", "r.obj": "data1", "r.act": "read",
		},
		Policies: [][]string{
			{"admin", "data1", "read"},
		},
		Assertion:   assertion,
		RoleMgr:     rm,
		CustomFuncs: map[string]BuiltinFunc{},
	}

	ok, effects, err := me.Match(mc, "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act")
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.Contains(t, effects, "allow")
}

func TestMatcherEngine_Match_RoleInheritanceWithDomain(t *testing.T) {
	me := newTestMatcherEngine()

	rm := role.NewRoleManager(logger.NewLogger())
	rm.AddLink("alice", "admin", "tenant1")

	assertion := &model.Assertion{
		Tokens: []string{"p.sub", "p.obj", "p.act"},
	}

	mc := &MatchContext{
		Request: map[string]interface{}{
			"r.sub": "alice", "r.obj": "data1", "r.act": "read", "r.dom": "tenant1",
		},
		Policies: [][]string{
			{"admin", "data1", "read"},
		},
		Assertion:   assertion,
		RoleMgr:     rm,
		CustomFuncs: map[string]BuiltinFunc{},
	}

	ok, effects, err := me.Match(mc, "g(r.sub, p.sub, r.dom) && r.obj == p.obj && r.act == p.act")
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.Contains(t, effects, "allow")

	// 不同域不应该匹配
	mc2 := &MatchContext{
		Request: map[string]interface{}{
			"r.sub": "alice", "r.obj": "data1", "r.act": "read", "r.dom": "tenant2",
		},
		Policies: [][]string{
			{"admin", "data1", "read"},
		},
		Assertion:   assertion,
		RoleMgr:     rm,
		CustomFuncs: map[string]BuiltinFunc{},
	}

	ok, _, err = me.Match(mc2, "g(r.sub, p.sub, r.dom) && r.obj == p.obj && r.act == p.act")
	assert.NoError(t, err)
	assert.False(t, ok)
}

// ==================== 短路优化测试 ====================

func TestMatcherEngine_Match_ShortCircuit(t *testing.T) {
	me := newTestMatcherEngine()

	assertion := &model.Assertion{
		Tokens: []string{"p.sub", "p.obj", "p.act", "p.eft"},
	}

	mc := &MatchContext{
		Request: map[string]interface{}{
			"r.sub": "alice", "r.obj": "data1", "r.act": "read",
		},
		Policies: [][]string{
			{"alice", "data1", "read", "allow"},
			{"alice", "data1", "read", "deny"},
		},
		Assertion:    assertion,
		CustomFuncs:  map[string]BuiltinFunc{},
		ShortCircuit: true,
	}

	ok, effects, err := me.Match(mc, matcherACL)
	assert.NoError(t, err)
	assert.True(t, ok)
	// 短路优化：匹配到第一条 allow 后立即返回，不应包含 deny
	assert.Equal(t, 1, len(effects))
	assert.Equal(t, "allow", effects[0])
}

func TestMatcherEngine_Match_NoShortCircuit(t *testing.T) {
	me := newTestMatcherEngine()

	assertion := &model.Assertion{
		Tokens: []string{"p.sub", "p.obj", "p.act", "p.eft"},
	}

	mc := &MatchContext{
		Request: map[string]interface{}{
			"r.sub": "alice", "r.obj": "data1", "r.act": "read",
		},
		Policies: [][]string{
			{"alice", "data1", "read", "allow"},
			{"alice", "data1", "read", "deny"},
		},
		Assertion:    assertion,
		CustomFuncs:  map[string]BuiltinFunc{},
		ShortCircuit: false,
	}

	ok, effects, err := me.Match(mc, matcherACL)
	assert.NoError(t, err)
	assert.True(t, ok)
	// 无短路：应匹配所有策略
	assert.Equal(t, 2, len(effects))
}

// ==================== eval 表达式测试 ====================

func TestMatcherEngine_Match_EvalExpression(t *testing.T) {
	me := newTestMatcherEngine()

	assertion := &model.Assertion{
		Tokens: []string{"p.sub_rule", "p.obj", "p.act"},
	}

	mc := &MatchContext{
		Request: map[string]interface{}{
			"r.sub": "alice", "r.obj": "data1", "r.act": "read",
		},
		Policies: [][]string{
			{`r.sub == "alice"`, "data1", "read"},
		},
		Assertion:   assertion,
		CustomFuncs: map[string]BuiltinFunc{},
		HasEval:     true,
	}

	ok, effects, err := me.Match(mc, "eval(p.sub_rule) && r.obj == p.obj && r.act == p.act")
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.Contains(t, effects, "allow")
}

// ==================== 逻辑运算测试 ====================

func TestMatcherEngine_Match_OrExpression(t *testing.T) {
	me := newTestMatcherEngine()

	assertion := &model.Assertion{
		Tokens: []string{"p.sub", "p.obj", "p.act"},
	}

	mc := &MatchContext{
		Request: map[string]interface{}{
			"r.sub": "alice", "r.obj": "data1", "r.act": "read",
		},
		Policies: [][]string{
			{"admin", "data1", "read"},
		},
		Assertion:   assertion,
		CustomFuncs: map[string]BuiltinFunc{},
	}

	// r.sub == p.sub 为 false，但 r.act == p.act 为 true，|| 应该匹配
	ok, _, err := me.Match(mc, "r.sub == p.sub || r.act == p.act")
	assert.NoError(t, err)
	assert.True(t, ok)
}

func TestMatcherEngine_Match_AndExpression(t *testing.T) {
	me := newTestMatcherEngine()

	assertion := &model.Assertion{
		Tokens: []string{"p.sub", "p.obj", "p.act"},
	}

	mc := &MatchContext{
		Request: map[string]interface{}{
			"r.sub": "alice", "r.obj": "data1", "r.act": "read",
		},
		Policies: [][]string{
			{"alice", "data1", "write"},
		},
		Assertion:   assertion,
		CustomFuncs: map[string]BuiltinFunc{},
	}

	// r.sub == p.sub 为 true，但 r.act == p.act 为 false，&& 不应该匹配
	ok, _, err := me.Match(mc, "r.sub == p.sub && r.act == p.act")
	assert.NoError(t, err)
	assert.False(t, ok)
}

// ==================== in 运算符测试 ====================

func TestMatcherEngine_Match_InExpression(t *testing.T) {
	me := newTestMatcherEngine()

	mc := &MatchContext{
		Request: map[string]interface{}{
			"r.sub": "alice",
		},
		Policies:    [][]string{},
		CustomFuncs: map[string]BuiltinFunc{},
	}

	ok, _, err := me.Match(mc, `r.sub in ("alice","bob")`)
	assert.NoError(t, err)
	assert.True(t, ok)

	ok, _, err = me.Match(mc, `r.sub in ("charlie","bob")`)
	assert.NoError(t, err)
	assert.False(t, ok)
}

// ==================== 自定义函数测试 ====================

func TestMatcherEngine_Match_CustomFunction(t *testing.T) {
	me := newTestMatcherEngine()

	assertion := &model.Assertion{
		Tokens: []string{"p.sub", "p.obj", "p.act"},
	}

	mc := &MatchContext{
		Request: map[string]interface{}{
			"r.sub": "alice", "r.obj": "/v1/users/123", "r.act": "GET",
		},
		Policies: [][]string{
			{"alice", "/v1/users/*", "GET"},
		},
		Assertion: assertion,
		CustomFuncs: map[string]BuiltinFunc{
			"keyMatch3": func(args ...interface{}) (interface{}, error) {
				return true, nil // 简化测试
			},
		},
	}

	ok, _, err := me.Match(mc, "r.sub == p.sub && keyMatch3(r.obj, p.obj) && r.act == p.act")
	assert.NoError(t, err)
	assert.True(t, ok)
}

// ==================== extractEffect 测试 ====================

func TestMatcherEngine_ExtractEffect(t *testing.T) {
	me := newTestMatcherEngine()

	// 有 eft 字段
	assertion := &model.Assertion{
		Tokens: []string{"p.sub", "p.obj", "p.act", "p.eft"},
	}
	assert.Equal(t, "allow", me.extractEffect([]string{"alice", "data1", "read", "allow"}, assertion))
	assert.Equal(t, "deny", me.extractEffect([]string{"alice", "data1", "read", "deny"}, assertion))

	// 无 eft 字段，默认 allow
	assertionNoEft := &model.Assertion{
		Tokens: []string{"p.sub", "p.obj", "p.act"},
	}
	assert.Equal(t, "allow", me.extractEffect([]string{"alice", "data1", "read"}, assertionNoEft))

	// assertion 为 nil
	assert.Equal(t, "allow", me.extractEffect([]string{"alice", "data1", "read"}, nil))
}

// ==================== acquireVars/releaseVars 测试 ====================

func TestMatcherEngine_AcquireVars(t *testing.T) {
	me := newTestMatcherEngine()

	request := map[string]interface{}{
		"r.sub": "alice", "r.obj": "data1", "r.act": "read",
	}

	// 无策略行
	vars := me.acquireVars(request, nil, nil)
	assert.Equal(t, "alice", vars["r.sub"])
	assert.Equal(t, "data1", vars["r.obj"])

	// 有策略行
	assertion := &model.Assertion{
		Tokens: []string{"p.sub", "p.obj", "p.act"},
	}
	vars = me.acquireVars(request, []string{"admin", "data1", "read"}, assertion)
	assert.Equal(t, "alice", vars["r.sub"])
	assert.Equal(t, "admin", vars["p.sub"])
	assert.Equal(t, "data1", vars["p.obj"])

	// 池化回环：归还后重新获取应为清空状态，无残留键
	releaseVars(vars)
	reused := me.acquireVars(map[string]interface{}{"r.sub": "bob"}, nil, nil)
	assert.Equal(t, "bob", reused["r.sub"])
	assert.NotContains(t, reused, "p.sub")
	assert.NotContains(t, reused, "r.obj")
	releaseVars(reused)
}

// ==================== resolveValue 测试 ====================

func TestMatcherEngine_ResolveValue(t *testing.T) {
	me := newTestMatcherEngine()

	vars := map[string]interface{}{
		"r.sub": "alice",
	}

	// 直接查找
	assert.Equal(t, "alice", me.resolveValue("r.sub", vars))

	// 字面量（双引号）
	assert.Equal(t, "hello", me.resolveValue(`"hello"`, vars))

	// 字面量（单引号）
	assert.Equal(t, "world", me.resolveValue(`'world'`, vars))

	// 不存在的变量返回原始 token
	assert.Equal(t, "unknown", me.resolveValue("unknown", vars))
}

// ==================== findTopLevelOp 测试 ====================

func TestMatcherEngine_FindTopLevelOp(t *testing.T) {
	me := newTestMatcherEngine()

	// 顶层 ||
	idx := me.findTopLevelOp("a || b", "||")
	assert.Equal(t, 2, idx)

	// 括号内的 || 不应被找到
	idx = me.findTopLevelOp("(a || b) && c", "||")
	assert.Equal(t, -1, idx)

	// 顶层 &&
	idx = me.findTopLevelOp("a && b", "&&")
	assert.Equal(t, 2, idx)

	// 不存在
	idx = me.findTopLevelOp("a == b", "||")
	assert.Equal(t, -1, idx)
}

// ==================== parseFunctionCall 测试 ====================

func TestMatcherEngine_ParseFunctionCall(t *testing.T) {
	me := newTestMatcherEngine()

	// 正常函数调用
	name, args, ok := me.parseFunctionCall("keyMatch3(r.obj, p.obj)")
	assert.True(t, ok)
	assert.Equal(t, "keyMatch3", name)
	assert.Equal(t, []string{"r.obj", "p.obj"}, args)

	// g 函数不应被解析
	_, _, ok = me.parseFunctionCall("g(r.sub, p.sub)")
	assert.False(t, ok)

	// eval 函数不应被解析
	_, _, ok = me.parseFunctionCall(matcherEval)
	assert.False(t, ok)

	// 非函数表达式
	_, _, ok = me.parseFunctionCall("r.sub == p.sub")
	assert.False(t, ok)
}

// ==================== expandEval 测试 ====================

func TestMatcherEngine_ExpandEval(t *testing.T) {
	me := newTestMatcherEngine()

	vars := map[string]interface{}{
		"p.sub_rule": `r.sub == "alice"`,
	}

	result := me.expandEval("eval(p.sub_rule) && r.obj == p.obj", vars)
	assert.Contains(t, result, `r.sub == "alice"`)
	assert.Contains(t, result, "r.obj == p.obj")

	// 不存在的变量保持原样
	result = me.expandEval("eval(p.unknown)", vars)
	assert.Contains(t, result, "eval(p.unknown)")
}

// ==================== valueToString 测试 ====================

func TestValueToString(t *testing.T) {
	// string 类型：零分配直接返回
	assert.Equal(t, "hello", valueToString("hello"))

	// nil：返回空字符串
	assert.Equal(t, "", valueToString(nil))

	// 其他类型：走 fmt.Sprintf
	assert.Equal(t, "42", valueToString(42))
	assert.Equal(t, "true", valueToString(true))
}

// ==================== resolveValue 测试 ====================

func TestResolveValue_DirectLookup(t *testing.T) {
	me := newTestMatcherEngine()
	vars := map[string]interface{}{"r.sub": "alice"}

	result := me.resolveValue("r.sub", vars)
	assert.Equal(t, "alice", result)
}

func TestResolveValue_LiteralString(t *testing.T) {
	me := newTestMatcherEngine()
	vars := map[string]interface{}{}

	// 双引号字面量
	result := me.resolveValue(`"hello"`, vars)
	assert.Equal(t, "hello", result)

	// 单引号字面量
	result = me.resolveValue(`'world'`, vars)
	assert.Equal(t, "world", result)
}

func TestResolveValue_UnknownToken(t *testing.T) {
	me := newTestMatcherEngine()
	vars := map[string]interface{}{}

	// 未知 token 直接返回自身
	result := me.resolveValue("unknown", vars)
	assert.Equal(t, "unknown", result)
}

func TestResolveValue_NestedProperty(t *testing.T) {
	me := newTestMatcherEngine()
	// 模拟嵌套属性：r.obj 是一个 map，访问 r.obj.name
	vars := map[string]interface{}{
		"r.obj": map[string]interface{}{"name": "data1"},
	}

	result := me.resolveValue("r.obj.name", vars)
	assert.Equal(t, "data1", result)
}

// ==================== containsDangerousExpr 测试 ====================

func TestContainsDangerousExpr(t *testing.T) {
	tests := []struct {
		name      string
		expr      string
		dangerous bool
	}{
		{"safe expression", `r.sub == "alice"`, false},
		{"os injection", `os.Getenv("SECRET")`, true},
		{"runtime injection", `runtime.GOMAXPROCS(0)`, true},
		{"exec injection", `exec("rm -rf /")`, true},
		{"system injection", `system("ls")`, true},
		{"import injection", `import("os")`, true},
		{"panic injection", `panic("crash")`, true},
		{"recover injection", `recover()`, true},
		{"unsafe injection", `unsafe.Pointer(nil)`, true},
		{"reflect injection", `reflect.ValueOf(x)`, true},
		{"syscall injection", `syscall.Exit(1)`, true},
		{"case insensitive", `OS.GETENV("x")`, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.dangerous, containsDangerousExpr(tt.expr))
		})
	}
}

// ==================== expandEval 安全测试 ====================

func TestExpandEval_DangerousExpression(t *testing.T) {
	me := newTestMatcherEngine()
	vars := map[string]interface{}{
		"p.sub_rule": `os.Getenv("SECRET")`,
	}

	result := me.expandEval(matcherEval, vars)
	assert.Equal(t, "false", result, "dangerous eval expression should be blocked")
}

// ==================== resolveValue 补充测试 ====================

func TestResolveValue_LiteralWithQuotes(t *testing.T) {
	me := newTestMatcherEngine()
	vars := map[string]interface{}{}

	// 双引号字面量
	result := me.resolveValue(`"hello"`, vars)
	assert.Equal(t, "hello", result)

	// 单引号字面量
	result = me.resolveValue(`'world'`, vars)
	assert.Equal(t, "world", result)
}

func TestResolveValue_NestedMultiLevel(t *testing.T) {
	me := newTestMatcherEngine()

	// 多级嵌套属性
	type Address struct {
		City string
	}
	type User struct {
		Name    string
		Address Address
	}

	vars := map[string]interface{}{
		"r.obj": User{Name: "alice", Address: Address{City: "Beijing"}},
	}

	// 二级属性访问
	result := me.resolveValue("r.obj.Name", vars)
	assert.Equal(t, "alice", result)

	result = me.resolveValue("r.obj.Address.City", vars)
	assert.Equal(t, "Beijing", result)
}

func TestResolveValue_FallbackToToken(t *testing.T) {
	me := newTestMatcherEngine()
	vars := map[string]interface{}{}

	// 不存在的 token 直接返回
	result := me.resolveValue("unknown_token", vars)
	assert.Equal(t, "unknown_token", result)
}

// ==================== IsFiltered / SetModel 测试 ====================

func TestIsFiltered(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)
	assert.False(t, e.IsFiltered())
}

func TestSetModel(t *testing.T) {
	e := newTestEnforcer(t, aclModelPath, aclPolicyPath)

	newModel := model.NewModel(logger.NoLogger)
	_ = newModel.AddDef("r", "sub, obj, act")
	_ = newModel.AddDef("p", "sub, obj, act")
	_ = newModel.AddDef("e", "some(where (p.eft == allow))")
	_ = newModel.AddDef("m", matcherACL)

	e.SetModel(newModel)
	assert.Equal(t, newModel, e.GetModel())
}

func TestExpandEval_SafeExpression(t *testing.T) {
	me := newTestMatcherEngine()
	vars := map[string]interface{}{
		"p.sub_rule": `r.sub == "admin"`,
	}

	result := me.expandEval(matcherEval, vars)
	assert.Equal(t, `r.sub == "admin"`, result)
}

func TestExpandEval_UnknownVariable(t *testing.T) {
	me := newTestMatcherEngine()
	vars := map[string]interface{}{}

	result := me.expandEval("eval(p.unknown)", vars)
	assert.Equal(t, "eval(p.unknown)", result, "unknown variable should remain unchanged")
}

// ==================== matchSingleSegment 测试 ====================

func TestMatchSingleSegment_NoPolicies(t *testing.T) {
	me := newTestMatcherEngine()

	mc := &MatchContext{
		Request:      map[string]interface{}{"r.sub": "alice"},
		Policies:     [][]string{},
		CustomFuncs:  map[string]BuiltinFunc{},
		ShortCircuit: true,
	}

	ok, effects, err := me.matchSingleSegment(mc, `r.sub == "alice"`, nil, nil, nil)
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, []string{"allow"}, effects)
}

func TestMatchSingleSegment_WithPolicies(t *testing.T) {
	me := newTestMatcherEngine()

	assertion := &model.Assertion{
		Tokens: []string{"p.sub", "p.obj"},
	}

	mc := &MatchContext{
		Request: map[string]interface{}{"r.sub": "alice", "r.obj": "data1"},
		Policies: [][]string{
			{"admin", "data1"},
			{"alice", "data1"},
		},
		Assertion:    assertion,
		CustomFuncs:  map[string]BuiltinFunc{},
		ShortCircuit: true,
	}

	ok, effects, err := me.matchSingleSegment(mc, matcherACLShort, mc.Policies, assertion, nil)
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.Contains(t, effects, "allow")
}

func TestMatchSingleSegment_ShortCircuit(t *testing.T) {
	me := newTestMatcherEngine()

	assertion := &model.Assertion{
		Tokens: []string{"p.sub", "p.obj"},
	}

	mc := &MatchContext{
		Request: map[string]interface{}{"r.sub": "alice", "r.obj": "data1"},
		Policies: [][]string{
			{"alice", "data1"},
			{"bob", "data1"},
		},
		Assertion:    assertion,
		CustomFuncs:  map[string]BuiltinFunc{},
		ShortCircuit: true,
	}

	ok, effects, err := me.matchSingleSegment(mc, matcherACLShort, mc.Policies, assertion, nil)
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.Len(t, effects, 1, "short circuit should stop at first allow")
}

// ==================== evaluateRoleFunction 测试 ====================

func TestEvaluateRoleFunction_NilRoleMgr(t *testing.T) {
	me := newTestMatcherEngine()

	// 无角色管理器时，直接比较名字
	assert.True(t, me.evaluateRoleFunction("alice", "alice", nil))
	assert.False(t, me.evaluateRoleFunction("alice", "bob", nil))
}

func TestEvaluateRoleFunction_WithRoleMgr(t *testing.T) {
	me := newTestMatcherEngine()
	rm := role.NewRoleManager(logger.NoLogger)
	_ = rm.AddLink("alice", "admin")

	assert.True(t, me.evaluateRoleFunction("alice", "admin", rm))
	assert.False(t, me.evaluateRoleFunction("alice", "superadmin", rm))
}

func TestEvaluateRoleFunctionWithDomain(t *testing.T) {
	me := newTestMatcherEngine()
	rm := role.NewRoleManager(logger.NoLogger)
	_ = rm.AddLink("alice", "admin", "tenant1")

	assert.True(t, me.evaluateRoleFunctionWithDomain("alice", "admin", "tenant1", rm))
	assert.False(t, me.evaluateRoleFunctionWithDomain("alice", "admin", "tenant2", rm))
}

func TestEvaluateRoleFunctionWithDomain_NilRoleMgr(t *testing.T) {
	me := newTestMatcherEngine()

	assert.True(t, me.evaluateRoleFunctionWithDomain("alice", "alice", "tenant1", nil))
	assert.False(t, me.evaluateRoleFunctionWithDomain("alice", "bob", "tenant1", nil))
}

// ==================== evalExpr 补充测试 ====================

func TestEvalExpr_EmptyExpr(t *testing.T) {
	me := newTestMatcherEngine()
	assert.False(t, me.evalExpr("", nil, nil))
}

func TestEvalExpr_NestedParentheses(t *testing.T) {
	me := newTestMatcherEngine()
	vars := map[string]interface{}{"r.sub": "alice", "p.sub": "alice"}
	// 多层括号嵌套
	assert.True(t, me.evalExpr("(((r.sub == p.sub)))", vars, nil))
}

func TestEvalExpr_OrAndMixed(t *testing.T) {
	me := newTestMatcherEngine()
	vars := map[string]interface{}{"r.sub": "alice", "p.sub": "alice", "r.obj": "data1", "p.obj": "data2"}
	// || 和 && 混合：r.sub == p.sub 为 true，短路返回 true
	assert.True(t, me.evalExpr("r.sub == p.sub || r.obj == p.obj", vars, nil))
}

func TestEvalExpr_AndTrue(t *testing.T) {
	me := newTestMatcherEngine()
	vars := map[string]interface{}{"r.sub": "alice", "p.sub": "alice", "r.obj": "data1", "p.obj": "data1"}
	assert.True(t, me.evalExpr("r.sub == p.sub && r.obj == p.obj", vars, nil))
}

func TestEvalExpr_AndFalse(t *testing.T) {
	me := newTestMatcherEngine()
	vars := map[string]interface{}{"r.sub": "alice", "p.sub": "alice", "r.obj": "data1", "p.obj": "data2"}
	assert.False(t, me.evalExpr("r.sub == p.sub && r.obj == p.obj", vars, nil))
}

func TestEvalExpr_NotEqual(t *testing.T) {
	me := newTestMatcherEngine()
	vars := map[string]interface{}{"r.sub": "alice", "p.sub": "bob"}
	assert.True(t, me.evalExpr("r.sub != p.sub", vars, nil))
	assert.False(t, me.evalExpr("r.sub != r.sub", vars, nil))
}

func TestEvalExpr_CustomFuncError(t *testing.T) {
	me := newTestMatcherEngine()
	me.customFuncs = map[string]BuiltinFunc{
		"failFunc": func(args ...interface{}) (interface{}, error) {
			return nil, fmt.Errorf("custom error")
		},
	}
	vars := map[string]interface{}{"r.sub": "alice", "p.sub": "bob"}
	// 自定义函数返回 error，应返回 false
	assert.False(t, me.evalExpr("failFunc(r.sub, p.sub)", vars, nil))
}

func TestEvalExpr_CustomFuncNonBoolReturn(t *testing.T) {
	me := newTestMatcherEngine()
	me.customFuncs = map[string]BuiltinFunc{
		"intFunc": func(args ...interface{}) (interface{}, error) {
			return 42, nil // 非 bool 返回
		},
	}
	vars := map[string]interface{}{"r.sub": "alice"}
	assert.False(t, me.evalExpr("intFunc(r.sub)", vars, nil))
}

func TestEvalExpr_InExpr(t *testing.T) {
	me := newTestMatcherEngine()
	vars := map[string]interface{}{"r.sub": "alice"}
	assert.True(t, me.evalExpr(`r.sub in ("alice","bob")`, vars, nil))
	assert.False(t, me.evalExpr(`r.sub in ("charlie","bob")`, vars, nil))
}

func TestEvalExpr_Fallback(t *testing.T) {
	me := newTestMatcherEngine()
	// 无法解析的表达式，返回 false
	assert.False(t, me.evalExpr("unknown_expr", nil, nil))
}

// ==================== parseFunctionCall 补充测试 ====================

func TestParseFunctionCall_NoLeftParen(t *testing.T) {
	me := newTestMatcherEngine()
	_, _, ok := me.parseFunctionCall("noParens")
	assert.False(t, ok)
}

func TestParseFunctionCall_NoRightParenAtEnd(t *testing.T) {
	me := newTestMatcherEngine()
	_, _, ok := me.parseFunctionCall("func(a, b")
	assert.False(t, ok)
}

func TestParseFunctionCall_EmptyName(t *testing.T) {
	me := newTestMatcherEngine()
	_, _, ok := me.parseFunctionCall("(a, b)")
	assert.False(t, ok)
}

func TestParseFunctionCall_GFunction(t *testing.T) {
	me := newTestMatcherEngine()
	_, _, ok := me.parseFunctionCall("g(r.sub, p.sub)")
	assert.False(t, ok)
}

func TestParseFunctionCall_EvalFunction(t *testing.T) {
	me := newTestMatcherEngine()
	_, _, ok := me.parseFunctionCall("eval(p.sub_rule)")
	assert.False(t, ok)
}

func TestParseFunctionCall_NestedArgs(t *testing.T) {
	me := newTestMatcherEngine()
	name, args, ok := me.parseFunctionCall("func(a, (b, c), d)")
	assert.True(t, ok)
	assert.Equal(t, "func", name)
	assert.Len(t, args, 3)
}

func TestParseFunctionCall_NoArgs(t *testing.T) {
	me := newTestMatcherEngine()
	_, _, ok := me.parseFunctionCall("func()")
	assert.False(t, ok) // 0 个参数应返回 false
}

func TestEvalInExpr_NoInKeyword(t *testing.T) {
	me := newTestMatcherEngine()
	vars := map[string]interface{}{"r.sub": "alice"}
	// 不含 " in " 的表达式应返回 false
	assert.False(t, me.evalInExpr("r.sub == \"alice\"", vars))
}

func TestEvalInExpr_NoParentheses(t *testing.T) {
	me := newTestMatcherEngine()
	vars := map[string]interface{}{"r.sub": "alice"}
	// 右侧没有括号应返回 false
	assert.False(t, me.evalInExpr("r.sub in alice,bob", vars))
}

func TestEvalGFunction_NoMatch(t *testing.T) {
	me := newTestMatcherEngine()
	vars := map[string]interface{}{"r.sub": "alice", "p.sub": "admin"}
	// g() 参数不足应返回 false
	assert.False(t, me.evalGFunction("g()", vars, nil))
}

func TestEvalGFunction_NilRoleMgr(t *testing.T) {
	me := newTestMatcherEngine()
	vars := map[string]interface{}{"r.sub": "alice", "p.sub": "alice"}
	// roleMgr 为 nil 时，name1 == name2 返回 true
	assert.True(t, me.evalGFunction("g(r.sub, p.sub)", vars, nil))
}

func TestEvalGFunction_NilRoleMgr_Different(t *testing.T) {
	me := newTestMatcherEngine()
	vars := map[string]interface{}{"r.sub": "alice", "p.sub": "admin"}
	// roleMgr 为 nil 时，name1 != name2 返回 false
	assert.False(t, me.evalGFunction("g(r.sub, p.sub)", vars, nil))
}

func TestEvalGFunction_WithDomain_NilRoleMgr(t *testing.T) {
	me := newTestMatcherEngine()
	vars := map[string]interface{}{"r.sub": "alice", "p.sub": "alice", "r.dom": "tenant1"}
	// roleMgr 为 nil 时，带域的 g() 也比较 name1 == name2
	assert.True(t, me.evalGFunction("g(r.sub, p.sub, r.dom)", vars, nil))
}
