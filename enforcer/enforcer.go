/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-05-23 09:16:22
 * @FilePath: \go-casbin\enforcer\enforcer.go
 * @Description: 核心执行器（含熔断、重试、状态机、完整RBAC/Management API）
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package enforcer

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/kamalyes/go-casbin/errors"
	"github.com/kamalyes/go-casbin/model"
	"github.com/kamalyes/go-casbin/policy"
	"github.com/kamalyes/go-casbin/role"
	"github.com/kamalyes/go-logger"
	"github.com/kamalyes/go-toolbox/pkg/breaker"
	"github.com/kamalyes/go-toolbox/pkg/mathx"
	"github.com/kamalyes/go-toolbox/pkg/retry"
	"github.com/kamalyes/go-toolbox/pkg/syncx"
)

// 执行器状态常量
const (
	StateReady    = "ready"    // 就绪状态：正常执行权限校验
	StateDisabled = "disabled" // 禁用状态：所有 Enforce 调用返回错误
	StateError    = "error"    // 错误状态：策略加载失败等异常
)

// 策略主体常量
const (
	SubjectAnonymous     = "anonymous"     // 匿名主体：公开接口策略使用
	SubjectAuthenticated = "authenticated" // 已认证主体：认证免鉴权策略使用
)

// Enforcer 核心执行器
// 整合模型、策略、角色、匹配器等模块，提供完整的权限校验能力
// 支持熔断器、重试、状态机、分布式通知等企业级特性
//
// 核心职责：
//   - 权限校验：Enforce/EnforceContext/EnforceEx 等方法
//   - 策略管理：AddPolicy/RemovePolicy/UpdatePolicy 等 CRUD 操作
//   - 角色管理：AddGroupingPolicy/GetRolesForUser 等角色继承操作
//   - 多租户：GetRolesForUserInDomain/GetPermissionsForUserInDomain 等域隔离操作
//   - 生命周期：状态机管理（Ready/Disabled/Error），熔断保护，自动重试
//   - 公开策略：IsPublicPolicy 检查路径是否允许匿名访问
//
// 使用方式：
//
//	e, _ := enforcer.NewEnforcer(
//	    enforcer.WithModelPath("resources/rbac_model.conf"),
//	    enforcer.WithPolicyPath("resources/rbac_policy.csv"),
//	    enforcer.WithLogger(log),
//	)
//	ok, _ := e.Enforce("alice", "data1", "read")
type Enforcer struct {
	mu       sync.RWMutex
	model    *model.Model          // 权限模型（PERM 元模型：r/p/g/e/m 五段）
	policy   *policy.Policy        // 策略管理器（加载/保存/增删改查策略）
	roleMgr  *role.RoleManager     // 角色管理器（RBAC 角色继承链、域支持、缓存）
	matcher  *MatcherEngine        // 匹配器引擎（基于 go-toolbox/matcher，支持 ACL/RBAC/ABAC）
	monitor  interface{}           // 监控接口（预留）
	watcher  *policy.PolicyWatcher // 文件变更监控器（单机模式，检测 CSV 文件变更）
	notifier policy.PolicyNotifier // 分布式策略变更通知器（Pub/Sub，多节点同步）

	stateMachine *syncx.StateMachine[string] // 状态机（管理执行器生命周期：Disabled→Ready→Error）
	breaker      *breaker.Circuit            // 熔断器（保护下游存储，防止级联故障）
	retry        *retry.Retry                // 重试器（指数退避+抖动，自动重试临时性故障）
	logger       logger.ILogger              // 日志记录器（基于 go-logger，支持结构化日志）

	customFuncs map[string]BuiltinFunc // 自定义匹配函数（可在 matcher 表达式中使用）

	rootAdapter policy.TransactionalAdapter // 根适配器（始终指向原始适配器，ExecuteInTransaction 用于开启事务，不受 SetAdapter 热替换影响）

	autoSave           bool       // 是否自动保存策略到适配器（AddPolicy/RemovePolicy 时自动持久化）
	autoBuildRoleLinks bool       // 是否自动构建角色继承链（添加 g 策略时自动更新角色关系）
	autoNotifyWatcher  bool       // 是否自动通知策略变更（含 Pub/Sub 广播到其他节点）
	enabled            bool       // 执行器是否启用（禁用时所有 Enforce 返回 EnforcerDisabledError）
	publicPolicies     [][]string // 公开接口策略（允许匿名访问的路径，不持久化到适配器）
	authSkipPolicies   [][]string // 认证免鉴权策略（需 JWT 但跳过 Casbin 的路径，不持久化到适配器）

	// 性能优化：缓存热路径上重复创建的对象
	effectEvaluator       *policy.EffectEvaluator   // 缓存效果评估器（effect 表达式在模型加载后不变）
	extraPolicies         map[string]*PolicySegment // 缓存额外策略段（p2/p3 等，策略变更时重建）
	matcherExpr           string                    // 缓存 matcher 表达式（模型加载后不变）
	requestTokens         []string                  // 缓存请求 token 列表（r 段定义，模型加载后不变）
	cachedPolicyAssertion *model.Assertion          // 缓存 p 段策略断言（模型加载后不变，避免每次 doEnforce map 查找）
	shortCircuit          bool                      // 缓存短路优化标志（effect 表达式不变时结果不变）
	hasEval               bool                      // 缓存 matcher 是否含 eval()（模型加载后不变，避免每次 doEnforce 重复扫描）
	hasGFunc              bool                      // 缓存 matcher 是否含 g()（模型加载后不变，避免每次 doEnforce 重复扫描）
	effectIndex           int                       // 缓存 p.eft 在 assertion.Tokens 中的索引（-1 无 eft 字段），extractEffect O(1)
	normalizeHost         func(string) string       // 自定义域名归一化函数（默认不处理）

	// Enforce 结果缓存：缓存 (sub,obj,act,...) → allow/deny，命中后跳过 RLock+matcher，O(1) 返回
	// 仅缓存全 string 的 rvals（ABAC 结构体不缓存）；策略变更时主动失效
	// 代际轮转实现：到期整代废弃 O(1) 回收，无需后台清理 goroutine 和全表扫描
	enforceCache *generationalEnforceCache
}

// NewEnforcer 创建核心执行器
// 通过 Option 函数模式配置模型路径、策略路径、日志、熔断器、重试器、通知器等
// 创建流程：加载模型 → 初始化角色管理器 → 初始化匹配器 → 加载策略 → 构建角色链 → 启动监控
func NewEnforcer(opts ...Option) (*Enforcer, error) {
	o := defaultOptions()
	for _, opt := range opts {
		opt(o)
	}

	if o.logger == nil {
		o.logger = logger.NewLogger()
	}

	sm := syncx.NewStateMachine[string](StateDisabled)
	sm.AllowTransition(StateDisabled, StateReady)
	sm.AllowTransition(StateReady, StateDisabled)
	sm.AllowTransition(StateReady, StateError)
	sm.AllowTransition(StateError, StateReady)
	sm.AllowTransition(StateError, StateDisabled)

	sm.OnTransition(func(from, to string) {
		o.logger.InfoKV("Enforcer state changed", "from", from, "to", to)
	})

	e := &Enforcer{
		logger:             o.logger,
		autoSave:           o.autoSave,
		autoBuildRoleLinks: true,
		autoNotifyWatcher:  true,
		enabled:            o.enabled,
		breaker:            o.breaker,
		retry:              o.retry,
		stateMachine:       sm,
		customFuncs:        make(map[string]BuiltinFunc),
		publicPolicies:     o.publicPolicies,
		authSkipPolicies:   o.authSkipPolicies,
		normalizeHost:      o.normalizeHost,
		enforceCache:       newGenerationalEnforceCache(),
	}

	e.registerBuiltinFunctions()

	if o.modelPath != "" {
		m, err := model.NewModelFromPath(o.modelPath, o.logger)
		if err != nil {
			return nil, errors.WrapError("failed to load model", err)
		}
		e.model = m
	} else if o.modelText != "" {
		m, err := model.NewModelFromText(o.modelText, o.logger)
		if err != nil {
			return nil, errors.WrapError("failed to parse model", err)
		}
		e.model = m
	} else {
		return nil, errors.NewModelLoadFailedError("no model source provided")
	}

	e.roleMgr = role.NewRoleManager(o.logger)
	e.matcher = NewMatcherEngine(o.logger)

	var adapter policy.Adapter
	if o.adapter != nil {
		adapter = o.adapter
	} else if o.policyPath != "" {
		adapter = policy.NewFileAdapter(o.policyPath)
	} else {
		adapter = policy.NewMemoryAdapter()
	}

	e.policy = policy.NewPolicy(e.model, adapter, o.logger)

	// 捕获根适配器引用，ExecuteInTransaction 始终用它开启事务
	// 注意：NewEnforcer 直接设置 e.policy 而非走 SetAdapter，所以这里必须显式捕获
	// 否则 e.rootAdapter 永远为 nil，ExecuteInTransaction 会走 fallback 路径，引发事务热替换竞态
	if ta, ok := adapter.(policy.TransactionalAdapter); ok {
		e.rootAdapter = ta
	}

	if err := e.policy.LoadPolicy(); err != nil {
		return nil, errors.WrapError("failed to load policy", err)
	}

	if e.autoBuildRoleLinks {
		e.loadRoleLinks()
	}

	// 初始化性能缓存：effect 评估器和 matcher 表达式在模型加载后不变
	e.initCachedFields()

	if o.watcher && o.policyPath != "" {
		e.watcher = policy.NewPolicyWatcher(o.policyPath, o.watchInterval, o.logger)
		e.watcher.AddCallback(func() {
			_ = e.ReloadPolicy()
		})
		_ = e.watcher.Start()
	}

	// 初始化分布式策略变更通知器
	if o.notifier != nil {
		e.notifier = o.notifier
		// 订阅策略变更事件，收到事件后自动重载策略
		if err := e.notifier.Subscribe(context.Background(), e.handlePolicyChange); err != nil {
			o.logger.WarnKV("Failed to subscribe policy notifier", "error", err.Error())
		} else {
			o.logger.InfoKV("Policy notifier subscribed successfully")
		}
	}

	if o.enabled {
		if err := sm.TransitionTo(StateReady); err != nil {
			o.logger.WarnKV("Failed to transition to ready state", "error", err.Error())
		}
	}

	// 加载公开接口策略（仅内存，不持久化到适配器）
	if len(o.publicPolicies) > 0 {
		e.publicPolicies = o.publicPolicies
		e.reloadPublicPoliciesUnlocked()
		o.logger.InfoKV("Public policies loaded", "count", len(o.publicPolicies))
	}

	// 加载认证免鉴权策略（仅内存，不持久化到适配器）
	if len(o.authSkipPolicies) > 0 {
		e.authSkipPolicies = o.authSkipPolicies
		e.reloadAuthSkipPoliciesUnlocked()
		o.logger.InfoKV("Auth-skip policies loaded", "count", len(o.authSkipPolicies))
	}

	o.logger.InfoKV("Enforcer created successfully",
		"model_sections", len(e.model.GetAssertions()),
		"auto_save", e.autoSave,
		"enabled", e.enabled,
	)

	return e, nil
}

// Close 关闭执行器，释放所有资源
// 停止文件监控器和分布式通知器
func (e *Enforcer) Close() {
	if e.watcher != nil {
		e.watcher.Stop()
	}
	if e.notifier != nil {
		_ = e.notifier.Close()
	}
	e.logger.InfoMsg("Enforcer closed")
}

// ==================== Enforcer API ====================

// Enforce 执行权限校验（不带 context）
// 内部调用 EnforceContext 并传入 context.Background()
func (e *Enforcer) Enforce(rvals ...interface{}) (bool, error) {
	return e.EnforceContext(context.Background(), rvals...)
}

// EnforceContext 执行权限校验（带 context）
// 核心校验流程：检查状态 → 缓存查询 → 构建请求 → 匹配策略 → 评估效果 → 缓存回填
// 支持熔断器保护和重试机制
//
// 性能优化：Enforce 结果缓存
//   - 仅缓存全 string 的 rvals（ABAC 结构体不缓存）
//   - 命中后跳过 RLock+matcher，O(1) 返回，热路径吞吐提升 5-10 倍
//   - 策略变更时通过版本号 O(1) 失效（invalidateExtraPoliciesCache 联动）
//   - 分布式场景下各实例独立缓存，通过短 TTL 容忍秒级不一致
func (e *Enforcer) EnforceContext(ctx context.Context, rvals ...interface{}) (bool, error) {
	if !e.enabled {
		return false, errors.NewEnforcerDisabledError("enforcer is disabled")
	}

	if e.stateMachine.CurrentState() != StateReady {
		return false, errors.NewEnforcerNotReadyError(e.stateMachine.CurrentState())
	}

	// context 已取消时快速返回，避免在 RLock 或 matcher 上无谓阻塞
	// 典型场景：gRPC 调用方 context 超时（gateway 3s deadline），此时 AC 服务应立即放弃处理
	if ctx != nil && ctx.Err() != nil {
		return false, ctx.Err()
	}

	// Enforce 结果缓存：命中后 O(1) 返回，跳过 RLock+matcher
	// 仅缓存全 string 的 rvals（ABAC 结构体不缓存）
	// 版本号不匹配时视为失效（策略已变更），不返回旧结果
	if cacheKey, cacheable := buildEnforceCacheKey(rvals); cacheable {
		if entry, hit := e.enforceCache.Load(cacheKey); hit {
			return entry.result, nil
		}
		// 缓存 miss，走 enforceCore 后回填（TTL 与版本号由缓存内部管理）
		result, err := e.enforceCore(ctx, rvals...)
		if err == nil {
			e.enforceCache.Store(cacheKey, result)
		}
		return result, err
	}

	// ABAC 等不可缓存场景，直接走核心流程
	return e.enforceCore(ctx, rvals...)
}

// enforceCore Enforce 核心校验流程（熔断器/重试/doEnforce）
// 由 EnforceContext 在缓存 miss 时调用
func (e *Enforcer) enforceCore(ctx context.Context, rvals ...interface{}) (bool, error) {
	enforceFn := func() (bool, error) {
		return e.doEnforce(ctx, rvals...)
	}

	if e.breaker != nil {
		result, err := e.executeWithBreaker(enforceFn)
		if err != nil {
			e.logger.ErrorContextKV(ctx, "Enforce failed with breaker", "error", err.Error())
			return false, err
		}
		return result, nil
	}

	if e.retry != nil {
		var result bool
		var err error
		retryErr := e.retry.Do(func() error {
			result, err = e.doEnforce(ctx, rvals...)
			return err
		})
		if retryErr != nil {
			return false, errors.NewEnforcerRetryExhaustedError(retryErr.Error())
		}
		return result, nil
	}

	result, err := enforceFn()
	if err != nil {
		e.logger.ErrorContextKV(ctx, "Enforce failed", "error", err.Error())
		return false, err
	}

	return result, nil
}

// enforceCacheKeyPool 复用 []byte 缓冲区，减少 Enforce 缓存命中热路径上的内存分配
// 使用 go-toolbox/syncx.Pool 泛型池，类型安全（直接返回 *[]byte，无需类型断言）
// string(b) 会显式拷贝，Put 后结果字符串不受后续复用影响
var enforceCacheKeyPool = syncx.NewPool(func() *[]byte {
	b := make([]byte, 0, 128)
	return &b
})

// requestMapPool 复用 request map，减少 doEnforce 热路径上的 map 分配
// 使用 go-toolbox/syncx.Pool 泛型池，类型安全（直接返回 map，无需类型断言）
// map 在 buildVariableMap 中被读取（值拷贝到 vars），doEnforce 结束后可安全复用
// 高并发场景下显著降低 GC 压力（50w QPS 时每秒 50w 次 map 分配）
var requestMapPool = syncx.NewPool(func() map[string]interface{} {
	return make(map[string]interface{}, 4)
})

// matchContextPool 复用 MatchContext，减少 doEnforce 热路径上的堆分配
// 每次 doEnforce 调用都需要一个 MatchContext，池化后零分配
// 所有字段在每次使用时被覆写，无需 clear
var matchContextPool = syncx.NewPool(func() *MatchContext {
	return &MatchContext{}
})

// buildEnforceCacheKey 构建 Enforce 结果缓存键
// 仅缓存全 string 的 rvals（ABAC 结构体不缓存），返回 (cacheKey, cacheable)
//
// 性能优化：
//   - 使用 sync.Pool 复用 []byte 缓冲区，避免每次分配
//   - string(b) 显式拷贝，确保 Put 后结果字符串安全
//   - 这是缓存命中路径（99% 场景）的最热函数，每次 Enforce 都会调用
func buildEnforceCacheKey(rvals []interface{}) (string, bool) {
	if len(rvals) == 0 {
		return "", false
	}
	bp := enforceCacheKeyPool.Get()
	b := (*bp)[:0]
	for _, rv := range rvals {
		s, ok := rv.(string)
		if !ok {
			*bp = b
			enforceCacheKeyPool.Put(bp)
			return "", false
		}
		b = append(b, s...)
		b = append(b, '|')
	}
	result := string(b) // 显式拷贝，Put 后安全
	*bp = b
	enforceCacheKeyPool.Put(bp)
	return result, true
}

// invalidateEnforceCache 使所有 Enforce 结果缓存失效
// 代际缓存内部通过版本号递增 + 两代重建实现 O(1) 失效，旧条目随 GC 回收
func (e *Enforcer) invalidateEnforceCache() {
	e.enforceCache.Invalidate()
}

// EnforceWithMatcher 使用自定义匹配表达式执行权限校验
func (e *Enforcer) EnforceWithMatcher(matcherExpr string, rvals ...interface{}) (bool, error) {
	return e.enforceWithMatcherExpr(matcherExpr, rvals...)
}

// EnforceEx 执行权限校验并返回匹配的策略
func (e *Enforcer) EnforceEx(rvals ...interface{}) (bool, []string, error) {
	return e.enforceExWithMatcherExpr("", rvals...)
}

// EnforceExWithMatcher 使用自定义匹配表达式执行权限校验并返回匹配的策略
func (e *Enforcer) EnforceExWithMatcher(matcherExpr string, rvals ...interface{}) (bool, []string, error) {
	return e.enforceExWithMatcherExpr(matcherExpr, rvals...)
}

// BatchEnforce 批量执行权限校验
// 共享一次读锁，避免每个请求重复获取/释放 RLock
func (e *Enforcer) BatchEnforce(requests [][]interface{}) ([]bool, error) {
	results := make([]bool, len(requests))

	e.mu.RLock()
	defer e.mu.RUnlock()

	for i, req := range requests {
		result, err := e.doEnforce(context.Background(), req...)
		if err != nil {
			return nil, err
		}
		results[i] = result
	}
	return results, nil
}

// BatchEnforceWithMatcher 使用自定义匹配表达式批量执行权限校验
// 共享一次读锁，避免每个请求重复获取/释放 RLock
func (e *Enforcer) BatchEnforceWithMatcher(matcherExpr string, requests [][]interface{}) ([]bool, error) {
	results := make([]bool, len(requests))

	e.mu.RLock()
	defer e.mu.RUnlock()

	for i, req := range requests {
		result, err := e.doEnforceWithMatcher(context.Background(), matcherExpr, req...)
		if err != nil {
			return nil, err
		}
		results[i] = result
	}
	return results, nil
}

func (e *Enforcer) enforceWithMatcherExpr(matcherExpr string, rvals ...interface{}) (bool, error) {
	if !e.enabled {
		return false, errors.NewEnforcerDisabledError("enforcer is disabled")
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.doEnforceWithMatcher(context.Background(), matcherExpr, rvals...)
}

// doEnforceWithMatcher 不加锁的 EnforceWithMatcher 内部实现
// 调用方必须已持有 e.mu 读锁
func (e *Enforcer) doEnforceWithMatcher(ctx context.Context, matcherExpr string, rvals ...interface{}) (bool, error) {
	if err := e.validateRequest(rvals); err != nil {
		return false, err
	}

	request := e.buildRequest(rvals...)
	if request == nil {
		return false, errors.NewModelInvalidError("invalid request parameters")
	}
	// 归还 request map 到 pool（matcher 内部已将值拷贝到 vars，不持有 request 引用）
	defer e.releaseRequest(request)

	expr := matcherExpr
	if expr == "" {
		expr = e.matcherExpr
	}
	if expr == "" {
		return false, errors.NewModelInvalidError("matcher expression is empty")
	}

	matched, matchedEffects, err := e.evaluateMatch(request, expr, strings.Contains(expr, policy.EvalFunc), strings.Contains(expr, policy.GFunc))
	if err != nil {
		return false, err
	}

	if !matched {
		return false, nil
	}

	effectResult, err := e.evaluateEffectFromResultsCached(matchedEffects)
	if err != nil {
		return false, err
	}

	return bool(effectResult), nil
}

func (e *Enforcer) enforceExWithMatcherExpr(matcherExpr string, rvals ...interface{}) (bool, []string, error) {
	if !e.enabled {
		return false, nil, errors.NewEnforcerDisabledError("enforcer is disabled")
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	if err := e.validateRequest(rvals); err != nil {
		return false, nil, err
	}

	request := e.buildRequest(rvals...)
	if request == nil {
		return false, nil, errors.NewModelInvalidError("invalid request parameters")
	}
	// 归还 request map 到 pool（matcher 内部已将值拷贝到 vars，不持有 request 引用）
	defer e.releaseRequest(request)

	expr := matcherExpr
	if expr == "" {
		expr = e.matcherExpr
	}
	if expr == "" {
		return false, nil, errors.NewModelInvalidError("matcher expression is empty")
	}

	matched, matchedEffects, err := e.evaluateMatch(request, expr, strings.Contains(expr, policy.EvalFunc), strings.Contains(expr, policy.GFunc))
	if err != nil {
		return false, nil, err
	}

	if !matched {
		return false, nil, nil
	}

	var matchedPolicy []string
	if len(matchedEffects) > 0 {
		matchedPolicy = matchedEffects
	}
	return true, matchedPolicy, nil
}

// ==================== Custom Function ====================

// ==================== 自定义函数 API ====================

func (e *Enforcer) registerBuiltinFunctions() {
	builtins := map[string]BuiltinFunc{
		"keyMatch":   KeyMatchFunc,
		"keyMatch2":  KeyMatch2Func,
		"keyMatch3":  KeyMatch3Func,
		"regexMatch": RegexMatchFunc,
		"ipMatch":    IPMatchFunc,
		"globMatch":  GlobMatchFunc,
	}
	for name, fn := range builtins {
		e.customFuncs[name] = fn
	}
}

// AddFunction 添加自定义匹配函数
// 自定义函数可在 matcher 表达式中使用，扩展匹配能力
// 例如：添加 keyMatch2 函数用于 URL 路径匹配
func (e *Enforcer) AddFunction(name string, fn BuiltinFunc) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.customFuncs[name] = fn
	e.logger.InfoKV("Custom function added", "name", name)
}

// GetFunction 获取已注册的自定义匹配函数
func (e *Enforcer) GetFunction(name string) (BuiltinFunc, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	fn, ok := e.customFuncs[name]
	return fn, ok
}

// withLockAndNotify 通用模板：锁内执行内存+DB 操作，锁外执行 NATS 通知
// 减少 notifyPolicyChange（网络 IO）的持锁时间，避免阻塞 Enforce 读操作
// fn 内不允许调用 notifyPolicyChange，由本方法在锁外统一处理
func (e *Enforcer) withLockAndNotify(fn func() error, eventType policy.ChangeEventType, ptype string, oldp, newp []string) error {
	e.mu.Lock()
	if err := fn(); err != nil {
		e.mu.Unlock()
		return err
	}
	e.mu.Unlock()

	e.notifyPolicyChange(eventType, ptype, oldp, newp)
	return nil
}

// ==================== 策略管理 API ====================

// AddPolicy 添加一条策略规则
// 同时写入适配器（autoSave）和通知其他节点（autoNotifyWatcher）
// 优化：notifyPolicyChange 移出锁外，减少锁内网络 IO 持锁时间
func (e *Enforcer) AddPolicy(params ...string) error {
	return e.withLockAndNotify(func() error {
		if err := e.validatePolicyRule(model.SectionPolicyDefinition, policy.PTypePolicy, params); err != nil {
			return err
		}
		if err := e.policy.AddPolicy(model.SectionPolicyDefinition, policy.PTypePolicy, params); err != nil {
			return err
		}
		e.invalidateExtraPoliciesCache()
		return nil
	}, policy.EventTypePolicyAdded, policy.PTypePolicy, nil, params)
}

// AddPolicies 批量添加策略规则
func (e *Enforcer) AddPolicies(rules [][]string) error {
	return e.withLockAndNotify(func() error {
		for _, rule := range rules {
			if err := e.validatePolicyRule(model.SectionPolicyDefinition, policy.PTypePolicy, rule); err != nil {
				return err
			}
		}
		if err := e.policy.AddPolicies(model.SectionPolicyDefinition, policy.PTypePolicy, rules); err != nil {
			return err
		}
		e.invalidateExtraPoliciesCache()
		return nil
	}, policy.EventTypePolicyAdded, policy.PTypePolicy, nil, nil)
}

// AddPoliciesEx 批量添加策略规则（忽略已存在的规则）
func (e *Enforcer) AddPoliciesEx(rules [][]string) error {
	return e.withLockAndNotify(func() error {
		if err := e.policy.AddPoliciesEx(model.SectionPolicyDefinition, policy.PTypePolicy, rules); err != nil {
			return err
		}
		e.invalidateExtraPoliciesCache()
		return nil
	}, policy.EventTypePolicyAdded, policy.PTypePolicy, nil, nil)
}

// AddNamedPolicy 添加指定类型的策略规则
func (e *Enforcer) AddNamedPolicy(ptype string, params ...string) error {
	return e.withLockAndNotify(func() error {
		if err := e.policy.AddPolicy(model.SectionPolicyDefinition, ptype, params); err != nil {
			return err
		}
		e.invalidateExtraPoliciesCache()
		return nil
	}, policy.EventTypePolicyAdded, ptype, nil, params)
}

// AddNamedPolicies 批量添加指定类型的策略规则
func (e *Enforcer) AddNamedPolicies(ptype string, rules [][]string) error {
	return e.withLockAndNotify(func() error {
		if err := e.policy.AddPolicies(model.SectionPolicyDefinition, ptype, rules); err != nil {
			return err
		}
		e.invalidateExtraPoliciesCache()
		return nil
	}, policy.EventTypePolicyAdded, ptype, nil, nil)
}

// AddNamedPoliciesEx 批量添加指定类型的策略规则（忽略已存在的规则）
func (e *Enforcer) AddNamedPoliciesEx(ptype string, rules [][]string) error {
	return e.withLockAndNotify(func() error {
		if err := e.policy.AddPoliciesEx(model.SectionPolicyDefinition, ptype, rules); err != nil {
			return err
		}
		e.invalidateExtraPoliciesCache()
		return nil
	}, policy.EventTypePolicyAdded, ptype, nil, nil)
}

// RemovePolicy 删除一条策略规则
func (e *Enforcer) RemovePolicy(params ...string) error {
	return e.withLockAndNotify(func() error {
		// Policy 层已统一处理内存删除和适配器持久化（含回滚），无需 Enforcer 层重复写入
		if err := e.policy.RemovePolicy(model.SectionPolicyDefinition, policy.PTypePolicy, params); err != nil {
			return err
		}

		e.invalidateExtraPoliciesCache()
		return nil
	}, policy.EventTypePolicyRemoved, policy.PTypePolicy, params, nil)
}

// RemovePolicies 批量删除策略规则
func (e *Enforcer) RemovePolicies(rules [][]string) error {
	return e.withLockAndNotify(func() error {
		// Policy 层已统一处理内存删除和适配器持久化（含回滚），无需 Enforcer 层重复写入
		if err := e.policy.RemovePolicies(model.SectionPolicyDefinition, policy.PTypePolicy, rules); err != nil {
			return err
		}

		e.invalidateExtraPoliciesCache()
		return nil
	}, policy.EventTypePolicyRemoved, policy.PTypePolicy, nil, nil)
}

// RemoveFilteredPolicy 按字段过滤删除策略规则
// fieldIndex: 起始字段索引，fieldValues: 过滤字段值
func (e *Enforcer) RemoveFilteredPolicy(fieldIndex int, fieldValues ...string) error {
	return e.withLockAndNotify(func() error {
		e.invalidateExtraPoliciesCache()
		if err := e.policy.RemoveFilteredPolicy(model.SectionPolicyDefinition, policy.PTypePolicy, fieldIndex, fieldValues...); err != nil {
			return err
		}
		return nil
	}, policy.EventTypePolicyRemoved, policy.PTypePolicy, nil, nil)
}

// RemoveNamedPolicy 删除指定类型的策略规则
func (e *Enforcer) RemoveNamedPolicy(ptype string, params ...string) error {
	return e.withLockAndNotify(func() error {
		// Policy 层已统一处理内存删除和适配器持久化（含回滚），无需 Enforcer 层重复写入
		if err := e.policy.RemovePolicy(model.SectionPolicyDefinition, ptype, params); err != nil {
			return err
		}

		e.invalidateExtraPoliciesCache()
		return nil
	}, policy.EventTypePolicyRemoved, ptype, params, nil)
}

// RemoveNamedPolicies 批量删除指定类型的策略规则
func (e *Enforcer) RemoveNamedPolicies(ptype string, rules [][]string) error {
	return e.withLockAndNotify(func() error {
		if err := e.policy.RemovePolicies(model.SectionPolicyDefinition, ptype, rules); err != nil {
			return err
		}
		e.invalidateExtraPoliciesCache()
		return nil
	}, policy.EventTypePolicyRemoved, ptype, nil, nil)
}

// RemoveFilteredNamedPolicy 按字段过滤删除指定类型的策略规则
func (e *Enforcer) RemoveFilteredNamedPolicy(ptype string, fieldIndex int, fieldValues ...string) error {
	return e.withLockAndNotify(func() error {
		if err := e.policy.RemoveFilteredPolicy(model.SectionPolicyDefinition, ptype, fieldIndex, fieldValues...); err != nil {
			return err
		}
		e.invalidateExtraPoliciesCache()
		return nil
	}, policy.EventTypePolicyRemoved, ptype, nil, nil)
}

// UpdatePolicy 更新一条策略规则
func (e *Enforcer) UpdatePolicy(oldPolicy, newPolicy []string) error {
	return e.withLockAndNotify(func() error {
		e.invalidateExtraPoliciesCache()
		if err := e.policy.UpdatePolicy(model.SectionPolicyDefinition, policy.PTypePolicy, oldPolicy, newPolicy); err != nil {
			return err
		}
		return nil
	}, policy.EventTypePolicyAdded, policy.PTypePolicy, nil, nil)
}

// UpdatePolicies 批量更新策略规则
func (e *Enforcer) UpdatePolicies(oldPolicies, newPolicies [][]string) error {
	return e.withLockAndNotify(func() error {
		e.invalidateExtraPoliciesCache()
		if err := e.policy.UpdatePolicies(model.SectionPolicyDefinition, policy.PTypePolicy, oldPolicies, newPolicies); err != nil {
			return err
		}
		return nil
	}, policy.EventTypePolicyAdded, policy.PTypePolicy, nil, nil)
}

// UpdateFilteredPolicies 按过滤条件更新策略规则
func (e *Enforcer) UpdateFilteredPolicies(newPolicies [][]string, fieldIndex int, fieldValues ...string) error {
	return e.withLockAndNotify(func() error {
		for _, rule := range newPolicies {
			if err := e.validatePolicyRule(model.SectionPolicyDefinition, policy.PTypePolicy, rule); err != nil {
				return err
			}
		}

		e.invalidateExtraPoliciesCache()
		if err := e.policy.UpdateFilteredPolicies(model.SectionPolicyDefinition, policy.PTypePolicy, newPolicies, fieldIndex, fieldValues...); err != nil {
			return err
		}
		return nil
	}, policy.EventTypePolicyAdded, policy.PTypePolicy, nil, nil)
}

// ==================== 角色分组策略 API ====================

// AddGroupingPolicy 添加角色分组策略（g 策略）
// 同时更新角色继承链、写入适配器和通知其他节点
func (e *Enforcer) AddGroupingPolicy(params ...string) error {
	return e.withLockAndNotify(func() error {
		if err := e.policy.AddPolicy(model.SectionRoleDefinition, policy.PTypeGrouping, params); err != nil {
			return err
		}

		if len(params) >= 2 && e.autoBuildRoleLinks {
			domain := make([]string, 0)
			if len(params) >= 3 {
				domain = append(domain, params[2])
			}
			if err := e.roleMgr.AddLink(params[0], params[1], domain...); err != nil {
				return err
			}
		}
		return nil
	}, policy.EventTypePolicyAdded, policy.PTypeGrouping, nil, params)
}

// AddGroupingPolicies 批量添加角色分组策略
func (e *Enforcer) AddGroupingPolicies(rules [][]string) error {
	return e.withLockAndNotify(func() error {
		if err := e.policy.AddPolicies(model.SectionRoleDefinition, policy.PTypeGrouping, rules); err != nil {
			return err
		}

		if e.autoBuildRoleLinks {
			for _, rule := range rules {
				if len(rule) >= 2 {
					domain := make([]string, 0)
					if len(rule) >= 3 {
						domain = append(domain, rule[2])
					}
					_ = e.roleMgr.AddLink(rule[0], rule[1], domain...)
				}
			}
		}
		return nil
	}, policy.EventTypePolicyAdded, policy.PTypeGrouping, nil, nil)
}

// AddGroupingPoliciesEx 批量添加角色分组策略（忽略已存在的规则）
func (e *Enforcer) AddGroupingPoliciesEx(rules [][]string) error {
	return e.withLockAndNotify(func() error {
		if err := e.policy.AddPoliciesEx(model.SectionRoleDefinition, policy.PTypeGrouping, rules); err != nil {
			return err
		}
		if e.autoBuildRoleLinks {
			for _, rule := range rules {
				if len(rule) >= 2 {
					domain := make([]string, 0)
					if len(rule) >= 3 {
						domain = append(domain, rule[2])
					}
					_ = e.roleMgr.AddLink(rule[0], rule[1], domain...)
				}
			}
		}
		return nil
	}, policy.EventTypePolicyAdded, policy.PTypeGrouping, nil, nil)
}

// RemoveGroupingPolicy 删除角色分组策略
// 同时更新角色继承链、从适配器删除和通知其他节点
func (e *Enforcer) RemoveGroupingPolicy(params ...string) error {
	return e.withLockAndNotify(func() error {
		if err := e.policy.RemovePolicy(model.SectionRoleDefinition, policy.PTypeGrouping, params); err != nil {
			return err
		}

		if len(params) >= 2 && e.autoBuildRoleLinks {
			domain := make([]string, 0)
			if len(params) >= 3 {
				domain = append(domain, params[2])
			}
			e.roleMgr.DeleteLink(params[0], params[1], domain...)
		}

		if e.autoSave && e.policy.GetAdapter() != nil {
			line := "g, " + strings.Join(params, ", ")
			if err := e.policy.GetAdapter().RemovePolicy(line); err != nil {
				return errors.WrapError("auto-remove grouping policy", err)
			}
		}
		return nil
	}, policy.EventTypePolicyRemoved, policy.PTypeGrouping, params, nil)
}

// RemoveGroupingPolicies 批量删除角色分组策略
func (e *Enforcer) RemoveGroupingPolicies(rules [][]string) error {
	return e.withLockAndNotify(func() error {
		if err := e.policy.RemovePolicies(model.SectionRoleDefinition, policy.PTypeGrouping, rules); err != nil {
			return err
		}

		if e.autoBuildRoleLinks {
			for _, rule := range rules {
				if len(rule) >= 2 {
					domain := make([]string, 0)
					if len(rule) >= 3 {
						domain = append(domain, rule[2])
					}
					e.roleMgr.DeleteLink(rule[0], rule[1], domain...)
				}
			}
		}

		if e.autoSave && e.policy.GetAdapter() != nil {
			if ba, ok := e.policy.GetAdapter().(policy.BatchAdapter); ok {
				var lines []string
				for _, rule := range rules {
					lines = append(lines, "g, "+strings.Join(rule, ", "))
				}
				if err := ba.RemovePolicies(lines); err != nil {
					return errors.WrapError("auto-remove grouping policies", err)
				}
			}
		}
		return nil
	}, policy.EventTypePolicyRemoved, policy.PTypeGrouping, nil, nil)
}

// RemoveFilteredGroupingPolicy 按字段过滤删除角色分组策略
// 同时清理角色管理器、适配器持久化和分布式通知
func (e *Enforcer) RemoveFilteredGroupingPolicy(fieldIndex int, fieldValues ...string) error {
	return e.withLockAndNotify(func() error {
		removed := e.policy.GetFilteredPolicy(policy.PTypeGrouping, fieldIndex, fieldValues...)

		if err := e.policy.RemoveFilteredPolicy(model.SectionRoleDefinition, policy.PTypeGrouping, fieldIndex, fieldValues...); err != nil {
			return err
		}

		if e.autoBuildRoleLinks {
			for _, rule := range removed {
				if len(rule) >= 2 {
					domain := make([]string, 0)
					if len(rule) >= 3 {
						domain = append(domain, rule[2])
					}
					e.roleMgr.DeleteLink(rule[0], rule[1], domain...)
				}
			}
		}
		return nil
	}, policy.EventTypePolicyRemoved, policy.PTypeGrouping, nil, nil)
}

// DeleteRoleAssignments 删除指定角色的所有分配关系
// 删除 g 段中第二列（角色列）匹配 roleName 的所有记录
// 同时清理角色管理器、适配器持久化和分布式通知
func (e *Enforcer) DeleteRoleAssignments(roleName string) error {
	return e.RemoveFilteredGroupingPolicy(1, roleName)
}

// ClearAllPolicies 清理所有策略和角色关系
// 用于租户删除等场景，彻底清空 enforcer 中的 p 段和 g 段数据
// 同时清理角色管理器、适配器持久化和分布式通知
func (e *Enforcer) ClearAllPolicies() error {
	return e.withLockAndNotify(func() error {
		e.model.ClearPolicies()
		e.roleMgr.Clear()
		e.invalidateExtraPoliciesCache()

		if e.autoSave && e.policy.GetAdapter() != nil {
			if err := e.policy.GetAdapter().SavePolicy(nil); err != nil {
				return errors.WrapError("clear all policies", err)
			}
		}
		return nil
	}, policy.EventTypePolicyRemoved, "", nil, nil)
}

// UpdateGroupingPolicy 更新角色分组策略
func (e *Enforcer) UpdateGroupingPolicy(oldRule, newRule []string) error {
	return e.withLockAndNotify(func() error {
		if err := e.policy.UpdatePolicy(model.SectionRoleDefinition, policy.PTypeGrouping, oldRule, newRule); err != nil {
			return err
		}

		if e.autoBuildRoleLinks {
			if len(oldRule) >= 2 {
				domain := make([]string, 0)
				if len(oldRule) >= 3 {
					domain = append(domain, oldRule[2])
				}
				e.roleMgr.DeleteLink(oldRule[0], oldRule[1], domain...)
			}
			if len(newRule) >= 2 {
				domain := make([]string, 0)
				if len(newRule) >= 3 {
					domain = append(domain, newRule[2])
				}
				_ = e.roleMgr.AddLink(newRule[0], newRule[1], domain...)
			}
		}
		return nil
	}, policy.EventTypePolicyAdded, policy.PTypeGrouping, nil, nil)
}

// UpdateGroupingPolicies 批量更新角色分组策略
func (e *Enforcer) UpdateGroupingPolicies(oldRules, newRules [][]string) error {
	return e.withLockAndNotify(func() error {
		if err := e.policy.UpdatePolicies(model.SectionRoleDefinition, policy.PTypeGrouping, oldRules, newRules); err != nil {
			return err
		}

		if e.autoBuildRoleLinks {
			for _, old := range oldRules {
				if len(old) >= 2 {
					domain := make([]string, 0)
					if len(old) >= 3 {
						domain = append(domain, old[2])
					}
					e.roleMgr.DeleteLink(old[0], old[1], domain...)
				}
			}
			for _, newR := range newRules {
				if len(newR) >= 2 {
					domain := make([]string, 0)
					if len(newR) >= 3 {
						domain = append(domain, newR[2])
					}
					_ = e.roleMgr.AddLink(newR[0], newR[1], domain...)
				}
			}
		}
		return nil
	}, policy.EventTypePolicyAdded, policy.PTypeGrouping, nil, nil)
}

// ==================== RBAC API ====================

// GetRolesForUser 获取用户的所有角色
func (e *Enforcer) GetRolesForUser(name string, domain ...string) []string {
	return e.roleMgr.GetRoles(name, domain...)
}

// GetUsersForRole 获取角色的所有用户
func (e *Enforcer) GetUsersForRole(name string, domain ...string) []string {
	return e.roleMgr.GetUsers(name, domain...)
}

// HasRoleForUser 判断用户是否拥有指定角色
func (e *Enforcer) HasRoleForUser(name, roleName string, domain ...string) bool {
	return e.roleMgr.HasLink(name, roleName, domain...)
}

// AddRoleForUser 为用户添加角色（同时写入适配器和通知其他节点）
// 优化：notifyPolicyChange 移出锁外，减少锁内网络 IO 持锁时间，避免阻塞 Enforce 读操作
func (e *Enforcer) AddRoleForUser(user, roleName string, domain ...string) error {
	return e.withLockAndNotify(func() error {
		if err := e.roleMgr.AddLink(user, roleName, domain...); err != nil {
			return err
		}

		if e.autoSave && e.policy.GetAdapter() != nil {
			line := "g, " + user + ", " + roleName
			if len(domain) > 0 {
				line += ", " + domain[0]
			}
			if err := e.policy.GetAdapter().AddPolicy(line); err != nil {
				e.roleMgr.DeleteLink(user, roleName, domain...)
				return errors.WrapError("auto-save role", err)
			}
		}
		return nil
	}, policy.EventTypePolicyAdded, policy.PTypeGrouping, nil, []string{user, roleName})
}

// DeleteRoleForUser 删除用户的角色（同时从适配器删除和通知其他节点）
// 优化：notifyPolicyChange 移出锁外，减少锁内网络 IO 持锁时间，避免阻塞 Enforce 读操作
func (e *Enforcer) DeleteRoleForUser(user, roleName string, domain ...string) error {
	return e.withLockAndNotify(func() error {
		e.roleMgr.DeleteLink(user, roleName, domain...)

		if e.autoSave && e.policy.GetAdapter() != nil {
			line := "g, " + user + ", " + roleName
			if len(domain) > 0 {
				line += ", " + domain[0]
			}
			if err := e.policy.GetAdapter().RemovePolicy(line); err != nil {
				return errors.WrapError("auto-remove role", err)
			}
		}
		return nil
	}, policy.EventTypePolicyRemoved, policy.PTypeGrouping, []string{user, roleName}, nil)
}

// DeleteRolesForUser 删除用户的所有角色
// 同时清理 g 段策略、适配器持久化和分布式通知
// 优化：notifyPolicyChange 移出锁外，减少锁内网络 IO 持锁时间，避免阻塞 Enforce 读操作
func (e *Enforcer) DeleteRolesForUser(user string, domain ...string) error {
	return e.withLockAndNotify(func() error {
		roles := e.roleMgr.GetRoles(user, domain...)
		if len(roles) == 0 {
			return nil
		}

		for _, r := range roles {
			e.roleMgr.DeleteLink(user, r, domain...)
		}

		if e.autoSave && e.policy.GetAdapter() != nil {
			if err := e.policy.RemoveFilteredPolicy(model.SectionRoleDefinition, policy.PTypeGrouping, 0, user); err != nil {
				e.logger.WarnKV("Failed to remove filtered grouping policy", "user", user, "error", err.Error())
			}
		}
		return nil
	}, policy.EventTypePolicyRemoved, policy.PTypeGrouping, []string{user}, nil)
}

// DeleteUser 删除用户及其所有角色关系
func (e *Enforcer) DeleteUser(user string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	existingGrouping := e.policy.GetFilteredPolicy(policy.PTypeGrouping, 0, user)
	for _, rule := range existingGrouping {
		if len(rule) >= 2 {
			domain := make([]string, 0)
			if len(rule) >= 3 {
				domain = append(domain, rule[2])
			}
			e.roleMgr.DeleteLink(rule[0], rule[1], domain...)
		}
	}

	return e.policy.RemoveFilteredPolicy(model.SectionRoleDefinition, policy.PTypeGrouping, 0, user)
}

// DeleteRole 删除角色及其所有用户关系
func (e *Enforcer) DeleteRole(roleName string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	existingGrouping := e.policy.GetFilteredPolicy(policy.PTypeGrouping, 1, roleName)
	for _, rule := range existingGrouping {
		if len(rule) >= 2 {
			domain := make([]string, 0)
			if len(rule) >= 3 {
				domain = append(domain, rule[2])
			}
			e.roleMgr.DeleteLink(rule[0], rule[1], domain...)
		}
	}

	return e.policy.RemoveFilteredPolicy(model.SectionRoleDefinition, policy.PTypeGrouping, 1, roleName)
}

// GetImplicitRolesForUser 获取用户的隐式角色（包含继承链上的所有角色）
func (e *Enforcer) GetImplicitRolesForUser(name string, domain ...string) []string {
	return e.roleMgr.GetImplicitRoles(name, domain...)
}

// GetImplicitPermissionsForUser 获取用户的隐式权限（包含继承链上所有角色的权限）
func (e *Enforcer) GetImplicitPermissionsForUser(user string, domain ...string) [][]string {
	roles := e.roleMgr.GetImplicitRoles(user, domain...)
	roles = append(roles, user)

	var permissions [][]string
	seen := make(map[string]bool)

	for _, r := range roles {
		policies := e.policy.GetFilteredPolicy(policy.PTypePolicy, 0, r)
		for _, p := range policies {
			key := strings.Join(p, ",")
			if !seen[key] {
				seen[key] = true
				permissions = append(permissions, p)
			}
		}
	}

	return permissions
}

// GetImplicitUsersForPermission 获取拥有指定权限的所有隐式用户
func (e *Enforcer) GetImplicitUsersForPermission(permission ...string) []string {
	policies := e.policy.GetFilteredPolicy(policy.PTypePolicy, 1, permission...)

	var users []string
	seen := make(map[string]bool)

	for _, p := range policies {
		if len(p) > 0 && !seen[p[0]] {
			seen[p[0]] = true
			users = append(users, p[0])

			implicitUsers := e.roleMgr.GetImplicitUsers(p[0])
			for _, u := range implicitUsers {
				if !seen[u] {
					seen[u] = true
					users = append(users, u)
				}
			}
		}
	}

	return users
}

// GetPermissionsForUser 获取用户的直接权限
func (e *Enforcer) GetPermissionsForUser(user string, domain ...string) [][]string {
	return e.policy.GetFilteredPolicy(policy.PTypePolicy, 0, user)
}

// HasPermissionForUser 判断用户是否拥有指定权限
func (e *Enforcer) HasPermissionForUser(user string, permission ...string) bool {
	return e.policy.HasPolicy(policy.PTypePolicy, append([]string{user}, permission...))
}

// AddPermissionForUser 为用户添加单条权限
// 等价于 AddPolicy(user, permission...)
// 例如：AddPermissionForUser("alice", "data1", "read")
func (e *Enforcer) AddPermissionForUser(user string, permission ...string) error {
	return e.AddPolicy(append([]string{user}, permission...)...)
}

// AddPermissionsForUser 为用户批量添加权限
// permissions 为权限数组，每个元素是一条完整的权限（不含用户名）
// 例如：AddPermissionsForUser("alice", []string{"data1","read"}, []string{"data2","write"})
func (e *Enforcer) AddPermissionsForUser(user string, permissions ...[]string) error {
	var rules [][]string
	for _, perm := range permissions {
		rules = append(rules, append([]string{user}, perm...))
	}
	return e.AddPolicies(rules)
}

// DeletePermissionForUser 删除用户的单条权限
// 等价于 RemovePolicy(user, permission...)
func (e *Enforcer) DeletePermissionForUser(user string, permission ...string) error {
	return e.RemovePolicy(append([]string{user}, permission...)...)
}

// DeletePermissionsForUser 删除用户的所有权限
// 移除 p 段中以 user 为第一字段的所有策略行
func (e *Enforcer) DeletePermissionsForUser(user string) error {
	return e.RemoveFilteredPolicy(0, user)
}

// DeletePermission 删除指定权限（按权限内容匹配，不限定用户）
// 移除 p 段中从第 1 个字段开始匹配 permission 的所有策略行
// 例如：DeletePermission("data1", "read") 会删除所有用户对 data1 的 read 权限
func (e *Enforcer) DeletePermission(permission ...string) error {
	return e.RemoveFilteredPolicy(1, permission...)
}

// ==================== RBAC Domain API ====================
// 以下 API 支持多租户域隔离，domain 参数用于指定租户/平台/地区等维度
// 域隔离原理：角色键格式为 "domain:name"，不同域的角色关系互不影响
//
// 数据权限扩展：
//   除了租户（tenant）维度，还可以通过域机制实现更细粒度的数据权限：
//   - 平台维度：domain="platform:web" / domain="platform:mobile"
//   - 地区维度：domain="region:cn-east" / domain="region:us-west"
//   - 组合维度：domain="tenant1:platform:web:region:cn-east"
//   只需在策略文件中使用对应的域标识即可实现数据权限隔离

// GetUsersForRoleInDomain 获取指定域中拥有某角色的用户列表
// name: 角色名称，domain: 域标识（如 "tenant1"、"platform:web"）
func (e *Enforcer) GetUsersForRoleInDomain(name, domain string) []string {
	return e.roleMgr.GetUsers(name, domain)
}

// GetRolesForUserInDomain 获取指定域中用户的角色列表
func (e *Enforcer) GetRolesForUserInDomain(name, domain string) []string {
	return e.roleMgr.GetRoles(name, domain)
}

// GetPermissionsForUserInDomain 获取指定域中用户的权限列表
// 先获取用户在域中的所有角色，再查找这些角色在域中的策略
func (e *Enforcer) GetPermissionsForUserInDomain(user, domain string) [][]string {
	roles := e.roleMgr.GetRoles(user, domain)
	allSubjects := append([]string{user}, roles...)

	subjectSet := make(map[string]struct{}, len(allSubjects))
	for _, s := range allSubjects {
		subjectSet[s] = struct{}{}
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	assertion := e.getPolicyAssertion()
	if assertion == nil {
		return nil
	}

	var result [][]string
	for _, p := range assertion.Policies {
		if len(p) < 4 {
			continue
		}
		if p[1] != domain {
			continue
		}
		if _, ok := subjectSet[p[0]]; !ok {
			continue
		}
		result = append(result, p)
	}
	return result
}

// DomainQuery 多域查询参数
type DomainQuery struct {
	Subject string
	Domain  string
}

// GetPermissionsInDomains 批量获取多个 (subject, domain) 组合的权限
// 相比逐个调用 GetFilteredPolicy，此方法只做一次策略全扫描，
// 按 (subject, domain) 索引匹配，避免 N×M 次线性扫描
// 返回去重后的 "obj:act" 列表
func (e *Enforcer) GetPermissionsInDomains(queries []DomainQuery) []string {
	if len(queries) == 0 {
		return nil
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	// 构建 (subject, domain) 查找集合
	lookup := make(map[[2]string]struct{}, len(queries))
	for _, q := range queries {
		lookup[[2]string{q.Subject, q.Domain}] = struct{}{}
	}

	// 一次遍历策略，按 (sub, dom) 匹配
	policyAssertion := e.getPolicyAssertion()
	if policyAssertion == nil {
		return nil
	}

	permSet := make(map[string]struct{})
	for _, p := range policyAssertion.Policies {
		if len(p) < 4 {
			continue
		}
		key := [2]string{p[0], p[1]}
		if _, ok := lookup[key]; ok {
			permSet[p[2]+":"+p[3]] = struct{}{}
		}
	}

	permissions := make([]string, 0, len(permSet))
	for p := range permSet {
		permissions = append(permissions, p)
	}
	return permissions
}

// AddRoleForUserInDomain 在指定域中为用户添加角色
// 等价于在 g 段添加策略：user, roleName, domain
func (e *Enforcer) AddRoleForUserInDomain(user, roleName, domain string) error {
	return e.AddRoleForUser(user, roleName, domain)
}

// DeleteRoleForUserInDomain 在指定域中删除用户的角色
func (e *Enforcer) DeleteRoleForUserInDomain(user, roleName, domain string) error {
	return e.DeleteRoleForUser(user, roleName, domain)
}

// DeleteRolesForUserInDomain 删除指定域中用户的所有角色
func (e *Enforcer) DeleteRolesForUserInDomain(user, domain string) error {
	return e.DeleteRolesForUser(user, domain)
}

// GetAllUsersByDomain 获取指定域中的所有用户
func (e *Enforcer) GetAllUsersByDomain(domain string) []string {
	return e.roleMgr.GetUsers("role", domain)
}

// DeleteAllUsersByDomain 删除指定域中的所有用户角色关系
// 同时清理 g 段策略、适配器持久化和分布式通知
// 优化：notifyPolicyChange 移出锁外，减少锁内网络 IO 持锁时间，避免阻塞 Enforce 读操作
func (e *Enforcer) DeleteAllUsersByDomain(domain string) error {
	return e.withLockAndNotify(func() error {
		e.roleMgr.DeleteDomain(domain)

		if e.autoSave && e.policy.GetAdapter() != nil {
			if err := e.policy.RemoveFilteredPolicy(model.SectionRoleDefinition, policy.PTypeGrouping, 2, domain); err != nil {
				e.logger.WarnKV("Failed to remove filtered grouping policy by domain", "domain", domain, "error", err.Error())
			}
		}
		return nil
	}, policy.EventTypePolicyRemoved, policy.PTypeGrouping, nil, nil)
}

// DeleteDomains 批量删除多个域的角色关系
// 同时清理 g 段策略、适配器持久化和分布式通知
// 优化：notifyPolicyChange 移出锁外，减少锁内网络 IO 持锁时间，避免阻塞 Enforce 读操作
func (e *Enforcer) DeleteDomains(domains ...string) error {
	return e.withLockAndNotify(func() error {
		for _, d := range domains {
			e.roleMgr.DeleteDomain(d)
		}

		if e.autoSave && e.policy.GetAdapter() != nil {
			for _, d := range domains {
				if err := e.policy.RemoveFilteredPolicy(model.SectionRoleDefinition, policy.PTypeGrouping, 2, d); err != nil {
					e.logger.WarnKV("Failed to remove filtered grouping policy by domain", "domain", d, "error", err.Error())
				}
			}
		}
		return nil
	}, policy.EventTypePolicyRemoved, policy.PTypeGrouping, nil, nil)
}

// GetAllDomains 获取所有域列表
func (e *Enforcer) GetAllDomains() []string {
	return e.roleMgr.GetAllDomains()
}

// GetAllRolesByDomain 获取指定域中的所有角色
func (e *Enforcer) GetAllRolesByDomain(domain string) []string {
	return e.roleMgr.GetRoles("role", domain)
}

// ==================== Transactional API ====================
// 以下 API 提供事务支持，确保内存模型、角色管理器和适配器的一致性
// 如果适配器实现了 TransactionalAdapter 接口，操作会在数据库事务中执行
// 否则回退到非事务模式，但仍保证内存状态的一致性
//
// 注意：事务方法内部直接操作内存模型和角色管理器，不调用已加锁的公开方法
// 所有事务方法自行管理锁，避免死锁

// ExecuteInTransaction 在事务中执行批量操作
// 适配器支持事务时，所有操作在同一个数据库事务中执行
//
// 约束：fn 回调在 e.mu.Lock 持有期间执行，fn 内禁止调用 AddPolicy/RemovePolicy/
// AddGroupingPolicy 等公开 API（它们内部会 e.mu.Lock 导致自死锁）
// fn 内应直接调用 e.policy 的内部方法（如 e.policy.AddPolicy/e.policy.RemoveFilteredPolicy）
// 参见 TransactionalSyncUserRoles/TransactionalDeleteUser 的实现
func (e *Enforcer) ExecuteInTransaction(ctx context.Context, fn func() error) error {
	// 快速失败：上下文已取消时不再开启事务，避免 driver: bad connection 等级联错误
	if err := ctx.Err(); err != nil {
		return err
	}
	// 始终使用 rootAdapter 开启事务，不用 e.policy.GetAdapter()
	// 原因：事务执行期间 e.policy 的 adapter 会被临时替换为 txAdapter，
	// 如果此时另一个 goroutine 调用 e.policy.GetAdapter() 会拿到 txAdapter，
	// 然后 txAdapter.inTransaction=true 导致直接复用已提交/回滚的事务，
	// 触发 "transaction has already been committed or rolled back" 错误
	// 读 rootAdapter 用 RLock 与 SetAdapter 的 Lock 同步，读完即释放，避免与回调内 Lock 死锁
	e.mu.RLock()
	rootAdapter := e.rootAdapter
	e.mu.RUnlock()
	if rootAdapter != nil {
		return rootAdapter.ExecuteInTransaction(ctx, func(txAdapter policy.Adapter) error {
			e.mu.Lock()
			defer e.mu.Unlock()
			prevAdapter := e.policy.GetAdapter()
			e.policy.SetAdapter(txAdapter)
			defer e.policy.SetAdapter(prevAdapter)
			return fn()
		})
	}
	// 回退：适配器不支持事务接口（如内存适配器/文件适配器）
	if ta, ok := e.policy.GetAdapter().(policy.TransactionalAdapter); ok {
		return ta.ExecuteInTransaction(ctx, func(txAdapter policy.Adapter) error {
			e.mu.Lock()
			defer e.mu.Unlock()
			prevAdapter := e.policy.GetAdapter()
			e.policy.SetAdapter(txAdapter)
			defer e.policy.SetAdapter(prevAdapter)
			return fn()
		})
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	return fn()
}

// TransactionalSyncUserRoles 在事务中同步用户角色
// 先删除用户所有旧角色（含 g 段策略和适配器），再批量添加新角色
// 适用于用户角色绑定变更场景，确保角色替换的原子性
// groupingRules 每个元素格式为 [user, roleName, domain]
//
// 优化：
//   - 使用 UpdateFilteredPolicies 合并 DELETE+INSERT 为单次 DB 操作
//   - notifyPolicyChange 移到事务提交后执行，减少锁内网络 IO 持锁时间
func (e *Enforcer) TransactionalSyncUserRoles(ctx context.Context, user string, groupingRules [][]string) error {
	err := e.ExecuteInTransaction(ctx, func() error {
		// 先清理旧 roleMgr 链接（基于内存中现有策略）
		existingGrouping := e.policy.GetFilteredPolicy(policy.PTypeGrouping, 0, user)
		for _, rule := range existingGrouping {
			if len(rule) >= 2 {
				domain := make([]string, 0)
				if len(rule) >= 3 {
					domain = append(domain, rule[2])
				}
				e.roleMgr.DeleteLink(rule[0], rule[1], domain...)
			}
		}

		// 用 UpdateFilteredPolicies 合并删除旧策略+插入新策略为单次 DB 操作
		// 替代之前的 RemoveFilteredPolicy + AddPolicies（两次 DB 操作）
		if err := e.policy.UpdateFilteredPolicies(model.SectionRoleDefinition, policy.PTypeGrouping, groupingRules, 0, user); err != nil {
			return err
		}

		// 添加新 roleMgr 链接
		if e.autoBuildRoleLinks {
			for _, rule := range groupingRules {
				if len(rule) >= 2 {
					domain := make([]string, 0)
					if len(rule) >= 3 {
						domain = append(domain, rule[2])
					}
					_ = e.roleMgr.AddLink(rule[0], rule[1], domain...)
				}
			}
		}

		return nil
	})
	// 事务提交成功后再通知，避免回滚时发出错误通知
	if err == nil {
		e.notifyPolicyChange(policy.EventTypePolicyAdded, policy.PTypeGrouping, nil, nil)
	}
	return err
}

// TransactionalDeleteUser 在事务中删除用户及其所有角色关系和权限
// 同时清理 p 段策略、g 段策略、角色管理器和适配器
//
// 优化：notifyPolicyChange 移到事务提交后执行，减少锁内网络 IO 持锁时间
// p+g 段同时变更，合并为一次通知（PType="" 表示多类型变更），减少 NATS 往返
func (e *Enforcer) TransactionalDeleteUser(ctx context.Context, user string) error {
	err := e.ExecuteInTransaction(ctx, func() error {
		_ = e.policy.RemoveFilteredPolicy(model.SectionPolicyDefinition, policy.PTypePolicy, 0, user)

		existingGrouping := e.policy.GetFilteredPolicy(policy.PTypeGrouping, 0, user)
		for _, rule := range existingGrouping {
			if len(rule) >= 2 {
				domain := make([]string, 0)
				if len(rule) >= 3 {
					domain = append(domain, rule[2])
				}
				e.roleMgr.DeleteLink(rule[0], rule[1], domain...)
			}
		}
		_ = e.policy.RemoveFilteredPolicy(model.SectionRoleDefinition, policy.PTypeGrouping, 0, user)

		return nil
	})
	// 事务提交成功后再通知：p+g 段合并为一次通知，减少 NATS 往返
	if err == nil {
		e.notifyPolicyChange(policy.EventTypePolicyRemoved, "", nil, nil)
	}
	return err
}

// TransactionalDeleteRole 在事务中删除角色及其所有关系
// 同时清理 g 段策略、p 段策略、角色管理器和适配器
//
// 优化：notifyPolicyChange 移到事务提交后执行，减少锁内网络 IO 持锁时间
// p+g 段同时变更，合并为一次通知（PType="" 表示多类型变更），减少 NATS 往返
func (e *Enforcer) TransactionalDeleteRole(ctx context.Context, roleName string) error {
	err := e.ExecuteInTransaction(ctx, func() error {
		users := e.roleMgr.GetUsers(roleName)
		for _, u := range users {
			e.roleMgr.DeleteLink(u, roleName)
		}

		_ = e.policy.RemoveFilteredPolicy(model.SectionRoleDefinition, policy.PTypeGrouping, 1, roleName)
		_ = e.policy.RemoveFilteredPolicy(model.SectionPolicyDefinition, policy.PTypePolicy, 0, roleName)

		return nil
	})
	// 事务提交成功后再通知：p+g 段合并为一次通知
	if err == nil {
		e.notifyPolicyChange(policy.EventTypePolicyRemoved, "", nil, nil)
	}
	return err
}

// ==================== Management API ====================
// 以下 API 提供策略的查询和管理能力，用于管理后台等场景

// GetAllSubjects 获取所有策略主体（p 段第 0 字段去重）
func (e *Enforcer) GetAllSubjects() []string {
	return e.policy.GetAllSubjects()
}

// GetAllNamedSubjects 获取指定策略类型的所有主体（去重）
func (e *Enforcer) GetAllNamedSubjects(ptype string) []string {
	policies := e.policy.GetAllPolicies(ptype)
	seen := make(map[string]bool)
	var result []string
	for _, p := range policies {
		if len(p) > 0 && !seen[p[0]] {
			seen[p[0]] = true
			result = append(result, p[0])
		}
	}
	return result
}

// GetAllObjects 获取所有策略客体（p 段第 1 字段去重）
func (e *Enforcer) GetAllObjects() []string {
	return e.policy.GetAllObjects()
}

// GetAllNamedObjects 获取指定策略类型的所有客体（去重）
func (e *Enforcer) GetAllNamedObjects(ptype string) []string {
	policies := e.policy.GetAllPolicies(ptype)
	seen := make(map[string]bool)
	var result []string
	for _, p := range policies {
		if len(p) > 1 && !seen[p[1]] {
			seen[p[1]] = true
			result = append(result, p[1])
		}
	}
	return result
}

// GetAllActions 获取所有策略动作（p 段第 2 字段去重）
func (e *Enforcer) GetAllActions() []string {
	return e.policy.GetAllActions()
}

// GetAllNamedActions 获取指定策略类型的所有动作（去重）
func (e *Enforcer) GetAllNamedActions(ptype string) []string {
	policies := e.policy.GetAllPolicies(ptype)
	seen := make(map[string]bool)
	var result []string
	for _, p := range policies {
		if len(p) > 2 && !seen[p[2]] {
			seen[p[2]] = true
			result = append(result, p[2])
		}
	}
	return result
}

// GetAllRoles 获取所有角色（g 段第 1 字段去重）
func (e *Enforcer) GetAllRoles() []string {
	return e.policy.GetAllRoles()
}

// GetAllNamedRoles 获取指定策略类型的所有角色（去重）
func (e *Enforcer) GetAllNamedRoles(ptype string) []string {
	policies := e.policy.GetAllPolicies(ptype)
	seen := make(map[string]bool)
	var result []string
	for _, p := range policies {
		if len(p) > 1 && !seen[p[1]] {
			seen[p[1]] = true
			result = append(result, p[1])
		}
	}
	return result
}

// GetAllUsers 获取所有用户列表
func (e *Enforcer) GetAllUsers() []string {
	return e.policy.GetAllUsers()
}

// GetPolicy 获取 p 段的所有策略
func (e *Enforcer) GetPolicy() [][]string {
	return e.policy.GetAllPolicies(policy.PTypePolicy)
}

// GetFilteredPolicy 获取 p 段的过滤策略
// fieldIndex: 起始字段索引，fieldValues: 过滤值
func (e *Enforcer) GetFilteredPolicy(fieldIndex int, fieldValues ...string) [][]string {
	return e.policy.GetFilteredPolicy(policy.PTypePolicy, fieldIndex, fieldValues...)
}

// GetNamedPolicy 获取指定策略类型的所有策略
func (e *Enforcer) GetNamedPolicy(ptype string) [][]string {
	return e.policy.GetAllPolicies(ptype)
}

// GetFilteredNamedPolicy 获取指定策略类型的过滤策略
func (e *Enforcer) GetFilteredNamedPolicy(ptype string, fieldIndex int, fieldValues ...string) [][]string {
	return e.policy.GetFilteredPolicy(ptype, fieldIndex, fieldValues...)
}

// GetGroupingPolicy 获取 g 段的所有角色分组策略
func (e *Enforcer) GetGroupingPolicy() [][]string {
	return e.policy.GetAllPolicies(policy.PTypeGrouping)
}

// GetFilteredGroupingPolicy 获取 g 段的过滤分组策略
func (e *Enforcer) GetFilteredGroupingPolicy(fieldIndex int, fieldValues ...string) [][]string {
	return e.policy.GetFilteredPolicy(policy.PTypeGrouping, fieldIndex, fieldValues...)
}

// GetNamedGroupingPolicy 获取指定策略类型的所有分组策略
func (e *Enforcer) GetNamedGroupingPolicy(ptype string) [][]string {
	return e.policy.GetAllPolicies(ptype)
}

// GetFilteredNamedGroupingPolicy 获取指定策略类型的过滤分组策略
func (e *Enforcer) GetFilteredNamedGroupingPolicy(ptype string, fieldIndex int, fieldValues ...string) [][]string {
	return e.policy.GetFilteredPolicy(ptype, fieldIndex, fieldValues...)
}

// HasNamedPolicy 判断指定策略类型中是否存在某条策略
func (e *Enforcer) HasNamedPolicy(ptype string, params ...string) bool {
	return e.policy.HasPolicy(ptype, params)
}

// HasPolicy 判断 p 段中是否存在某条策略
func (e *Enforcer) HasPolicy(params ...string) bool {
	return e.policy.HasPolicy(policy.PTypePolicy, params)
}

// HasGroupingPolicy 判断 g 段中是否存在某条分组策略
func (e *Enforcer) HasGroupingPolicy(params ...string) bool {
	return e.policy.HasPolicy(policy.PTypeGrouping, params)
}

// HasNamedGroupingPolicy 判断指定策略类型中是否存在某条分组策略
func (e *Enforcer) HasNamedGroupingPolicy(ptype string, params ...string) bool {
	return e.policy.HasPolicy(ptype, params)
}

// ==================== Self API (without autoNotifyWatcher) ====================
// 以下 API 直接操作策略，不触发自动通知（autoNotifyWatcher）
// 适用于批量操作场景：先通过 SelfXxx 批量修改，最后手动调用通知

// SelfAddPolicy 直接添加策略（不触发通知和自动保存）
func (e *Enforcer) SelfAddPolicy(sec, ptype string, rule []string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.validatePolicyRule(sec, ptype, rule); err != nil {
		return err
	}
	e.invalidateExtraPoliciesCache()
	return e.policy.AddPolicy(sec, ptype, rule)
}

// SelfAddPolicies 批量添加策略（不触发通知，遇到重复策略返回错误）
func (e *Enforcer) SelfAddPolicies(sec, ptype string, rules [][]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, rule := range rules {
		if err := e.validatePolicyRule(sec, ptype, rule); err != nil {
			return err
		}
	}
	e.invalidateExtraPoliciesCache()
	return e.policy.AddPolicies(sec, ptype, rules)
}

// SelfAddPoliciesEx 批量添加策略（不触发通知，跳过重复策略）
func (e *Enforcer) SelfAddPoliciesEx(sec, ptype string, rules [][]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, rule := range rules {
		if err := e.validatePolicyRule(sec, ptype, rule); err != nil {
			return err
		}
	}
	e.invalidateExtraPoliciesCache()
	return e.policy.AddPoliciesEx(sec, ptype, rules)
}

// SelfRemovePolicy 直接删除策略（不触发通知）
func (e *Enforcer) SelfRemovePolicy(sec, ptype string, rule []string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.invalidateExtraPoliciesCache()
	return e.policy.RemovePolicy(sec, ptype, rule)
}

// SelfRemovePolicies 批量删除策略（不触发通知）
func (e *Enforcer) SelfRemovePolicies(sec, ptype string, rules [][]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.invalidateExtraPoliciesCache()
	return e.policy.RemovePolicies(sec, ptype, rules)
}

// SelfRemoveFilteredPolicy 按条件过滤删除策略（不触发通知）
func (e *Enforcer) SelfRemoveFilteredPolicy(sec, ptype string, fieldIndex int, fieldValues ...string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.invalidateExtraPoliciesCache()
	return e.policy.RemoveFilteredPolicy(sec, ptype, fieldIndex, fieldValues...)
}

// SelfUpdatePolicy 更新策略（不触发通知）
func (e *Enforcer) SelfUpdatePolicy(sec, ptype string, oldRule, newRule []string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.invalidateExtraPoliciesCache()
	return e.policy.UpdatePolicy(sec, ptype, oldRule, newRule)
}

// SelfUpdatePolicies 批量更新策略（不触发通知）
func (e *Enforcer) SelfUpdatePolicies(sec, ptype string, oldRules, newRules [][]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.invalidateExtraPoliciesCache()
	return e.policy.UpdatePolicies(sec, ptype, oldRules, newRules)
}

// ==================== Public Policy API ====================
// 公开接口策略：允许匿名用户访问的路径，在启动时从代码加载，不持久化到适配器

// IsPublicPolicy 检查指定路径和方法是否为公开接口
// 通过 Enforce 检查 anonymous 主体是否有权限访问
// 适用于 Gateway 的 Authorities 方法：公开接口无需 JWT 验证直接放行
//
// 参数格式取决于模型定义：
//   - RBAC: IsPublicPolicy("/v1/login", "POST")
//   - RBAC Domain: IsPublicPolicy("tenant::x", "/v1/login", "POST")
func (e *Enforcer) IsPublicPolicy(rvals ...interface{}) (bool, error) {
	// 将 anonymous 作为主体插入到请求参数的最前面
	requestParams := append([]interface{}{SubjectAnonymous}, rvals...)
	return e.Enforce(requestParams...)
}

// IsPublicPolicyCtx 检查指定路径和方法是否为公开接口（带 context）
// 与 IsPublicPolicy 的区别：传入请求 context，使 EnforceContext 能感知 deadline/cancel
// 当 gRPC 调用方 context 超时时，避免 AC 服务 goroutine 永久阻塞
func (e *Enforcer) IsPublicPolicyCtx(ctx context.Context, rvals ...interface{}) (bool, error) {
	requestParams := append([]interface{}{SubjectAnonymous}, rvals...)
	return e.EnforceContext(ctx, requestParams...)
}

// GetPublicPolicies 获取当前配置的公开策略列表
func (e *Enforcer) GetPublicPolicies() [][]string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([][]string, len(e.publicPolicies))
	copy(result, e.publicPolicies)
	return result
}

// IsAuthSkipPolicy 检查指定路径和方法是否为认证免鉴权接口
// 通过 Enforce 检查 authenticated 主体是否有权限访问
// 适用于 Gateway 的 Authorities 方法：认证免鉴权接口需要 JWT 验证但跳过 Casbin 权限校验
//
// 参数格式取决于模型定义：
//   - RBAC: IsAuthSkipPolicy("/v1/auth/user-info", "GET")
//   - RBAC Domain: IsAuthSkipPolicy("tenant::x", "/v1/auth/user-info", "GET")
func (e *Enforcer) IsAuthSkipPolicy(rvals ...interface{}) (bool, error) {
	// 将 authenticated 作为主体插入到请求参数的最前面
	requestParams := append([]interface{}{SubjectAuthenticated}, rvals...)
	return e.Enforce(requestParams...)
}

// IsAuthSkipPolicyCtx 检查指定路径和方法是否为认证免鉴权接口（带 context）
// 与 IsAuthSkipPolicy 的区别：传入请求 context，使 EnforceContext 能感知 deadline/cancel
func (e *Enforcer) IsAuthSkipPolicyCtx(ctx context.Context, rvals ...interface{}) (bool, error) {
	requestParams := append([]interface{}{SubjectAuthenticated}, rvals...)
	return e.EnforceContext(ctx, requestParams...)
}

// GetAuthSkipPolicies 获取当前配置的认证免鉴权策略列表
func (e *Enforcer) GetAuthSkipPolicies() [][]string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([][]string, len(e.authSkipPolicies))
	copy(result, e.authSkipPolicies)
	return result
}

// ==================== Enforcer Control API ====================
// 以下 API 控制执行器的行为开关和状态

// Enable 启用/禁用执行器
// 禁用时所有 Enforce 调用返回错误，状态机切换到 StateDisabled
func (e *Enforcer) Enable(enabled bool) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.enabled = enabled
	targetState := mathx.IF(enabled, StateReady, StateDisabled)
	_ = e.stateMachine.TransitionTo(targetState)

	e.logger.InfoKV("Enforcer enabled state changed", "enabled", enabled)
}

// EnableAutoSave 启用/禁用自动保存
// 开启后 AddPolicy/RemovePolicy 等操作会自动持久化到适配器
func (e *Enforcer) EnableAutoSave(autoSave bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.autoSave = autoSave
	// 同步 Policy 层的 autoSave，确保策略操作时正确控制适配器持久化
	e.policy.SetAutoSave(autoSave)
}

// EnableAutoBuildRoleLinks 启用/禁用自动构建角色继承链
// 开启后添加 g 策略时自动更新角色管理器的继承关系
func (e *Enforcer) EnableAutoBuildRoleLinks(autoBuild bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.autoBuildRoleLinks = autoBuild
}

// EnableAutoNotifyWatcher 启用/禁用自动通知策略变更
// 开启后策略变更会通过 Pub/Sub 广播给其他节点
func (e *Enforcer) EnableAutoNotifyWatcher(autoNotify bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.autoNotifyWatcher = autoNotify
}

// IsEnabled 检查执行器是否启用
func (e *Enforcer) IsEnabled() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.enabled
}

// NormalizeHost 使用自定义归一化函数处理域名
// 如果未设置自定义函数，直接返回原始值
func (e *Enforcer) NormalizeHost(host string) string {
	if e.normalizeHost != nil {
		return e.normalizeHost(host)
	}
	return host
}

// IsAutoSave 检查是否启用自动保存
func (e *Enforcer) IsAutoSave() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.autoSave
}

// IsFiltered 检查策略是否经过过滤加载
func (e *Enforcer) IsFiltered() bool {
	return e.policy.IsFiltered()
}

// GetState 获取执行器当前状态（Ready/Disabled/Error）
func (e *Enforcer) GetState() string {
	return e.stateMachine.CurrentState()
}

// GetModel 获取当前权限模型
func (e *Enforcer) GetModel() *model.Model {
	return e.model
}

// SetModel 设置权限模型（热替换，需重新加载策略）
func (e *Enforcer) SetModel(m *model.Model) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.model = m
}

// GetPolicyManager 获取策略管理器
func (e *Enforcer) GetPolicyManager() *policy.Policy {
	return e.policy
}

// GetRoleManager 获取角色管理器
func (e *Enforcer) GetRoleManager() *role.RoleManager {
	return e.roleMgr
}

// SetRoleManager 设置角色管理器（热替换）
func (e *Enforcer) SetRoleManager(rm *role.RoleManager) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.roleMgr = rm
}

// GetAdapter 获取策略适配器
func (e *Enforcer) GetAdapter() policy.Adapter {
	return e.policy.GetAdapter()
}

// SetAdapter 设置策略适配器（热替换）
func (e *Enforcer) SetAdapter(adapter policy.Adapter) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.policy.SetAdapter(adapter)
	// 捕获根适配器引用，ExecuteInTransaction 始终用它开启事务
	// 避免 e.policy.GetAdapter() 在事务热替换期间返回 txAdapter 导致竞态
	if ta, ok := adapter.(policy.TransactionalAdapter); ok {
		e.rootAdapter = ta
	}
}

// GetBreaker 获取熔断器实例
func (e *Enforcer) GetBreaker() *breaker.Circuit {
	return e.breaker
}

// GetWatcher 获取文件变更监控器
func (e *Enforcer) GetWatcher() *policy.PolicyWatcher {
	return e.watcher
}

// ClearPolicy 清空所有策略和缓存
func (e *Enforcer) ClearPolicy() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.model.ClearPolicies()
	e.policy.GetCache().InvalidateAll()
	e.invalidateExtraPoliciesCache()
}

// LoadPolicy 从适配器加载策略
// 加载失败时状态机切换到 StateError
// 加载成功后自动构建角色继承链（如果 autoBuildRoleLinks 开启）
// 公开策略会在适配器策略加载后自动重新注入
func (e *Enforcer) LoadPolicy() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.policy.LoadPolicy(); err != nil {
		_ = e.stateMachine.TransitionTo(StateError)
		return err
	}

	// 重新加载公开策略（仅内存，不持久化）
	// 直接调用内部方法，因为外层已持有锁
	e.reloadPublicPoliciesUnlocked()

	// 重新加载认证免鉴权策略（仅内存，不持久化）
	e.reloadAuthSkipPoliciesUnlocked()

	if e.autoBuildRoleLinks {
		e.loadRoleLinks()
	}

	e.invalidateExtraPoliciesCache()
	return nil
}

// LoadFilteredPolicy 从适配器加载过滤后的策略
// filter 参数格式取决于适配器实现
func (e *Enforcer) LoadFilteredPolicy(filter interface{}) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.policy.LoadFilteredPolicy(filter); err != nil {
		_ = e.stateMachine.TransitionTo(StateError)
		return err
	}

	if e.autoBuildRoleLinks {
		e.loadRoleLinks()
	}

	e.invalidateExtraPoliciesCache()
	return nil
}

// SavePolicy 将当前策略保存到适配器
func (e *Enforcer) SavePolicy() error {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.policy.SavePolicy()
}

// BuildRoleLinks 手动构建角色继承链
// 遍历 g 段策略，将角色关系注入角色管理器
func (e *Enforcer) BuildRoleLinks() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.loadRoleLinks()
	return nil
}

// ReloadPolicy 重新加载策略
// 从适配器重新加载策略并重建角色继承链
// 加载失败时状态机切换到 StateError
func (e *Enforcer) ReloadPolicy() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.policy.LoadPolicy(); err != nil {
		_ = e.stateMachine.TransitionTo(StateError)
		return err
	}

	// 重新加载公开策略（仅内存，不持久化）
	// 直接调用内部方法，因为外层已持有锁
	e.reloadPublicPoliciesUnlocked()

	// 重新加载认证免鉴权策略（仅内存，不持久化）
	e.reloadAuthSkipPoliciesUnlocked()

	e.loadRoleLinks()

	// 策略重载后重建缓存
	e.initCachedFields()

	// 失效 extraPolicies 与 enforceCache，避免读到过期决策
	// 分布式通知触发的重载也必须走失效逻辑，保证多节点一致性
	e.invalidateExtraPoliciesCache()

	e.logger.InfoKV("Policy reloaded successfully")
	return nil
}

// reloadPolicyForRemoteChange 远程增量变更触发的策略重载
//
// 与 ReloadPolicy 的关键区别：不清空 enforceCache，让短 TTL（30s）自然过期
// 适用于分布式场景下的增量事件（PolicyAdded/Removed/Updated），避免每次小变更
// 都全量清空 enforceCache 导致集群命中率骤降、瞬时回源风暴
//
// 重建内容：
//   - 策略数据（LoadPolicy）
//   - 公开/认证免鉴权策略
//   - 角色继承链（loadRoleLinks）
//   - 性能缓存字段（initCachedFields，含 hasEval/hasGFunc/matcherExpr/effectEvaluator）
//   - extraPolicies（置 nil，下次 Enforce 懒加载重建）
//
// 仅 enforceCache 容忍秒级不一致（最长 30s 后所有缓存条目自然过期）
func (e *Enforcer) reloadPolicyForRemoteChange() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.policy.LoadPolicy(); err != nil {
		_ = e.stateMachine.TransitionTo(StateError)
		return err
	}

	e.reloadPublicPoliciesUnlocked()
	e.reloadAuthSkipPoliciesUnlocked()
	e.loadRoleLinks()
	e.initCachedFields()

	// 重建 extraPolicies（置 nil 触发懒加载），但保留 enforceCache
	// 让 30s TTL 自然消化增量变更，避免分布式命中率骤降
	e.extraPolicies = nil

	e.logger.InfoKV("Policy reloaded for remote incremental change (enforceCache preserved)")
	return nil
}

// SetMonitor 设置监控接口（预留扩展）
func (e *Enforcer) SetMonitor(m interface{}) {
	e.monitor = m
}

// ==================== Internal Methods ====================
// 以下为内部方法，不对外暴露

// reloadPublicPoliciesUnlocked 重新加载公开策略（无锁版本）
// 调用方必须已持有 e.mu 锁
// 临时移除适配器，防止公开策略被写入持久化存储
func (e *Enforcer) reloadPublicPoliciesUnlocked() {
	if len(e.publicPolicies) == 0 {
		return
	}
	// 临时移除适配器，确保公开策略仅添加到模型内存，不持久化
	prevAdapter := e.policy.GetAdapter()
	e.policy.SetAdapter(nil)
	if err := e.policy.AddPoliciesEx(model.SectionPolicyDefinition, policy.PTypePolicy, e.publicPolicies); err != nil {
		e.logger.WarnKV("Failed to reload public policies", "error", err.Error())
	}
	e.policy.SetAdapter(prevAdapter)
}

// reloadAuthSkipPoliciesUnlocked 重新加载认证免鉴权策略（无锁版本）
// 调用方必须已持有 e.mu 锁
// 临时移除适配器，防止认证免鉴权策略被写入持久化存储
func (e *Enforcer) reloadAuthSkipPoliciesUnlocked() {
	if len(e.authSkipPolicies) == 0 {
		return
	}
	// 临时移除适配器，确保认证免鉴权策略仅添加到模型内存，不持久化
	prevAdapter := e.policy.GetAdapter()
	e.policy.SetAdapter(nil)
	if err := e.policy.AddPoliciesEx(model.SectionPolicyDefinition, policy.PTypePolicy, e.authSkipPolicies); err != nil {
		e.logger.WarnKV("Failed to reload auth-skip policies", "error", err.Error())
	}
	e.policy.SetAdapter(prevAdapter)
}

// executeWithBreaker 通过熔断器执行函数
// 当熔断器处于 Open 状态时直接返回 ErrBreakerOpen 错误
// 当函数执行失败时，熔断器会累计失败次数，达到阈值后熔断
func (e *Enforcer) executeWithBreaker(fn func() (bool, error)) (bool, error) {
	var result bool
	var err error

	breakerErr := e.breaker.Execute(func() error {
		result, err = fn()
		return err
	})

	if breakerErr != nil {
		if breakerErr == breaker.ErrOpen {
			return false, errors.NewEnforcerBreakerOpenError(e.breaker.GetStats()["name"].(string))
		}
		return false, breakerErr
	}

	return result, nil
}

// evaluateMatch 构建 MatchContext 并执行匹配（公共逻辑）
// doEnforce / doEnforceWithMatcher / enforceExWithMatcherExpr 共用
// 调用方负责 validateRequest、buildRequest、releaseRequest、expr 校验
//
// 性能优化：
//   - MatchContext 从 pool 复用，避免每次 doEnforce 堆分配
//   - policyAssertion 使用缓存值，避免每次 map 查找
//   - hasEval/hasGFunc 由调用方传入预计算值，避免重复 strings.Contains
func (e *Enforcer) evaluateMatch(request map[string]interface{}, expr string, hasEval, hasGFunc bool) (bool, []string, error) {
	// 优先使用缓存值（NewEnforcer 时初始化），fallback 到动态查找（兼容手动构建的测试场景）
	policyAssertion := e.cachedPolicyAssertion
	if policyAssertion == nil {
		policyAssertion = e.getPolicyAssertion()
	}
	if policyAssertion == nil {
		return false, nil, errors.NewPolicyNotFoundError(policy.PTypePolicy)
	}

	// 从 pool 复用 MatchContext，避免每次 doEnforce 堆分配
	// 所有字段在每次使用时被覆写，Put 前无需 clear（不持有引用）
	mc := matchContextPool.Get()
	mc.Request = request
	mc.Policies = policyAssertion.Policies
	mc.RoleMgr = e.roleMgr
	mc.Assertion = policyAssertion
	mc.CustomFuncs = e.customFuncs
	mc.ExtraPolicies = e.getExtraPolicies() // 使用缓存的 extraPolicies
	mc.ShortCircuit = e.shortCircuit        // 短路优化：some(where(p.eft==allow)) 模式下匹配到即返回
	mc.HasEval = hasEval                    // 预计算值，避免每次 doEnforce 重复 strings.Contains 扫描
	mc.HasGFunc = hasGFunc                  // 预计算值，避免每次 doEnforce 重复 strings.Contains 扫描
	mc.EffectIndex = e.effectIndex          // 预计算的 eft 索引，extractEffect O(1)

	matched, matchedEffects, err := e.matcher.Match(mc, expr)
	matchContextPool.Put(mc)
	if err != nil {
		return false, nil, errors.WrapError("matcher execution failed", err)
	}
	return matched, matchedEffects, nil
}

// doEnforce 执行权限校验核心逻辑
// 流程：校验请求参数 → 构建请求 → 获取 matcher 表达式 → 匹配策略 → 评估策略效果
// 内置 panic 恢复机制，防止匹配函数异常导致服务崩溃
func (e *Enforcer) doEnforce(ctx context.Context, rvals ...interface{}) (bool, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// 获取 RLock 后检查 context：若等待锁期间 context 已超时，立即返回避免执行 matcher
	// 注意：sync.RWMutex.RLock() 不支持 context，若写锁被长期持有此处仍会阻塞
	// 但写锁释放后此检查能避免后续无意义的 matcher 计算
	if ctx != nil && ctx.Err() != nil {
		return false, ctx.Err()
	}

	var err error
	defer syncx.RecoverToError(&err, func(r interface{}) {
		e.logger.ErrorContextKV(ctx, "Panic recovered in enforce", "panic", fmt.Sprintf("%v", r))
	})

	// 安全校验：请求参数不能为空，且必须与模型 r 段定义的字段数量匹配
	if validateErr := e.validateRequest(rvals); validateErr != nil {
		return false, validateErr
	}

	request := e.buildRequest(rvals...)
	if request == nil {
		return false, errors.NewModelInvalidError("invalid request parameters")
	}
	// 归还 request map 到 pool（matcher 内部已将值拷贝到 vars，不持有 request 引用）
	defer e.releaseRequest(request)

	// 使用缓存的 matcher 表达式，避免每次遍历 model assertions
	matcherExpr := e.matcherExpr
	if matcherExpr == "" {
		return false, errors.NewModelInvalidError("matcher expression is empty")
	}

	matched, matchedEffects, err := e.evaluateMatch(request, matcherExpr, e.hasEval, e.hasGFunc)
	if err != nil {
		return false, err
	}

	if !matched {
		return false, nil
	}

	// 使用缓存的 effect 评估器，避免每次创建新对象
	effectResult, err := e.evaluateEffectFromResultsCached(matchedEffects)
	if err != nil {
		return false, err
	}

	return bool(effectResult), nil
}

// initCachedFields 初始化性能缓存字段
// effect 评估器和 matcher 表达式在模型加载后不会变化，缓存后避免每次 Enforce 重复创建
// extraPolicies 在策略变更时需要重建，通过 invalidateExtraPoliciesCache 标记
func (e *Enforcer) initCachedFields() {
	// 缓存 matcher 表达式
	e.matcherExpr = e.getMatcherExpression()

	// 预计算 matcher 表达式特征，避免每次 doEnforce 重复 strings.Contains 扫描
	// matcherExpr 在模型加载后不变，HasEval/HasGFunc 是热路径上的高频判断
	e.hasEval = strings.Contains(e.matcherExpr, policy.EvalFunc)
	e.hasGFunc = strings.Contains(e.matcherExpr, policy.GFunc)

	// 缓存 request tokens（r 段定义）
	e.requestTokens = e.getRequestTokens()

	// 缓存 p 段策略断言，避免每次 doEnforce 调用 getPolicyAssertion 做 map 查找
	e.cachedPolicyAssertion = e.getPolicyAssertion()

	// 预计算 p.eft 索引，extractEffect 从 O(n) token 遍历降为 O(1) 索引访问
	e.effectIndex = -1
	if e.cachedPolicyAssertion != nil {
		for i, token := range e.cachedPolicyAssertion.Tokens {
			if token == "p.eft" {
				e.effectIndex = i
				break
			}
		}
	}

	// 缓存 effect 评估器
	effectExpr := ""
	for key, assertion := range e.model.GetAssertions() {
		if strings.HasPrefix(key, model.SectionPolicyEffect) {
			effectExpr = assertion.Value
			break
		}
	}
	if effectExpr != "" {
		e.effectEvaluator = policy.NewEffectEvaluator(effectExpr)
	}

	// 缓存短路优化标志
	e.shortCircuit = e.computeShortCircuit()

	// 初始化 extraPolicies 缓存
	e.extraPolicies = e.buildExtraPolicies(policy.PTypePolicy)
}

// invalidateExtraPoliciesCache 使 extraPolicies 缓存失效
// 在策略增删改时调用，下次 Enforce 时会重建
// 同时联动失效 Enforce 结果缓存，避免读到过期决策
func (e *Enforcer) invalidateExtraPoliciesCache() {
	e.extraPolicies = nil
	e.invalidateEnforceCache()
}

// getExtraPolicies 获取 extraPolicies（带懒加载缓存）
func (e *Enforcer) getExtraPolicies() map[string]*PolicySegment {
	if e.extraPolicies == nil {
		e.extraPolicies = e.buildExtraPolicies(policy.PTypePolicy)
	}
	return e.extraPolicies
}

// validateRequest 校验 Enforce 请求参数
// 使用缓存的 requestTokens 避免每次遍历 model assertions
func (e *Enforcer) validateRequest(rvals []interface{}) error {
	if len(rvals) == 0 {
		return errors.NewEnforcerInvalidRequestError("no parameters provided")
	}

	// 使用缓存的 requestTokens，避免每次遍历 model
	if tokens := e.requestTokens; tokens != nil && len(rvals) != len(tokens) {
		return errors.NewEnforcerInvalidRequestError(
			fmt.Sprintf("expected %d parameters, got %d", len(tokens), len(rvals)))
	}

	// 校验字符串参数不能为空（空 sub/obj/act 会导致误判）
	for i, val := range rvals {
		if s, ok := val.(string); ok && strings.TrimSpace(s) == "" {
			return errors.NewEnforcerInvalidRequestError(
				fmt.Sprintf("parameter at index %d is empty string", i))
		}
	}

	return nil
}

// computeShortCircuit 计算是否允许短路优化
// 当 effect 表达式为 some(where(p.eft==allow)) 模式时，匹配到 allow 即可返回
func (e *Enforcer) computeShortCircuit() bool {
	if e.effectEvaluator == nil {
		return false
	}
	expr := strings.ToLower(strings.TrimSpace(e.effectEvaluator.GetExpression()))
	return strings.Contains(expr, "some(where") && strings.Contains(expr, "allow") &&
		!strings.Contains(expr, "!some") && !strings.Contains(expr, "deny")
}

// validatePolicyRule 校验策略规则
// 检查：规则字段数量必须与模型 p 段定义匹配、字段值不能为空
// 防止无效策略规则导致匹配异常
func (e *Enforcer) validatePolicyRule(sec, ptype string, rule []string) error {
	if len(rule) == 0 {
		return errors.NewPolicyRuleInvalidError("empty policy rule")
	}

	// 获取 p 段定义的 token 数量
	policyAssertion := e.model.GetAssertion(sec)
	if policyAssertion == nil {
		for key, a := range e.model.GetAssertions() {
			if strings.HasPrefix(key, sec) {
				policyAssertion = a
				break
			}
		}
	}

	if policyAssertion != nil {
		expectedLen := len(policyAssertion.Tokens)
		if ptype != policy.PTypePolicy && ptype != "" {
			// 对于 g 段等其他策略段，不强制校验字段数量
			expectedLen = -1
		}
		if expectedLen > 0 && len(rule) != expectedLen {
			return errors.NewPolicyRuleInvalidError(
				fmt.Sprintf("expected %d fields for %s, got %d", expectedLen, ptype, len(rule)))
		}
	}

	// 校验字段值不能为空
	for i, field := range rule {
		if field == "" {
			return errors.NewPolicyRuleInvalidError(
				fmt.Sprintf("field at index %d is empty", i))
		}
	}

	return nil
}

// buildRequest 根据请求参数构建请求映射
// 使用缓存的 requestTokens 避免每次遍历 model assertions
//
// 性能优化：从 requestMapPool 复用 map，减少 doEnforce 热路径上的分配
// 调用方（doEnforce）负责在使用完毕后 clear 并 Put 回 pool
func (e *Enforcer) buildRequest(rvals ...interface{}) map[string]interface{} {
	tokens := e.requestTokens
	if tokens == nil {
		return nil
	}

	// 从 pool 复用 map，clear 残留数据（releaseRequest 已 clear，此处防御性清空）
	request := requestMapPool.Get()
	clear(request)

	for i, token := range tokens {
		if i < len(rvals) {
			request[token] = normalizeRequestValue(token, rvals[i])
		}
	}

	return request
}

// releaseRequest 将 request map 归还到 pool
// 在 doEnforce 结束后调用，clear 残留数据后 Put 回 pool
func (e *Enforcer) releaseRequest(request map[string]interface{}) {
	if request == nil {
		return
	}
	clear(request)
	requestMapPool.Put(request)
}

// normalizeRequestValue 规范请求参数值，根据 token 类型进行转换
// 性能优化：值未发生变化时直接返回原 interface{}，避免 string→interface{} 重新装箱分配
// 仅在 TrimSpace/路径规范化/动作规范化真正改变值时才分配新值
func normalizeRequestValue(token string, value interface{}) interface{} {
	s, ok := value.(string)
	if !ok {
		return value
	}
	trimmed := strings.TrimSpace(s)
	if trimmed == s {
		switch {
		case strings.HasSuffix(token, ".obj"):
			if normalized := normalizeKeyMatchPath(s, false); normalized != s {
				return normalized
			}
			return value // 路径规范化未改变值，返回原 interface 零装箱
		case strings.HasSuffix(token, ".act"):
			if normalized := normalizeHTTPAction(s); normalized != s {
				return normalized
			}
			return value
		default:
			return value // 无需规范化，返回原 interface 零装箱
		}
	}
	switch {
	case strings.HasSuffix(token, ".obj"):
		return normalizeKeyMatchPath(trimmed, false)
	case strings.HasSuffix(token, ".act"):
		return normalizeHTTPAction(trimmed)
	default:
		return trimmed
	}
}

// normalizeHTTPAction 规范 HTTP 动作，确保为大写
// 已是大写或非 HTTP 动作（如 read/write/exec）直接返回，零分配
// 仅小写 HTTP 动作触发 strings.ToUpper
func normalizeHTTPAction(action string) string {
	switch action {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "CONNECT", "TRACE":
		return action
	case "get", "post", "put", "patch", "delete", "head", "options", "connect", "trace":
		return strings.ToUpper(action)
	default:
		return action
	}
}

// getRequestTokens 获取 r 段的 token 列表
func (e *Enforcer) getRequestTokens() []string {
	reqAssertion := e.model.GetAssertion(model.SectionRequestDefinition)
	if reqAssertion == nil {
		for key, a := range e.model.GetAssertions() {
			if strings.HasPrefix(key, model.SectionRequestDefinition) {
				reqAssertion = a
				break
			}
		}
	}
	if reqAssertion == nil {
		return nil
	}
	return reqAssertion.Tokens
}

// getMatcherExpression 获取 m 段的匹配器表达式
// 例如：m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
func (e *Enforcer) getMatcherExpression() string {
	for key, assertion := range e.model.GetAssertions() {
		if strings.HasPrefix(key, model.SectionMatchers) {
			return assertion.Value
		}
	}
	return ""
}

// getPolicyAssertion 获取 p 段的策略断言
func (e *Enforcer) getPolicyAssertion() *model.Assertion {
	// 精确匹配 key=policy.PTypePolicy，避免匹配到 p2、p3 等额外策略段
	if assertion, ok := e.model.GetAssertions()[policy.PTypePolicy]; ok {
		return assertion
	}
	// 回退：遍历查找第一个策略段
	for key, assertion := range e.model.GetAssertions() {
		if key == model.SectionPolicyDefinition {
			return assertion
		}
	}
	return nil
}

// buildExtraPolicies 构建额外的策略段（排除指定策略）
func (e *Enforcer) buildExtraPolicies(excludeKey string) map[string]*PolicySegment {
	extra := make(map[string]*PolicySegment)
	for key, assertion := range e.model.GetAssertions() {
		if strings.HasPrefix(key, model.SectionPolicyDefinition) && key != excludeKey {
			extra[key] = &PolicySegment{
				Policies:  assertion.Policies,
				Assertion: assertion,
			}
		}
	}
	return extra
}

// evaluateEffectFromResults 根据匹配策略的效果列表评估最终结果
// 只评估匹配到的策略效果，而非全部策略
// 例如：e = some(where (p.eft == allow)) → 只要有一条匹配的策略 eft 为 allow 则允许
func (e *Enforcer) evaluateEffectFromResults(matchedEffects []string) (policy.EffectResult, error) {
	effectExpr := ""
	for key, assertion := range e.model.GetAssertions() {
		if strings.HasPrefix(key, model.SectionPolicyEffect) {
			effectExpr = assertion.Value
			break
		}
	}

	if effectExpr == "" {
		return policy.EffectAllowResult, nil
	}

	evaluator := policy.NewEffectEvaluator(effectExpr)
	return evaluator.Evaluate(matchedEffects)
}

// evaluateEffectFromResultsCached 使用缓存的 EffectEvaluator 评估策略效果
// 避免每次 Enforce 都遍历 model assertions 和创建新的 EffectEvaluator
func (e *Enforcer) evaluateEffectFromResultsCached(matchedEffects []string) (policy.EffectResult, error) {
	if e.effectEvaluator == nil {
		// 降级到原始方法（理论上不会发生，因为 initCachedFields 会初始化）
		return e.evaluateEffectFromResults(matchedEffects)
	}
	return e.effectEvaluator.Evaluate(matchedEffects)
}

// evaluateEffect 评估策略效果（基于全部策略，兼容旧接口）
func (e *Enforcer) evaluateEffect() (policy.EffectResult, error) {
	policyAssertion := e.getPolicyAssertion()
	if policyAssertion == nil {
		return policy.EffectDenyResult, nil
	}

	effects := make([]string, len(policyAssertion.Policies))
	for i, p := range policyAssertion.Policies {
		eft := "allow"
		for j, token := range policyAssertion.Tokens {
			if token == "p.eft" && j < len(p) {
				eft = p[j]
			}
		}
		effects[i] = eft
	}

	return e.evaluateEffectFromResults(effects)
}

// loadRoleLinks 从 g 段策略构建角色继承链
// 遍历所有 g 段策略，将角色关系注入角色管理器
// 支持域隔离：g 段策略的第 3 个字段作为 domain 参数
//
// 分布式一致性修复：加载前先 Clear role manager 的 hierarchy 和 cache，
// 防止已删除的 g 段策略残留旧继承关系（如删除用户角色后其他 pod reload 时仍保留旧 link）
// 原实现只追加 AddLink 不清理，导致用户仍拥有已删除角色的权限
func (e *Enforcer) loadRoleLinks() {
	e.roleMgr.Clear()
	for key, assertion := range e.model.GetAssertions() {
		if strings.HasPrefix(key, model.SectionRoleDefinition) {
			for _, p := range assertion.Policies {
				if len(p) >= 2 {
					domain := make([]string, 0)
					if len(p) > 2 {
						domain = append(domain, p[2])
					}
					if err := e.roleMgr.AddLink(p[0], p[1], domain...); err != nil {
						e.logger.WarnKV("Failed to add role link",
							"name1", p[0], "name2", p[1], "error", err.Error())
					}
				}
			}
		}
	}
}

// handlePolicyChange 处理策略变更事件
// 收到其他节点发布的变更事件后，按事件类型选择重载策略：
//
//   - 增量事件（PolicyAdded/Removed/Updated）：调用 reloadPolicyForRemoteChange
//     重载策略但保留 enforceCache，让短 TTL 自然消化变更，避免分布式命中率骤降
//   - 全量事件（PolicyReload/Cleared/FullSync）：调用 ReloadPolicy
//     全量清空 enforceCache 保证强一致性
//
// 该差异化策略是分布式高吞吐的关键：单条策略变更只影响极少数缓存键，
// 全量清空会让集群在 30s 内集中回源 matcher，瞬时 QPS 下跌
func (e *Enforcer) handlePolicyChange(event *policy.ChangeEvent) {
	e.logger.InfoKV("Received policy change event",
		"event_type", string(event.Type),
		"source", event.Source,
		"ptype", event.PType,
	)

	switch event.Type {
	case policy.EventTypePolicyAdded, policy.EventTypePolicyRemoved, policy.EventTypePolicyUpdated:
		// 增量事件：保留 enforceCache，让 30s TTL 自然过期
		if err := e.reloadPolicyForRemoteChange(); err != nil {
			e.logger.ErrorKV("Failed to reload policy for incremental change",
				"error", err.Error(),
				"event_type", string(event.Type),
			)
			return
		}
		e.logger.InfoKV("Policy incrementally reloaded (enforceCache preserved)",
			"event_type", string(event.Type),
			"source", event.Source,
		)
	default:
		// 全量事件（Reload/Cleared/FullSync）：全量清空 enforceCache
		if err := e.ReloadPolicy(); err != nil {
			e.logger.ErrorKV("Failed to reload policy for full change",
				"error", err.Error(),
				"event_type", string(event.Type),
			)
			return
		}
		e.logger.InfoKV("Policy fully reloaded after change event",
			"event_type", string(event.Type),
			"source", event.Source,
		)
	}
}

// notifyPolicyChange 通知策略变更
// 本节点修改策略后调用，通过 Pub/Sub 广播给其他节点
func (e *Enforcer) notifyPolicyChange(eventType policy.ChangeEventType, ptype string, oldPolicy, newPolicy []string) {
	if e.notifier == nil || !e.autoNotifyWatcher {
		return
	}

	event := policy.NewChangeEvent(eventType, ptype, "")
	event.OldPolicy = oldPolicy
	event.NewPolicy = newPolicy

	if err := e.notifier.Publish(context.Background(), event); err != nil {
		e.logger.WarnKV("Failed to publish policy change event",
			"error", err.Error(),
			"event_type", string(eventType),
		)
	}
}

// GetNotifier 获取策略变更通知器
func (e *Enforcer) GetNotifier() policy.PolicyNotifier {
	return e.notifier
}

// SetNotifier 设置策略变更通知器
// 设置后自动订阅变更事件
//
// 死锁防护：Close/Subscribe 在锁外执行
// 旧通知器的 EventLoop 回调 handlePolicyChange → ReloadPolicy 需要获取 e.mu.Lock
// 若在锁内调用 Close（内部 wg.Wait 等待 EventLoop 退出），会与回调形成死锁：
//
//	主 goroutine: 持 e.mu.Lock → Close → wg.Wait
//	EventLoop:    handlePolicyChange → ReloadPolicy → 等 e.mu.Lock
func (e *Enforcer) SetNotifier(notifier policy.PolicyNotifier) error {
	e.mu.Lock()
	oldNotifier := e.notifier
	e.notifier = notifier
	e.mu.Unlock()

	// 锁外订阅新通知器：成功后再关闭旧的，避免事件处理真空期
	if notifier != nil {
		if err := notifier.Subscribe(context.Background(), e.handlePolicyChange); err != nil {
			// Subscribe 失败，回滚 notifier 引用
			e.mu.Lock()
			e.notifier = oldNotifier
			e.mu.Unlock()
			e.logger.WarnKV("Failed to subscribe policy notifier", "error", err.Error())
			return err
		}
	}

	// 锁外关闭旧通知器：避免与 EventLoop 回调 handlePolicyChange 死锁
	if oldNotifier != nil {
		_ = oldNotifier.Close()
	}

	return nil
}
