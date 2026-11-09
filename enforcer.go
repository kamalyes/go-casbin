/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\enforcer.go
 * @Description: 企业级执行器 —— 官方 casbin v3 之上的接入层
 *
 * 内嵌 *SyncedCachedEnforcer，官方全部 API（管理、RBAC、过滤、事务、Ctx 系列）
 * 经由方法提升直接可用；本层只补官方不提供的工程化能力：
 *   - fail-closed 开关：停用时拒绝而非放行
 *   - 熔断 + 重试：保护策略存储，只包裹真正触达存储的调用
 *   - 决策指标与健康检查
 *   - 结构化日志（最小 ctx 接口，不绑定日志库）
 *   - Watcher 回调兜底：官方对 WatcherEx 不装回调，这里补全
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package casbin

import (
	"context"
	"sync/atomic"
	"time"

	upstream "github.com/casbin/casbin/v3"
	"github.com/kamalyes/go-casbin/monitor"
)

// Enforcer 企业级执行器
type Enforcer struct {
	*SyncedCachedEnforcer // 官方能力全部提升到本类型

	opts    *Options
	log     Logger
	mon     *monitor.Monitor
	breaker *Breaker
	retry   *Retry

	denyAll        atomic.Bool // 全拒开关，见 WithDenyAll
	hasStore       bool        // 是否配置了策略存储（适配器或策略文件）
	metricsEnabled bool        // 是否在决策热路径上采集指标

	public   *SyncedCachedEnforcer // 匿名放行策略（内存态，不落库）
	authSkip *SyncedCachedEnforcer // 认证免鉴权策略（内存态，不落库）
}

// NewEnforcer 创建企业级执行器
//
// 模型三选一：WithModel / WithModelPath / WithModelText
// 存储可选：WithAdapter（任意 persist.Adapter 实现）或 WithPolicyPath（文件）
//
//	e, err := casbin.NewEnforcer(
//	    casbin.WithModelPath("resources/rbac_model.conf"),
//	    casbin.WithAdapter(gormAdapter),
//	    casbin.WithWatcher(kafkaWatcher),
//	    casbin.WithBreaker("casbin-store", casbin.BreakerConfig{MaxFailures: 5}),
//	    casbin.WithPublicPolicies([][]string{{"/v1/login", "POST"}}),
//	)
func NewEnforcer(opts ...Option) (*Enforcer, error) {
	o := defaultOptions()
	for _, opt := range opts {
		opt(o)
	}

	m, err := buildModel(o)
	if err != nil {
		return nil, err
	}

	core, err := newCore(m, o)
	if err != nil {
		return nil, err
	}

	e := &Enforcer{
		SyncedCachedEnforcer: core,
		opts:                 o,
		log:                  o.logger,
		mon:                  o.metrics,
		breaker:              o.breaker,
		retry:                o.retry,
		hasStore:             o.adapter != nil || o.policyPath != "",
		metricsEnabled:       o.metricsEnabled,
	}
	if e.log == nil {
		e.log = NopLogger{}
	}
	if e.mon == nil {
		e.mon = monitor.New()
	}
	e.denyAll.Store(o.denyAll)

	if err := e.applyRuntimeOptions(); err != nil {
		return nil, err
	}
	if err := e.buildInMemoryEnforcers(); err != nil {
		return nil, err
	}

	e.log.InfoContextKV(context.Background(), "casbin enforcer created",
		"deny_all", o.denyAll,
		"cache", o.cacheEnabled,
		"auto_save", o.autoSave,
		"adapter", o.adapter != nil,
		"watcher", o.watcher != nil,
		"public_policies", len(o.publicPolicies),
		"auth_skip_policies", len(o.authSkipPolicies),
	)

	return e, nil
}

// buildModel 按 WithModel > WithModelPath > WithModelText 的优先级构建模型
func buildModel(o *Options) (Model, error) {
	switch {
	case o.model != nil:
		return o.model, nil
	case o.modelPath != "":
		return NewModelFromFile(o.modelPath)
	case o.modelText != "":
		return NewModelFromString(o.modelText)
	default:
		return nil, ErrNoModel
	}
}

// newCore 构建底层官方执行器
func newCore(m Model, o *Options) (*SyncedCachedEnforcer, error) {
	if o.adapter != nil {
		return upstream.NewSyncedCachedEnforcer(m, o.adapter)
	}
	if o.policyPath != "" {
		return upstream.NewSyncedCachedEnforcer(m, NewFileAdapter(o.policyPath))
	}
	return upstream.NewSyncedCachedEnforcer(m)
}

// applyRuntimeOptions 应用运行期配置：自动落库、缓存、通知器、周期重载
func (e *Enforcer) applyRuntimeOptions() error {
	e.EnableAutoSave(e.opts.autoSave)
	e.EnableCache(e.opts.cacheEnabled)
	if e.opts.cacheExpire > 0 {
		e.SetExpireTime(e.opts.cacheExpire)
	}

	if w := e.opts.watcher; w != nil {
		if err := e.SetWatcher(w); err != nil {
			return err
		}
		// 官方 SetWatcher 对 WatcherEx 实现不装任何回调（注释写明「无通用实现」），
		// 不补这一步会出现「广播正常、本地不重载」的静默缺口，这里统一兜底。
		if err := w.SetUpdateCallback(e.onPolicyChanged); err != nil {
			return err
		}
	}

	if e.opts.autoLoad > 0 {
		e.StartAutoLoadPolicy(e.opts.autoLoad)
	}

	return nil
}

// onPolicyChanged 收到远端策略变更广播后的本地重载
func (e *Enforcer) onPolicyChanged(payload string) {
	ctx := context.Background()

	if !e.hasStore {
		e.log.WarnContextKV(ctx, "casbin got a policy change but no store is configured",
			"payload", payload)
		return
	}

	if err := e.LoadPolicy(); err != nil {
		e.log.ErrorContextKV(ctx, "casbin reload policy failed",
			"payload", payload, "error", err.Error())
		return
	}

	e.mon.RecordPolicyReload()
	e.log.DebugContextKV(ctx, "casbin policy reloaded", "payload", payload)
}

// ==================== 决策 ====================

// Enforce 权限决策
// 全拒开关打开时返回 ErrDenyAll，见 WithDenyAll
func (e *Enforcer) Enforce(rvals ...interface{}) (bool, error) {
	return e.EnforceCtx(context.Background(), rvals...)
}

// EnforceCtx 带上下文的权限决策
// 决策本身是纯内存运算（0 次存储往返），ctx 用于超时/取消感知与日志链路透传
func (e *Enforcer) EnforceCtx(ctx context.Context, rvals ...interface{}) (bool, error) {
	if e.denyAll.Load() {
		return false, ErrDenyAll
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}

	// 计时只在开启指标时付出：一对 time.Now()/time.Since 约 20~43ns，
	// 相对缓存命中的决策本身（60 多纳秒）不是小数
	var start time.Time
	if e.metricsEnabled {
		start = time.Now()
	}

	allowed, err := e.SyncedCachedEnforcer.Enforce(rvals...)

	if e.metricsEnabled {
		e.mon.RecordEnforce(allowed, err, time.Since(start))
	}

	if err != nil {
		e.log.ErrorContextKV(ctx, "casbin enforce failed",
			"request", rvals, "error", err.Error())
	}

	return allowed, err
}

// ==================== 全拒开关 ====================

// SetDenyAll 运行期打开或关闭全拒开关，见 WithDenyAll
func (e *Enforcer) SetDenyAll(denyAll bool) {
	if e.denyAll.Swap(denyAll) == denyAll {
		return
	}
	e.log.WarnContextKV(context.Background(), "casbin deny-all switch toggled", "deny_all", denyAll)
}

// IsDenyAll 返回全拒开关是否打开
func (e *Enforcer) IsDenyAll() bool { return e.denyAll.Load() }

// ==================== 存储操作保护 ====================

// Guarded 在熔断 + 重试保护下执行会触达存储的操作
//
// Enforce 不走这里：决策是纯内存运算，包熔断只会在存储故障时误伤本可正常服务的请求。
// 自行调用会写库的管理 API 时，用本方法包一层即可获得同样的保护：
//
//	err := e.Guarded(ctx, func() error {
//	    _, err := e.AddPolicy("alice", "data1", "read")
//	    return err
//	})
func (e *Enforcer) Guarded(ctx context.Context, fn func() error) error {
	call := fn
	if e.breaker != nil {
		call = func() error {
			err := e.breaker.Execute(fn)
			if err == ErrBreakerOpen {
				e.mon.RecordBreakerReject()
			}
			return err
		}
	}

	if e.retry != nil {
		return e.retry.Do(ctx, call)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	return call()
}

// LoadPolicy 从存储全量重载策略（受熔断 + 重试保护）
func (e *Enforcer) LoadPolicy() error {
	return e.LoadPolicyCtx(context.Background())
}

// LoadPolicyCtx 从存储全量重载策略
func (e *Enforcer) LoadPolicyCtx(ctx context.Context) error {
	if !e.hasStore {
		return ErrNoAdapter
	}

	return e.Guarded(ctx, func() error {
		return e.SyncedCachedEnforcer.LoadPolicy()
	})
}

// SavePolicy 将内存策略全量写回存储（受熔断 + 重试保护）
func (e *Enforcer) SavePolicy() error {
	return e.SavePolicyCtx(context.Background())
}

// SavePolicyCtx 将内存策略全量写回存储
func (e *Enforcer) SavePolicyCtx(ctx context.Context) error {
	if !e.hasStore {
		return ErrNoAdapter
	}

	return e.Guarded(ctx, func() error {
		return e.SyncedCachedEnforcer.SavePolicy()
	})
}

// LoadFilteredPolicyCtx 按过滤条件加载策略（多租户分片按需加载）
func (e *Enforcer) LoadFilteredPolicyCtx(ctx context.Context, filter interface{}) error {
	if !e.hasStore {
		return ErrNoAdapter
	}

	return e.Guarded(ctx, func() error {
		return e.SyncedCachedEnforcer.LoadFilteredPolicy(filter)
	})
}

// ==================== 可观测性 ====================

// Monitor 返回监控门面
func (e *Enforcer) Monitor() *monitor.Monitor { return e.mon }

// Core 返回底层官方执行器，用于访问被本层覆盖的原始方法
func (e *Enforcer) Core() *SyncedCachedEnforcer { return e.SyncedCachedEnforcer }

// Breaker 返回存储熔断器，未配置时为 nil
func (e *Enforcer) Breaker() *Breaker { return e.breaker }

// LogMetrics 以结构化日志输出一次指标快照
func (e *Enforcer) LogMetrics(ctx context.Context) {
	s := e.mon.Snapshot()
	e.log.InfoContextKV(ctx, "casbin metrics snapshot",
		"enforce_total", s.EnforceTotal,
		"enforce_allow", s.EnforceAllow,
		"enforce_deny", s.EnforceDeny,
		"enforce_error", s.EnforceError,
		"allow_rate", s.AllowRate,
		"error_rate", s.ErrorRate,
		"policy_reloads", s.PolicyReloads,
		"breaker_rejects", s.BreakerRejects,
		"avg_latency", s.AvgLatency.String(),
		"max_latency", s.MaxLatency.String(),
	)
}

// HealthCheck 执行一轮健康检查，返回汇总状态与各项明细
func (e *Enforcer) HealthCheck() (monitor.Status, []monitor.CheckResult) {
	health := e.mon.Health()

	// 取不到策略数时按 0 计，健康检查本身不应因此报错
	policies, _ := e.GetPolicy()

	results := []monitor.CheckResult{
		health.CheckEnforcer(!e.denyAll.Load(), len(policies)),
		health.CheckDecisions(e.mon.Snapshot()),
	}
	if e.breaker != nil {
		results = append(results, health.CheckBreaker(e.breaker.State().String()))
	}

	return monitor.Aggregate(results...), results
}

// Close 停止后台任务并释放通知器
func (e *Enforcer) Close() error {
	if e.opts.autoLoad > 0 {
		e.StopAutoLoadPolicy()
	}

	// 先打开全拒，再关通知器：避免关闭过程中仍有决策放行
	e.denyAll.Store(true)

	if w := e.opts.watcher; w != nil {
		w.Close()
	}

	e.log.InfoContextKV(context.Background(), "casbin enforcer closed")

	return nil
}
