/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\publicpolicy.go
 * @Description: 网关三路决策原语 —— 匿名放行 / 认证免鉴权 / 正常鉴权
 *
 * 官方只提供一条 Enforce 决策路径，网关侧「哪些接口不用登录、哪些登录了但不查权限」
 * 要在业务层自己拼。本文件把这两类判定做成一等原语：
 *   - 策略只存在于内存，不写入适配器，每次启动从代码重新加载，改完即生效
 *   - 判定复用同一份 model 的 matcher，keyMatch / regexMatch 等语义与正式策略完全一致
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package casbin

import (
	"context"

	upstream "github.com/casbin/casbin/v3"
)

const (
	// SubjectAnonymous 匿名主体，用于匿名放行策略
	SubjectAnonymous = "__anonymous__"
	// SubjectAuthenticated 已认证主体，用于认证免鉴权策略
	SubjectAuthenticated = "__authenticated__"
)

// prependSubject 为每条策略头部插入主体标识
// 调用方只写路径与方法，避免手填主体出错
func prependSubject(subject string, policies [][]string) [][]string {
	if len(policies) == 0 {
		return nil
	}

	out := make([][]string, 0, len(policies))
	for _, p := range policies {
		if len(p) == 0 {
			continue
		}
		rule := make([]string, 0, len(p)+1)
		rule = append(rule, subject)
		rule = append(rule, p...)
		out = append(out, rule)
	}

	return out
}

// buildInMemoryEnforcers 构建承载内存态策略的两个独立执行器
// 独立实例意味着这些策略永远不会混进正式策略集，也不会被 SavePolicy 写进库
func (e *Enforcer) buildInMemoryEnforcers() error {
	var err error

	if e.public, err = e.newInMemoryEnforcer(e.opts.publicPolicies); err != nil {
		return err
	}
	if e.authSkip, err = e.newInMemoryEnforcer(e.opts.authSkipPolicies); err != nil {
		return err
	}

	return nil
}

// newInMemoryEnforcer 用同一份模型另建一个无适配器的执行器，装入给定策略
//
// 用带结果缓存的执行器：这两类策略在启动后就不再变，
// 而网关每个请求都要先问一遍，缓存命中率接近 100%。
// 不开缓存的话每次都要跑一遍完整 matcher，实测约 2µs，
// 会盖过真正鉴权的开销成为整条决策链的瓶颈。
func (e *Enforcer) newInMemoryEnforcer(policies [][]string) (*SyncedCachedEnforcer, error) {
	if len(policies) == 0 {
		return nil, nil
	}

	// 必须重新解析模型：直接复用主执行器的 Model 会让两边共享同一份策略集合
	m, err := e.rebuildModel()
	if err != nil {
		return nil, err
	}

	mem, err := upstream.NewSyncedCachedEnforcer(m)
	if err != nil {
		return nil, err
	}
	mem.EnableAutoSave(false)
	mem.EnableCache(true)

	if _, err := mem.AddPolicies(policies); err != nil {
		return nil, err
	}

	return mem, nil
}

// rebuildModel 重新解析一份全新的模型实例
func (e *Enforcer) rebuildModel() (Model, error) {
	switch {
	case e.opts.modelPath != "":
		return NewModelFromFile(e.opts.modelPath)
	case e.opts.modelText != "":
		return NewModelFromString(e.opts.modelText)
	default:
		// WithModel 传进来的实例无法安全复制：共用会污染正式策略集
		return nil, ErrNoPolicySource
	}
}

// IsPublicPolicy 判断请求是否命中匿名放行策略
// 入参只传路径与方法（RBAC Domain 模型再前置 domain），主体由内部补齐
//
//	ok, _ := e.IsPublicPolicy("/v1/login", "POST")
func (e *Enforcer) IsPublicPolicy(params ...string) (bool, error) {
	return e.IsPublicPolicyCtx(context.Background(), params...)
}

// IsPublicPolicyCtx 带上下文的匿名放行判定
func (e *Enforcer) IsPublicPolicyCtx(ctx context.Context, params ...string) (bool, error) {
	return e.matchInMemory(ctx, e.public, SubjectAnonymous, params)
}

// IsAuthSkipPolicy 判断请求是否命中认证免鉴权策略
// 语义为「需要通过 JWT 认证，但不再查权限」
//
//	ok, _ := e.IsAuthSkipPolicy("/v1/auth/user-info", "GET")
func (e *Enforcer) IsAuthSkipPolicy(params ...string) (bool, error) {
	return e.IsAuthSkipPolicyCtx(context.Background(), params...)
}

// IsAuthSkipPolicyCtx 带上下文的认证免鉴权判定
func (e *Enforcer) IsAuthSkipPolicyCtx(ctx context.Context, params ...string) (bool, error) {
	return e.matchInMemory(ctx, e.authSkip, SubjectAuthenticated, params)
}

// matchInMemory 在内存态执行器上做一次决策
// 未配置对应策略时直接返回 false，不构造请求也不计入指标
func (e *Enforcer) matchInMemory(ctx context.Context, mem *SyncedCachedEnforcer, subject string, params []string) (bool, error) {
	if mem == nil || len(params) == 0 {
		return false, nil
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}

	rvals := make([]interface{}, 0, len(params)+1)
	rvals = append(rvals, subject)
	for _, p := range params {
		rvals = append(rvals, p)
	}

	return mem.Enforce(rvals...)
}

// PublicPolicies 返回当前生效的匿名放行策略（含主体列）
func (e *Enforcer) PublicPolicies() ([][]string, error) {
	if e.public == nil {
		return nil, nil
	}
	return e.public.GetPolicy()
}

// AuthSkipPolicies 返回当前生效的认证免鉴权策略（含主体列）
func (e *Enforcer) AuthSkipPolicies() ([][]string, error) {
	if e.authSkip == nil {
		return nil, nil
	}
	return e.authSkip.GetPolicy()
}
