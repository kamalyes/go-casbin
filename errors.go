/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\errors.go
 * @Description: 企业层错误定义
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package casbin

import "errors"

var (
	// ErrDenyAll 全拒开关已打开，所有决策一律拒绝。
	//
	// 这是应急用的 kill switch：策略源不可用、或要立刻切断某个环境的访问时，
	// 宁可全拒并报错，也不要在没有有效策略的情况下放行。
	// 与官方 EnableEnforce(false) 不是一回事 —— 后者是「全部放行」，见 WithDenyAll 的注释。
	ErrDenyAll = errors.New("go-casbin: denied, the deny-all switch is on")

	// ErrBreakerOpen 熔断器已打开，下游存储调用被拒绝
	ErrBreakerOpen = errors.New("go-casbin: storage circuit breaker open")

	// ErrNoModel 未提供权限模型（WithModel / WithModelPath / WithModelText 三者必选其一）
	ErrNoModel = errors.New("go-casbin: no model provided, use WithModel, WithModelPath or WithModelText")

	// ErrNoPolicySource 配置了公共策略或免鉴权策略，但未提供可重建模型的来源
	ErrNoPolicySource = errors.New("go-casbin: in-memory policies require WithModelPath or WithModelText")

	// ErrNoAdapter 未配置策略存储，却调用了需要存储的操作。
	// 官方 Enforcer.LoadPolicy 在适配器为 nil 时会直接空指针 panic，
	// 本层改为返回此错误，避免 Watcher 回调把进程打挂。
	ErrNoAdapter = errors.New("go-casbin: no policy store configured, use WithAdapter or WithPolicyPath")
)
