/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\retry.go
 * @Description: 下游存储重试器（零依赖最小实现，指数退避 + 抖动）
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package casbin

import (
	"context"
	"math/rand/v2"
	"time"
)

// RetryConfig 重试配置
type RetryConfig struct {
	// MaxAttempts 最大尝试次数（含首次），<=0 时取 3
	MaxAttempts int
	// BaseDelay 首次退避时长，<=0 时取 50ms
	BaseDelay time.Duration
	// MaxDelay 退避时长上限，<=0 时取 2s
	MaxDelay time.Duration
	// Jitter 抖动比例 [0,1]，避免多副本同时重试打崩下游，默认 0.2
	Jitter float64
	// Retryable 判定错误是否值得重试，nil 时除 ErrBreakerOpen 外全部重试
	Retryable func(error) bool
}

// Retry 重试器
type Retry struct {
	cfg RetryConfig
}

// NewRetry 创建重试器
func NewRetry(cfg RetryConfig) *Retry {
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 3
	}
	if cfg.BaseDelay <= 0 {
		cfg.BaseDelay = 50 * time.Millisecond
	}
	if cfg.MaxDelay <= 0 {
		cfg.MaxDelay = 2 * time.Second
	}
	if cfg.Jitter < 0 {
		cfg.Jitter = 0
	}
	if cfg.Jitter > 1 {
		cfg.Jitter = 1
	}
	if cfg.Retryable == nil {
		// 熔断已打开说明下游正在故障，重试只会放大压力
		cfg.Retryable = func(err error) bool { return err != ErrBreakerOpen }
	}
	return &Retry{cfg: cfg}
}

// Do 执行 fn，失败时按指数退避重试
// ctx 被取消时立即返回 ctx.Err()，不再继续重试
func (r *Retry) Do(ctx context.Context, fn func() error) error {
	var err error

	for attempt := 0; attempt < r.cfg.MaxAttempts; attempt++ {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}

		if err = fn(); err == nil {
			return nil
		}
		if !r.cfg.Retryable(err) {
			return err
		}
		if attempt == r.cfg.MaxAttempts-1 {
			break
		}

		timer := time.NewTimer(r.backoff(attempt))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}

	return err
}

// backoff 计算第 attempt 次（从 0 起）失败后的等待时长
func (r *Retry) backoff(attempt int) time.Duration {
	delay := r.cfg.BaseDelay
	for i := 0; i < attempt && delay < r.cfg.MaxDelay; i++ {
		delay *= 2
	}
	if delay > r.cfg.MaxDelay {
		delay = r.cfg.MaxDelay
	}

	if r.cfg.Jitter > 0 {
		// 在 [delay*(1-jitter), delay] 区间内随机，只缩不放，不会超过 MaxDelay
		span := float64(delay) * r.cfg.Jitter
		delay -= time.Duration(rand.Float64() * span)
	}

	return delay
}
