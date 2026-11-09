/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\breaker.go
 * @Description: 下游存储熔断器（零依赖最小实现）
 *
 * 保护策略存储（MySQL / Redis / Kafka）故障时不把失败放大成级联故障。
 * 状态机：closed --失败达阈值--> open --静默期满--> half-open --连续成功--> closed
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package casbin

import (
	"sync"
	"time"
)

// BreakerState 熔断器状态
type BreakerState int32

const (
	BreakerClosed   BreakerState = iota // 闭合：正常放行
	BreakerOpen                         // 打开：直接拒绝，不触达下游
	BreakerHalfOpen                     // 半开：放行试探请求
)

// String 返回状态名
func (s BreakerState) String() string {
	switch s {
	case BreakerOpen:
		return "open"
	case BreakerHalfOpen:
		return "half-open"
	default:
		return "closed"
	}
}

// BreakerConfig 熔断器配置
type BreakerConfig struct {
	// MaxFailures 闭合状态下触发熔断的连续失败次数，<=0 时取 5
	MaxFailures int32
	// ResetTimeout 打开状态的静默期，期满后转半开，<=0 时取 10s
	ResetTimeout time.Duration
	// HalfOpenSuccesses 半开状态下转闭合所需的连续成功次数，<=0 时取 1
	HalfOpenSuccesses int32
	// OnStateChange 状态变更回调，在锁外调用，可安全地在其中打日志或上报指标
	OnStateChange func(from, to BreakerState)
}

// Breaker 熔断器
// 只用于会触达下游存储的调用；Enforce 是纯内存决策，不经过熔断器
type Breaker struct {
	name string
	cfg  BreakerConfig

	mu        sync.Mutex
	state     BreakerState
	failures  int32
	successes int32
	openedAt  time.Time
}

// NewBreaker 创建熔断器
func NewBreaker(name string, cfg BreakerConfig) *Breaker {
	if cfg.MaxFailures <= 0 {
		cfg.MaxFailures = 5
	}
	if cfg.ResetTimeout <= 0 {
		cfg.ResetTimeout = 10 * time.Second
	}
	if cfg.HalfOpenSuccesses <= 0 {
		cfg.HalfOpenSuccesses = 1
	}
	return &Breaker{name: name, cfg: cfg}
}

// Name 返回熔断器名称
func (b *Breaker) Name() string { return b.name }

// State 返回当前状态（会先结算静默期是否已满）
func (b *Breaker) State() BreakerState {
	b.mu.Lock()
	state, transition := b.refreshLocked()
	b.mu.Unlock()
	b.notify(transition)
	return state
}

// Execute 在熔断保护下执行 fn
// 熔断打开时直接返回 ErrBreakerOpen，不会调用 fn
func (b *Breaker) Execute(fn func() error) error {
	b.mu.Lock()
	_, entry := b.refreshLocked()
	if b.state == BreakerOpen {
		b.mu.Unlock()
		b.notify(entry)
		return ErrBreakerOpen
	}
	b.mu.Unlock()
	b.notify(entry)

	err := fn()

	b.mu.Lock()
	var exit *stateTransition
	if err != nil {
		exit = b.onFailureLocked()
	} else {
		exit = b.onSuccessLocked()
	}
	b.mu.Unlock()
	b.notify(exit)

	return err
}

// Reset 手动复位到闭合状态
func (b *Breaker) Reset() {
	b.mu.Lock()
	transition := b.transitionLocked(BreakerClosed)
	b.mu.Unlock()
	b.notify(transition)
}

// refreshLocked 结算打开状态的静默期，必要时转入半开
func (b *Breaker) refreshLocked() (BreakerState, *stateTransition) {
	if b.state == BreakerOpen && time.Since(b.openedAt) >= b.cfg.ResetTimeout {
		return BreakerHalfOpen, b.transitionLocked(BreakerHalfOpen)
	}
	return b.state, nil
}

func (b *Breaker) onFailureLocked() *stateTransition {
	switch b.state {
	case BreakerHalfOpen:
		// 试探失败，立刻回到打开状态，重新计时
		return b.transitionLocked(BreakerOpen)
	default:
		b.failures++
		if b.failures >= b.cfg.MaxFailures {
			return b.transitionLocked(BreakerOpen)
		}
		return nil
	}
}

func (b *Breaker) onSuccessLocked() *stateTransition {
	switch b.state {
	case BreakerHalfOpen:
		b.successes++
		if b.successes >= b.cfg.HalfOpenSuccesses {
			return b.transitionLocked(BreakerClosed)
		}
		return nil
	default:
		b.failures = 0
		return nil
	}
}

// transitionLocked 切换状态并重置计数，返回待在锁外投递的变更事件
func (b *Breaker) transitionLocked(to BreakerState) *stateTransition {
	from := b.state
	if from == to {
		return nil
	}

	b.state = to
	b.failures = 0
	b.successes = 0
	if to == BreakerOpen {
		b.openedAt = time.Now()
	}

	return &stateTransition{from: from, to: to}
}

// stateTransition 一次状态变更
type stateTransition struct {
	from BreakerState
	to   BreakerState
}

// notify 在锁外投递状态变更回调，避免回调里反向调用熔断器导致死锁
func (b *Breaker) notify(t *stateTransition) {
	if t == nil || b.cfg.OnStateChange == nil {
		return
	}
	b.cfg.OnStateChange(t.from, t.to)
}
