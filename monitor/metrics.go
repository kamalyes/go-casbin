/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\monitor\metrics.go
 * @Description: 决策指标采集（无锁计数器）
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package monitor

import (
	"sync/atomic"
	"time"
)

// Metrics 决策指标采集器
// 全部计数器基于 atomic，Enforce 热路径只做一次 Add，不引入锁
type Metrics struct {
	enforceTotal   atomic.Int64
	enforceAllow   atomic.Int64
	enforceDeny    atomic.Int64
	enforceError   atomic.Int64
	policyUpdates  atomic.Int64
	policyReloads  atomic.Int64
	breakerRejects atomic.Int64
	totalLatencyNs atomic.Int64
	maxLatencyNs   atomic.Int64
}

// NewMetrics 创建指标采集器
func NewMetrics() *Metrics {
	return &Metrics{}
}

// RecordEnforce 记录一次决策
// allowed 为决策结果，err 非空表示决策过程出错（出错不计入 allow/deny）
func (m *Metrics) RecordEnforce(allowed bool, err error, latency time.Duration) {
	m.enforceTotal.Add(1)
	switch {
	case err != nil:
		m.enforceError.Add(1)
	case allowed:
		m.enforceAllow.Add(1)
	default:
		m.enforceDeny.Add(1)
	}

	ns := latency.Nanoseconds()
	m.totalLatencyNs.Add(ns)
	for {
		old := m.maxLatencyNs.Load()
		if ns <= old || m.maxLatencyNs.CompareAndSwap(old, ns) {
			break
		}
	}
}

// RecordPolicyUpdate 记录一次策略变更
func (m *Metrics) RecordPolicyUpdate() { m.policyUpdates.Add(1) }

// RecordPolicyReload 记录一次策略重载
func (m *Metrics) RecordPolicyReload() { m.policyReloads.Add(1) }

// RecordBreakerReject 记录一次熔断拒绝
func (m *Metrics) RecordBreakerReject() { m.breakerRejects.Add(1) }

// Snapshot 指标快照
type Snapshot struct {
	EnforceTotal   int64
	EnforceAllow   int64
	EnforceDeny    int64
	EnforceError   int64
	PolicyUpdates  int64
	PolicyReloads  int64
	BreakerRejects int64
	AvgLatency     time.Duration
	MaxLatency     time.Duration
	ErrorRate      float64 // 百分比
	AllowRate      float64 // 百分比
	CollectedAt    time.Time
}

// GetSnapshot 读取当前指标快照
func (m *Metrics) GetSnapshot() Snapshot {
	total := m.enforceTotal.Load()

	var avg time.Duration
	if total > 0 {
		avg = time.Duration(m.totalLatencyNs.Load() / total)
	}

	return Snapshot{
		EnforceTotal:   total,
		EnforceAllow:   m.enforceAllow.Load(),
		EnforceDeny:    m.enforceDeny.Load(),
		EnforceError:   m.enforceError.Load(),
		PolicyUpdates:  m.policyUpdates.Load(),
		PolicyReloads:  m.policyReloads.Load(),
		BreakerRejects: m.breakerRejects.Load(),
		AvgLatency:     avg,
		MaxLatency:     time.Duration(m.maxLatencyNs.Load()),
		ErrorRate:      percent(m.enforceError.Load(), total),
		AllowRate:      percent(m.enforceAllow.Load(), total),
		CollectedAt:    time.Now(),
	}
}

// Reset 清零所有计数器
func (m *Metrics) Reset() {
	m.enforceTotal.Store(0)
	m.enforceAllow.Store(0)
	m.enforceDeny.Store(0)
	m.enforceError.Store(0)
	m.policyUpdates.Store(0)
	m.policyReloads.Store(0)
	m.breakerRejects.Store(0)
	m.totalLatencyNs.Store(0)
	m.maxLatencyNs.Store(0)
}

func percent(part, total int64) float64 {
	if total == 0 {
		return 0
	}
	return float64(part) / float64(total) * 100
}
