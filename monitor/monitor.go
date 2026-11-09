/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\monitor\monitor.go
 * @Description: 指标与健康检查的统一入口
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package monitor

import "time"

// Monitor 可观测性门面，聚合指标采集与健康检查
// 本包不打日志、不依赖任何日志库，日志由上层根据 Snapshot 自行输出
type Monitor struct {
	metrics *Metrics
	health  *HealthChecker
}

// New 创建监控门面
func New() *Monitor {
	return &Monitor{
		metrics: NewMetrics(),
		health:  NewHealthChecker(),
	}
}

// Metrics 返回指标采集器
func (m *Monitor) Metrics() *Metrics { return m.metrics }

// Health 返回健康检查器
func (m *Monitor) Health() *HealthChecker { return m.health }

// RecordEnforce 记录一次决策
func (m *Monitor) RecordEnforce(allowed bool, err error, latency time.Duration) {
	m.metrics.RecordEnforce(allowed, err, latency)
}

// RecordPolicyUpdate 记录一次策略变更
func (m *Monitor) RecordPolicyUpdate() { m.metrics.RecordPolicyUpdate() }

// RecordPolicyReload 记录一次策略重载
func (m *Monitor) RecordPolicyReload() { m.metrics.RecordPolicyReload() }

// RecordBreakerReject 记录一次熔断拒绝
func (m *Monitor) RecordBreakerReject() { m.metrics.RecordBreakerReject() }

// Snapshot 读取指标快照
func (m *Monitor) Snapshot() Snapshot { return m.metrics.GetSnapshot() }
