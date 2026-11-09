/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-05-23 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-05-23 10:41:50
 * @FilePath: \go-casbin\monitor\health.go
 * @Description: 健康检查
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package monitor

import (
	"fmt"
	"time"
)

// Status 健康状态
type Status string

const (
	StatusHealthy   Status = "healthy"   // 健康
	StatusDegraded  Status = "degraded"  // 降级（可用但不理想）
	StatusUnhealthy Status = "unhealthy" // 不健康
)

// CheckResult 单项健康检查结果
type CheckResult struct {
	Name      string
	Status    Status
	Message   string
	CheckedAt time.Time
}

// HealthChecker 健康检查器
type HealthChecker struct{}

// NewHealthChecker 创建健康检查器
func NewHealthChecker() *HealthChecker {
	return &HealthChecker{}
}

// CheckEnforcer 检查执行器可用性
func (hc *HealthChecker) CheckEnforcer(enabled bool, policyCount int) CheckResult {
	switch {
	case !enabled:
		return result("enforcer", StatusUnhealthy, "enforcer disabled, all requests are denied")
	case policyCount == 0:
		return result("enforcer", StatusDegraded, "enforcer enabled but policy set is empty")
	default:
		return result("enforcer", StatusHealthy, fmt.Sprintf("%d policy rules loaded", policyCount))
	}
}

// CheckBreaker 检查熔断器状态
// state 取 go-toolbox/breaker 的状态字符串（closed / half-open / open）
func (hc *HealthChecker) CheckBreaker(state string) CheckResult {
	switch state {
	case "open":
		return result("breaker", StatusUnhealthy, "storage circuit breaker is open")
	case "half-open":
		return result("breaker", StatusDegraded, "storage circuit breaker is recovering")
	default:
		return result("breaker", StatusHealthy, "storage circuit breaker is closed")
	}
}

// CheckDecisions 基于决策指标检查运行质量
func (hc *HealthChecker) CheckDecisions(s Snapshot) CheckResult {
	switch {
	case s.EnforceTotal == 0:
		return result("decisions", StatusHealthy, "no decision recorded yet")
	case s.ErrorRate >= 10:
		return result("decisions", StatusUnhealthy, fmt.Sprintf("error rate %.2f%%", s.ErrorRate))
	case s.ErrorRate >= 1:
		return result("decisions", StatusDegraded, fmt.Sprintf("error rate %.2f%%", s.ErrorRate))
	default:
		return result("decisions", StatusHealthy, fmt.Sprintf("error rate %.2f%%", s.ErrorRate))
	}
}

// Aggregate 汇总多项检查，取最差状态
func Aggregate(results ...CheckResult) Status {
	worst := StatusHealthy
	for _, r := range results {
		switch r.Status {
		case StatusUnhealthy:
			return StatusUnhealthy
		case StatusDegraded:
			worst = StatusDegraded
		}
	}
	return worst
}

func result(name string, status Status, msg string) CheckResult {
	return CheckResult{Name: name, Status: status, Message: msg, CheckedAt: time.Now()}
}
