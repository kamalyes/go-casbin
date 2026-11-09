/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\monitor\monitor_test.go
 * @Description: 指标与健康检查测试
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package monitor

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestRecordEnforceClassifiesOutcomes(t *testing.T) {
	m := NewMetrics()

	m.RecordEnforce(true, nil, time.Millisecond)
	m.RecordEnforce(false, nil, 2*time.Millisecond)
	m.RecordEnforce(true, errors.New("boom"), 3*time.Millisecond) // 出错不计入 allow

	s := m.GetSnapshot()
	if s.EnforceTotal != 3 || s.EnforceAllow != 1 || s.EnforceDeny != 1 || s.EnforceError != 1 {
		t.Fatalf("snapshot = %+v", s)
	}
	if s.AvgLatency != 2*time.Millisecond {
		t.Fatalf("AvgLatency = %v; want 2ms", s.AvgLatency)
	}
	if s.MaxLatency != 3*time.Millisecond {
		t.Fatalf("MaxLatency = %v; want 3ms", s.MaxLatency)
	}
	if s.AllowRate < 33.3 || s.AllowRate > 33.4 {
		t.Fatalf("AllowRate = %v; want ~33.33", s.AllowRate)
	}
	if s.CollectedAt.IsZero() {
		t.Error("CollectedAt should be set")
	}
}

func TestEmptySnapshotDoesNotDivideByZero(t *testing.T) {
	s := NewMetrics().GetSnapshot()

	if s.AvgLatency != 0 || s.AllowRate != 0 || s.ErrorRate != 0 {
		t.Fatalf("snapshot = %+v; want zero values", s)
	}
}

func TestMaxLatencyKeepsThePeak(t *testing.T) {
	m := NewMetrics()

	m.RecordEnforce(true, nil, 10*time.Millisecond)
	m.RecordEnforce(true, nil, time.Millisecond) // 更小的值不应覆盖峰值

	if got := m.GetSnapshot().MaxLatency; got != 10*time.Millisecond {
		t.Fatalf("MaxLatency = %v; want 10ms", got)
	}
}

func TestCountersAndReset(t *testing.T) {
	m := NewMetrics()

	m.RecordPolicyUpdate()
	m.RecordPolicyReload()
	m.RecordPolicyReload()
	m.RecordBreakerReject()
	m.RecordEnforce(true, nil, time.Millisecond)

	s := m.GetSnapshot()
	if s.PolicyUpdates != 1 || s.PolicyReloads != 2 || s.BreakerRejects != 1 {
		t.Fatalf("snapshot = %+v", s)
	}

	m.Reset()
	if s := m.GetSnapshot(); s.EnforceTotal != 0 || s.PolicyReloads != 0 || s.MaxLatency != 0 {
		t.Fatalf("after Reset = %+v; want all zero", s)
	}
}

func TestMetricsAreSafeUnderConcurrency(t *testing.T) {
	m := NewMetrics()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			m.RecordEnforce(i%2 == 0, nil, time.Duration(i)*time.Microsecond)
		}(i)
	}
	wg.Wait()

	if got := m.GetSnapshot().EnforceTotal; got != 100 {
		t.Fatalf("EnforceTotal = %d; want 100", got)
	}
}

func TestCheckEnforcer(t *testing.T) {
	hc := NewHealthChecker()

	if got := hc.CheckEnforcer(false, 10); got.Status != StatusUnhealthy {
		t.Errorf("disabled -> %s; want unhealthy", got.Status)
	}
	if got := hc.CheckEnforcer(true, 0); got.Status != StatusDegraded {
		t.Errorf("empty policy set -> %s; want degraded", got.Status)
	}
	got := hc.CheckEnforcer(true, 10)
	if got.Status != StatusHealthy {
		t.Errorf("enabled with policies -> %s; want healthy", got.Status)
	}
	if got.Name != "enforcer" || got.CheckedAt.IsZero() {
		t.Errorf("result = %+v; want name and timestamp populated", got)
	}
}

func TestCheckBreaker(t *testing.T) {
	hc := NewHealthChecker()

	cases := map[string]Status{
		"open":      StatusUnhealthy,
		"half-open": StatusDegraded,
		"closed":    StatusHealthy,
		"":          StatusHealthy,
	}
	for state, want := range cases {
		if got := hc.CheckBreaker(state); got.Status != want {
			t.Errorf("CheckBreaker(%q) = %s; want %s", state, got.Status, want)
		}
	}
}

func TestCheckDecisionsUsesErrorRate(t *testing.T) {
	hc := NewHealthChecker()

	if got := hc.CheckDecisions(Snapshot{}); got.Status != StatusHealthy {
		t.Errorf("no decisions -> %s; want healthy", got.Status)
	}
	if got := hc.CheckDecisions(Snapshot{EnforceTotal: 100, ErrorRate: 0.5}); got.Status != StatusHealthy {
		t.Errorf("0.5%% errors -> %s; want healthy", got.Status)
	}
	if got := hc.CheckDecisions(Snapshot{EnforceTotal: 100, ErrorRate: 5}); got.Status != StatusDegraded {
		t.Errorf("5%% errors -> %s; want degraded", got.Status)
	}
	if got := hc.CheckDecisions(Snapshot{EnforceTotal: 100, ErrorRate: 20}); got.Status != StatusUnhealthy {
		t.Errorf("20%% errors -> %s; want unhealthy", got.Status)
	}
}

func TestAggregateTakesTheWorstStatus(t *testing.T) {
	healthy := CheckResult{Status: StatusHealthy}
	degraded := CheckResult{Status: StatusDegraded}
	unhealthy := CheckResult{Status: StatusUnhealthy}

	if got := Aggregate(); got != StatusHealthy {
		t.Errorf("Aggregate() = %s; want healthy", got)
	}
	if got := Aggregate(healthy, healthy); got != StatusHealthy {
		t.Errorf("all healthy = %s; want healthy", got)
	}
	if got := Aggregate(healthy, degraded); got != StatusDegraded {
		t.Errorf("with degraded = %s; want degraded", got)
	}
	if got := Aggregate(degraded, unhealthy, healthy); got != StatusUnhealthy {
		t.Errorf("with unhealthy = %s; want unhealthy", got)
	}
}

func TestMonitorFacadeDelegates(t *testing.T) {
	m := New()

	if m.Metrics() == nil || m.Health() == nil {
		t.Fatal("facade should expose both collaborators")
	}

	m.RecordEnforce(true, nil, time.Millisecond)
	m.RecordPolicyUpdate()
	m.RecordPolicyReload()
	m.RecordBreakerReject()

	s := m.Snapshot()
	if s.EnforceTotal != 1 || s.PolicyUpdates != 1 || s.PolicyReloads != 1 || s.BreakerRejects != 1 {
		t.Fatalf("snapshot = %+v", s)
	}
}
