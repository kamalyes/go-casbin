/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\adapter\base\bench_test.go
 * @Description: 公共骨架基准测试
 *
 * 通知器的真实成本里，网络往返远大于编解码：这里把骨架自身的开销
 * 单独量出来，用于判断「要不要换二进制编码」这类问题值不值得做。
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package base

import (
	"context"
	"fmt"
	"testing"

	"github.com/casbin/casbin/v3/model"
)

func benchRules(n int) [][]string {
	rules := make([][]string, 0, n)
	for i := 0; i < n; i++ {
		rules = append(rules, []string{
			fmt.Sprintf("group%d", i), fmt.Sprintf("data%d", i/10), "read",
		})
	}

	return rules
}

// discard 不做任何事的传输层，用于隔离骨架自身开销
func discard(context.Context, []byte) error { return nil }

// ==================== 广播路径 ====================

func BenchmarkNotifierUpdate(b *testing.B) {
	n := NewNotifier("node-1", discard)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = n.Update()
	}
}

func BenchmarkNotifierUpdateForAddPolicy(b *testing.B) {
	n := NewNotifier("node-1", discard)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = n.UpdateForAddPolicy("p", "p", "alice", "data1", "read")
	}
}

func BenchmarkNotifierUpdateForAddPolicies(b *testing.B) {
	for _, n := range []int{10, 1000} {
		b.Run(fmt.Sprintf("rules=%d", n), func(b *testing.B) {
			notifier := NewNotifier("node-1", discard)
			rules := benchRules(n)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = notifier.UpdateForAddPolicies("p", "p", rules...)
			}
		})
	}
}

// ==================== 接收路径 ====================

func BenchmarkNotifierDispatchRemote(b *testing.B) {
	n := NewNotifier("node-1", discard)
	_ = n.SetUpdateCallback(func(string) {})

	payload, err := (&Event{Op: OpAddPolicy, Source: "node-2",
		Rules: [][]string{{"alice", "data1", "read"}}}).Marshal()
	if err != nil {
		b.Fatalf("Marshal: %v", err)
	}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n.Dispatch(ctx, payload)
	}
}

// BenchmarkNotifierDispatchSelf 自环事件的丢弃路径
// 自己发出的广播每个副本都会收到，这条路径的频率和广播次数同阶
func BenchmarkNotifierDispatchSelf(b *testing.B) {
	n := NewNotifier("node-1", discard)
	_ = n.SetUpdateCallback(func(string) { b.Fatal("self event reached the callback") })

	payload, err := (&Event{Op: OpAddPolicy, Source: "node-1"}).Marshal()
	if err != nil {
		b.Fatalf("Marshal: %v", err)
	}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n.Dispatch(ctx, payload)
	}
}

// ==================== 编解码分解 ====================

func BenchmarkEventMarshal(b *testing.B) {
	event := &Event{
		ID: "11111111-2222-3333-4444-555555555555", Source: "node-1",
		Op: OpAddPolicy, Sec: "p", PType: "p",
		Rules: [][]string{{"alice", "data1", "read"}}, TimestampMs: 1762000000000,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := event.Marshal(); err != nil {
			b.Fatalf("Marshal: %v", err)
		}
	}
}

func BenchmarkUnmarshalEvent(b *testing.B) {
	payload, err := (&Event{
		ID: "11111111-2222-3333-4444-555555555555", Source: "node-1",
		Op: OpAddPolicy, Sec: "p", PType: "p",
		Rules: [][]string{{"alice", "data1", "read"}}, TimestampMs: 1762000000000,
	}).Marshal()
	if err != nil {
		b.Fatalf("Marshal: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := UnmarshalEvent(payload); err != nil {
			b.Fatalf("UnmarshalEvent: %v", err)
		}
	}
}

// BenchmarkNewSource 每次广播都要生成一个事件 ID
func BenchmarkNewSource(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewSource()
	}
}

// ==================== 策略快照 ====================

func BenchmarkSnapshotPolicies(b *testing.B) {
	for _, n := range []int{100, 10000} {
		b.Run(fmt.Sprintf("rules=%d", n), func(b *testing.B) {
			m, err := model.NewModelFromString(modelText)
			if err != nil {
				b.Fatalf("NewModelFromString: %v", err)
			}
			for _, rule := range benchRules(n) {
				m.AddPolicy("p", "p", rule)
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = SnapshotPolicies(m)
			}
		})
	}
}

// ==================== 过滤条件 ====================

func BenchmarkMatchesFilter(b *testing.B) {
	rule := []string{"alice", "data1", "read"}
	values := []string{"alice", "", "read"}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = MatchesFilter(rule, 0, values)
	}
}

func BenchmarkFilterByPType(b *testing.B) {
	f := Filter{P: []string{"alice"}, G: []string{"alice"}}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = FilterByPType(f)
	}
}
