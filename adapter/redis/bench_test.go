/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\adapter\redis\bench_test.go
 * @Description: 适配器基准测试
 *
 * 用 miniredis 跑：它是进程内实现，没有真实网络往返与 fsync。
 * 所以这里的绝对值只能用来比较本包各条路径之间的相对开销，
 * 不能当成真实 Redis 的延迟 —— 真实部署里每次命令的 RTT
 * 通常是几十到几百微秒，会盖过下面所有的本地开销。
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package redis

import (
	"fmt"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/casbin/casbin/v3/model"
	"github.com/redis/go-redis/v9"
)

func benchRules(n int) [][]string {
	out := make([][]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, []string{
			fmt.Sprintf("group%d", i), fmt.Sprintf("data%d", i/10), "read",
		})
	}

	return out
}

func benchAdapter(b *testing.B, rules int) *Adapter {
	b.Helper()

	srv := miniredis.RunT(b)
	client := redis.NewClient(&redis.Options{Addr: srv.Addr()})
	b.Cleanup(func() { _ = client.Close() })

	a, err := NewAdapter(client, WithKeyPrefix("bench"))
	if err != nil {
		b.Fatalf("NewAdapter: %v", err)
	}

	if rules > 0 {
		if err := a.AddPolicies("p", "p", benchRules(rules)); err != nil {
			b.Fatalf("AddPolicies: %v", err)
		}
	}

	return a
}

func benchModel(b *testing.B) model.Model {
	b.Helper()

	m, err := model.NewModelFromString(modelText)
	if err != nil {
		b.Fatalf("NewModelFromString: %v", err)
	}

	return m
}

// ==================== 加载路径 ====================

func BenchmarkLoadPolicy(b *testing.B) {
	for _, n := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("rules=%d", n), func(b *testing.B) {
			a := benchAdapter(b, n)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := a.LoadPolicy(benchModel(b)); err != nil {
					b.Fatalf("LoadPolicy: %v", err)
				}
			}
		})
	}
}

// BenchmarkLoadFilteredPolicy Redis 的集合没有二级索引，
// 过滤只能取回整个集合再在内存里筛 —— 与 gorm 的 SQL 下推是两种成本结构
func BenchmarkLoadFilteredPolicy(b *testing.B) {
	a := benchAdapter(b, 10000)
	filter := &Filter{P: []string{"group0"}}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := a.LoadFilteredPolicy(benchModel(b), filter); err != nil {
			b.Fatalf("LoadFilteredPolicy: %v", err)
		}
	}
}

// ==================== 写入路径 ====================

func BenchmarkAddPolicy(b *testing.B) {
	a := benchAdapter(b, 0)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := a.AddPolicy("p", "p", []string{fmt.Sprintf("u%d", i), "data1", "read"}); err != nil {
			b.Fatalf("AddPolicy: %v", err)
		}
	}
}

func BenchmarkAddPolicies(b *testing.B) {
	for _, n := range []int{100, 1000} {
		b.Run(fmt.Sprintf("batch=%d", n), func(b *testing.B) {
			a := benchAdapter(b, 0)
			rules := benchRules(n)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := a.AddPolicies("p", "p", rules); err != nil {
					b.Fatalf("AddPolicies: %v", err)
				}
			}
		})
	}
}

// BenchmarkRemoveFilteredPolicy 取回整个集合、内存筛选、再 SREM
func BenchmarkRemoveFilteredPolicy(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		a := benchAdapter(b, 1000)
		b.StartTimer()

		if err := a.RemoveFilteredPolicy("p", "p", 0, "group0"); err != nil {
			b.Fatalf("RemoveFilteredPolicy: %v", err)
		}
	}
}

// ==================== 规则编解码（对照）====================
//
// 用 JSON 数组而非逗号拼接，是为了让带逗号的字段也能无损还原。
// 这两项在一次加载里占比很小，列出来说明没必要为此换编码。

func BenchmarkEncodeRule(b *testing.B) {
	rule := []string{"alice", "data1", "read"}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := encodeRule(rule); err != nil {
			b.Fatalf("encodeRule: %v", err)
		}
	}
}

func BenchmarkDecodeRule(b *testing.B) {
	member, err := encodeRule([]string{"alice", "data1", "read"})
	if err != nil {
		b.Fatalf("encodeRule: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := decodeRule(member); err != nil {
			b.Fatalf("decodeRule: %v", err)
		}
	}
}

func BenchmarkKeyBuilder(b *testing.B) {
	k := newKeyBuilder("casbin:tenant-a")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = k.rulesKey("p")
	}
}
