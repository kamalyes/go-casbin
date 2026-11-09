/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\adapter\gorm\bench_test.go
 * @Description: 适配器基准测试
 *
 * 适配器的真实开销主体是数据库往返，不是行与规则的互转。
 * 所以这里量端到端的加载与写入，并把纯内存的互转单独列出来做对照 ——
 * 对照数据是用来判断「值不值得优化编解码」的，答案通常是不值得。
 *
 * 默认只在 SQLite 上跑；设了 CASBIN_TEST_PG_DSN 会额外在 PostgreSQL 上跑一遍。
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package gorm

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"github.com/casbin/casbin/v3/model"
	"github.com/glebarez/sqlite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// benchBackend 一个受测后端
type benchBackend struct {
	name string
	open func(b *testing.B) *gorm.DB
}

func benchBackends() []benchBackend {
	list := []benchBackend{{
		name: "sqlite",
		open: func(b *testing.B) *gorm.DB {
			db, err := gorm.Open(
				sqlite.Open("file:"+benchPrefix(b)+"?mode=memory&cache=shared"),
				&gorm.Config{Logger: logger.Discard},
			)
			if err != nil {
				b.Fatalf("open sqlite: %v", err)
			}
			b.Cleanup(func() { closeBenchDB(db) })

			return db
		},
	}}

	if dsn := os.Getenv(pgDSNEnv); dsn != "" {
		list = append(list, benchBackend{
			name: "postgres",
			open: func(b *testing.B) *gorm.DB {
				db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
				if err != nil {
					b.Fatalf("open postgres: %v", err)
				}
				b.Cleanup(func() { closeBenchDB(db) })

				return db
			},
		})
	}

	return list
}

func closeBenchDB(db *gorm.DB) {
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close()
	}
}

// benchPrefix 由基准名算出稳定的短表名前缀
func benchPrefix(b *testing.B) string {
	sum := sha256.Sum256([]byte(b.Name()))

	return testTablePrefix + hex.EncodeToString(sum[:])[:12]
}

// benchAdapter 建一张表并灌入 rules 条策略
func benchAdapter(b *testing.B, db *gorm.DB, rules int) *Adapter {
	b.Helper()

	table := benchPrefix(b)
	a, err := NewAdapter(db, WithTableName(table))
	if err != nil {
		b.Fatalf("NewAdapter: %v", err)
	}
	b.Cleanup(func() { _ = db.Migrator().DropTable(table) })

	if rules > 0 {
		if err := a.AddPolicies("p", "p", benchRules(rules)); err != nil {
			b.Fatalf("AddPolicies: %v", err)
		}
	}

	return a
}

func benchRules(n int) [][]string {
	out := make([][]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, []string{
			fmt.Sprintf("group%d", i), fmt.Sprintf("data%d", i/10), "read",
		})
	}

	return out
}

func benchModel(b *testing.B) model.Model {
	b.Helper()

	m, err := model.NewModelFromString(modelText)
	if err != nil {
		b.Fatalf("NewModelFromString: %v", err)
	}

	return m
}

// eachBenchBackend 在每个可用后端上跑一遍
func eachBenchBackend(b *testing.B, fn func(b *testing.B, db *gorm.DB)) {
	for _, backend := range benchBackends() {
		b.Run(backend.name, func(b *testing.B) {
			fn(b, backend.open(b))
		})
	}
}

// ==================== 加载路径 ====================

// BenchmarkLoadPolicy 冷启动全量加载，分片 Enforcer 懒加载也走这条路
func BenchmarkLoadPolicy(b *testing.B) {
	for _, n := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("rules=%d", n), func(b *testing.B) {
			eachBenchBackend(b, func(b *testing.B, db *gorm.DB) {
				a := benchAdapter(b, db, n)

				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if err := a.LoadPolicy(benchModel(b)); err != nil {
						b.Fatalf("LoadPolicy: %v", err)
					}
				}
			})
		})
	}
}

// BenchmarkLoadFilteredPolicy 过滤加载：条件下推到 SQL，只取一个租户的策略
// 与同规模的 BenchmarkLoadPolicy 对比即「按需加载」省下的量
func BenchmarkLoadFilteredPolicy(b *testing.B) {
	eachBenchBackend(b, func(b *testing.B, db *gorm.DB) {
		a := benchAdapter(b, db, 10000)
		filter := &Filter{P: []string{"group0"}}

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := a.LoadFilteredPolicy(benchModel(b), filter); err != nil {
				b.Fatalf("LoadFilteredPolicy: %v", err)
			}
		}
	})
}

// ==================== 写入路径 ====================

// BenchmarkAddPolicy 逐条写入
func BenchmarkAddPolicy(b *testing.B) {
	eachBenchBackend(b, func(b *testing.B, db *gorm.DB) {
		a := benchAdapter(b, db, 0)

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := a.AddPolicy("p", "p", []string{fmt.Sprintf("u%d", i), "data1", "read"}); err != nil {
				b.Fatalf("AddPolicy: %v", err)
			}
		}
	})
}

// BenchmarkAddPolicies 批量写入，报告的是每批的耗时
func BenchmarkAddPolicies(b *testing.B) {
	for _, n := range []int{100, 1000} {
		b.Run(fmt.Sprintf("batch=%d", n), func(b *testing.B) {
			eachBenchBackend(b, func(b *testing.B, db *gorm.DB) {
				a := benchAdapter(b, db, 0)
				rules := benchRules(n)

				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					b.StopTimer()
					if err := db.Exec("delete from " + a.TableName()).Error; err != nil {
						b.Fatalf("clear: %v", err)
					}
					b.StartTimer()

					if err := a.AddPolicies("p", "p", rules); err != nil {
						b.Fatalf("AddPolicies: %v", err)
					}
				}
			})
		})
	}
}

// ==================== 纯内存互转（对照）====================
//
// 这几项加起来在一次加载里占比极小，列出来是为了说明
// 优化行与规则的互转对总耗时没有意义。

func BenchmarkNewRow(b *testing.B) {
	rule := []string{"alice", "data1", "read"}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = newRow("p", rule)
	}
}

func BenchmarkRowPolicyArray(b *testing.B) {
	row := newRow("p", []string{"alice", "data1", "read"})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = row.policyArray()
	}
}

func BenchmarkRuleConditions(b *testing.B) {
	rule := []string{"alice", "data1", "read"}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ruleConditions("p", rule)
	}
}

func BenchmarkIndexName(b *testing.B) {
	b.Run("short", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = indexName("casbin_rule", "lookup")
		}
	})

	// 超长表名要走哈希压缩，比直接拼接贵，但只在建表时调用
	b.Run("hashed", func(b *testing.B) {
		long := "casbin_rule_tenant_" + fmt.Sprintf("%060d", 1)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = indexName(long, "lookup")
		}
	})
}
