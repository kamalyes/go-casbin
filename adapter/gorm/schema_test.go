/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\adapter\gorm\schema_test.go
 * @Description: 建表与分片索引对齐测试，SQLite 与 PostgreSQL 双后端
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package gorm

import (
	"strings"
	"testing"
)

func TestEnsureTableCreatesTableAndIndexes(t *testing.T) {
	eachBackend(t, func(t *testing.T, h *harness) {
		table := h.Table("ensure")

		if err := EnsureTable(t.Context(), h.DB, table); err != nil {
			t.Fatalf("EnsureTable: %v", err)
		}
		if !h.HasTable(table) {
			t.Fatal("table was not created")
		}
		if got := h.IndexNames(t, table); len(got) != len(expectedIndexes) {
			t.Fatalf("indexes = %v; want all %d", got, len(expectedIndexes))
		}

		// 再跑一遍必须幂等
		if err := EnsureTable(t.Context(), h.DB, table); err != nil {
			t.Fatalf("second EnsureTable: %v", err)
		}
	})
}

func TestSyncTableIndexesIsIdempotent(t *testing.T) {
	eachBackend(t, func(t *testing.T, h *harness) {
		a := h.Adapter(t)

		for i := 0; i < 3; i++ {
			if err := SyncTableIndexes(t.Context(), h.DB, a.TableName()); err != nil {
				t.Fatalf("SyncTableIndexes #%d: %v", i, err)
			}
		}
		if got := h.IndexNames(t, a.TableName()); len(got) != len(expectedIndexes) {
			t.Fatalf("indexes = %v; want all %d", got, len(expectedIndexes))
		}
	})
}

func TestSyncAllShardIndexesRepairsMissingIndexes(t *testing.T) {
	eachBackend(t, func(t *testing.T, h *harness) {
		shards := []string{h.Table("shard_a"), h.Table("shard_b")}

		// 模拟手工建表：建了表但没建索引
		for _, table := range shards {
			if err := h.DB.Table(table).AutoMigrate(&CasbinRule{}); err != nil {
				t.Fatalf("AutoMigrate %s: %v", table, err)
			}
			if err := DropTableIndexes(t.Context(), h.DB, table); err != nil {
				t.Fatalf("DropTableIndexes %s: %v", table, err)
			}
			if got := h.IndexNames(t, table); len(got) != 0 {
				t.Fatalf("%s still has indexes %v before the repair", table, got)
			}
		}

		synced, err := SyncAllShardIndexes(t.Context(), h.DB, h.Table("shard_"))
		if err != nil {
			t.Fatalf("SyncAllShardIndexes: %v", err)
		}
		if len(synced) != len(shards) {
			t.Fatalf("synced = %v; want both shards", synced)
		}

		for _, table := range shards {
			if got := h.IndexNames(t, table); len(got) != len(expectedIndexes) {
				t.Errorf("%s indexes = %v; want all repaired", table, got)
			}
		}
	})
}

func TestSyncAllShardIndexesSkipsOtherTables(t *testing.T) {
	eachBackend(t, func(t *testing.T, h *harness) {
		other := h.Table("unrelated")
		shard := h.Table("only_a")

		for _, table := range []string{other, shard} {
			if err := h.DB.Table(table).AutoMigrate(&CasbinRule{}); err != nil {
				t.Fatalf("AutoMigrate %s: %v", table, err)
			}
		}

		synced, err := SyncAllShardIndexes(t.Context(), h.DB, h.Table("only_"))
		if err != nil {
			t.Fatalf("SyncAllShardIndexes: %v", err)
		}
		for _, table := range synced {
			if table == other {
				t.Fatal("the prefix filter let an unrelated table through")
			}
		}
		if len(synced) != 1 || synced[0] != shard {
			t.Fatalf("synced = %v; want just %s", synced, shard)
		}
	})
}

func TestShardTablesGetIndependentIndexNames(t *testing.T) {
	eachBackend(t, func(t *testing.T, h *harness) {
		// 固定索引名会让第二张分片表建索引时报 already exists：
		// SQLite 与 PostgreSQL 的索引名都是库级唯一的
		shards := []string{h.Table("x"), h.Table("y")}

		for _, table := range shards {
			if err := EnsureTable(t.Context(), h.DB, table); err != nil {
				t.Fatalf("EnsureTable %s: %v", table, err)
			}
		}

		seen := map[string]string{}
		for _, table := range shards {
			for _, name := range h.IndexNames(t, table) {
				if prev, dup := seen[name]; dup {
					t.Fatalf("index name %q shared by %s and %s", name, prev, table)
				}
				seen[name] = table
			}
		}
		if len(seen) != len(shards)*len(expectedIndexes) {
			t.Fatalf("got %d distinct index names; want %d", len(seen), len(shards)*len(expectedIndexes))
		}
	})
}

func TestLongTableNameStillGetsEveryIndex(t *testing.T) {
	eachBackend(t, func(t *testing.T, h *harness) {
		// 回归用例：PostgreSQL 的标识符上限是 63 字节且静默截断，
		// 而 pg_indexes.indexname 是 name 类型，查询字面量在比较时同样被截断，
		// 于是 HasIndex 会对一个「其实没建出来」的索引返回 true。
		// 一旦两个索引名的前 63 字节相同，联合索引就会被当成已存在而跳过，
		// 过滤加载悄悄退化成全表扫描，而且全程没有报错。
		table := h.Table(strings.Repeat("x", 40))

		if err := EnsureTable(t.Context(), h.DB, table); err != nil {
			t.Fatalf("EnsureTable: %v", err)
		}

		got := h.IndexNames(t, table)
		if len(got) != len(expectedIndexes) {
			t.Fatalf("indexes = %v; want all %d even with a long table name", got, len(expectedIndexes))
		}

		// 幂等性也必须保住
		if err := SyncTableIndexes(t.Context(), h.DB, table); err != nil {
			t.Fatalf("second SyncTableIndexes: %v", err)
		}
	})
}

func TestIndexNameStaysWithinIdentifierLimit(t *testing.T) {
	cases := []string{
		"casbin_rule",
		"casbin_rule_tenant_a",
		"casbin_rule_tenant_" + strings.Repeat("x", 40),
		strings.Repeat("y", 200),
	}

	for _, table := range cases {
		seen := map[string]bool{}
		for _, def := range expectedIndexes {
			name := indexName(table, def.suffix)

			if len(name) > maxIdentifierLength {
				t.Errorf("indexName(%d-char table, %s) = %d bytes; want <= %d",
					len(table), def.suffix, len(name), maxIdentifierLength)
			}
			if seen[name] {
				t.Errorf("indexName collided on %q for table of %d chars", name, len(table))
			}
			seen[name] = true
		}
	}
}

func TestIndexNameIsStableAndTableSpecific(t *testing.T) {
	long := strings.Repeat("z", 80)

	// 同一张表每次必须算出同样的名字，否则同步不幂等
	first := indexName(long, "lookup")
	if second := indexName(long, "lookup"); first != second {
		t.Fatalf("indexName is not stable: %q vs %q", first, second)
	}

	// 不同表即使前缀相同也不能撞
	a := indexName(strings.Repeat("z", 80)+"_a", "lookup")
	b := indexName(strings.Repeat("z", 80)+"_b", "lookup")
	if a == b {
		t.Fatalf("two different long table names share an index name: %q", a)
	}
}

func TestEnsureTableFallsBackToDefaultName(t *testing.T) {
	eachBackend(t, func(t *testing.T, h *harness) {
		if h.Backend == "postgres" {
			// 默认表名不带用例前缀，清理钩子覆盖不到，跳过以免留垃圾
			t.Skip("default table name is not namespaced for the shared database")
		}

		if err := EnsureTable(t.Context(), h.DB, ""); err != nil {
			t.Fatalf("EnsureTable(\"\"): %v", err)
		}
		if !h.HasTable(DefaultTableName) {
			t.Fatalf("table %s was not created", DefaultTableName)
		}
	})
}
