/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\adapter\gorm\schema.go
 * @Description: 建表与分片索引对齐
 *
 * 多租户按表分片时，表随租户开通陆续建出来：早期建的表可能缺后来加的索引，
 * 手工建的表可能压根没建。索引缺失不报错，只会让过滤加载悄悄退化成全表扫描，
 * 等租户数据涨起来才暴露成慢查询。这里提供冷启动批量对齐全部分片索引的能力。
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package gorm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// indexDef 一个索引的定义
type indexDef struct {
	// suffix 索引名后缀，完整名字由表名拼出
	suffix string
	// columns 索引列，顺序即索引顺序
	columns []string
}

// expectedIndexes 策略表应有的索引
//
//   - ptype：按策略类型过滤，LoadPolicy 分类型加载时用
//   - lookup：(ptype, v0, v1) 联合索引，覆盖「按主体查权限」
//     与「按主体 + 域查权限」两类最高频的过滤加载
var expectedIndexes = []indexDef{
	{suffix: "ptype", columns: []string{"ptype"}},
	{suffix: "lookup", columns: []string{"ptype", "v0", "v1"}},
}

// maxIdentifierLength 标识符长度上限，取 PostgreSQL 的 NAMEDATALEN - 1
//
// 超长标识符在 PostgreSQL 里会被静默截断，而且 pg_indexes.indexname 本身是
// name 类型，查询时字面量同样被截断到 63 字节再比较 —— 于是 HasIndex 会对一个
// 「其实没建出来」的索引返回 true。两个后缀不同但前 63 字节相同的索引名，
// 第二个就会被当成已存在而跳过：联合索引悄悄没建上，过滤加载退化成全表扫描，
// 全程没有任何报错。所以这里必须自己把名字控制在上限内。
const maxIdentifierLength = 63

// indexName 返回某张分片表上某个索引的完整名字
//
// 索引名必须带表名：SQLite 与 PostgreSQL 的索引名是库级唯一的，
// 所有分片共用一个固定名字时，第二张表建索引就会报 already exists。
//
// 表名过长时用稳定短哈希压缩：同一张表每次算出同样的名字（保证幂等），
// 不同表之间不会相撞，后缀保留在尾部，依然能看出是哪个索引。
func indexName(tableName, suffix string) string {
	name := "idx_" + tableName + "_" + suffix
	if len(name) <= maxIdentifierLength {
		return name
	}

	sum := sha256.Sum256([]byte(tableName))
	digest := hex.EncodeToString(sum[:])[:indexNameDigestLength]

	head := tableName
	if budget := maxIdentifierLength - len("idx__"+digest+"_") - len(suffix); budget < len(head) {
		if budget < 0 {
			budget = 0
		}
		head = head[:budget]
	}

	return "idx_" + head + "_" + digest + "_" + suffix
}

// indexNameDigestLength 压缩表名时保留的哈希位数，40 bit 足够避免分片间相撞
const indexNameDigestLength = 10

// EnsureTable 建表并对齐索引（幂等）
func EnsureTable(ctx context.Context, db *gorm.DB, tableName string) error {
	if tableName == "" {
		tableName = DefaultTableName
	}

	// Table 会被 Migrator 继承，因此 DDL 落在指定的分片表上而非模型默认表
	if err := db.WithContext(ctx).Table(tableName).AutoMigrate(&CasbinRule{}); err != nil {
		return err
	}

	return SyncTableIndexes(ctx, db, tableName)
}

// SyncTableIndexes 补齐单张策略表缺失的索引（幂等）
func SyncTableIndexes(ctx context.Context, db *gorm.DB, tableName string) error {
	if tableName == "" {
		tableName = DefaultTableName
	}

	scoped := db.WithContext(ctx).Table(tableName)
	migrator := scoped.Migrator()

	for _, def := range expectedIndexes {
		name := indexName(tableName, def.suffix)
		if migrator.HasIndex(&CasbinRule{}, name) {
			continue
		}
		if err := createIndex(ctx, db, tableName, name, def.columns); err != nil {
			return err
		}
	}

	return nil
}

// DropTableIndexes 删除单张策略表上由本适配器维护的索引（幂等）
// 仅用于测试与运维回滚，正常流程不需要
func DropTableIndexes(ctx context.Context, db *gorm.DB, tableName string) error {
	if tableName == "" {
		tableName = DefaultTableName
	}

	migrator := db.WithContext(ctx).Table(tableName).Migrator()
	for _, def := range expectedIndexes {
		name := indexName(tableName, def.suffix)
		if !migrator.HasIndex(&CasbinRule{}, name) {
			continue
		}
		if err := migrator.DropIndex(&CasbinRule{}, name); err != nil {
			return err
		}
	}

	return nil
}

// SyncAllShardIndexes 批量对齐所有分片表的索引
//
// prefix 为分片表名前缀（如 casbin_rule_），匹配到的每张表都会补齐缺失索引。
// 单张表失败不中断其余分片：返回已处理的表名与第一个错误，
// 让冷启动能「尽力对齐」，而不是因为一张坏表卡住整个进程。
func SyncAllShardIndexes(ctx context.Context, db *gorm.DB, prefix string) ([]string, error) {
	tables, err := db.WithContext(ctx).Migrator().GetTables()
	if err != nil {
		return nil, err
	}

	var (
		synced   []string
		firstErr error
	)
	for _, table := range tables {
		if prefix != "" && !strings.HasPrefix(table, prefix) {
			continue
		}

		if err := SyncTableIndexes(ctx, db, table); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		synced = append(synced, table)
	}

	return synced, firstErr
}

// createIndex 建一个索引
// gorm 的 Migrator.CreateIndex 只认模型 tag 里声明的索引名，
// 这里的名字是按表名算出来的，所以自己拼 DDL，标识符交给方言去转义
func createIndex(ctx context.Context, db *gorm.DB, tableName, name string, columns []string) error {
	stmt := &gorm.Statement{DB: db}

	quoted := make([]string, 0, len(columns))
	for _, column := range columns {
		quoted = append(quoted, stmt.Quote(clause.Column{Name: column}))
	}

	ddl := "CREATE INDEX " + stmt.Quote(clause.Column{Name: name}) +
		" ON " + stmt.Quote(clause.Table{Name: tableName}) +
		" (" + strings.Join(quoted, ", ") + ")"

	return db.WithContext(ctx).Exec(ddl).Error
}
