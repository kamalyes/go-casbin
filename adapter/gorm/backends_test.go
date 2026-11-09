/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\adapter\gorm\backends_test.go
 * @Description: 多后端测试脚手架
 *
 * 同一套用例在 SQLite 与 PostgreSQL 上各跑一遍。
 * SQLite 始终运行；PostgreSQL 需要设置环境变量才运行：
 *
 *	CASBIN_TEST_PG_DSN='postgres://user:pass@127.0.0.1:5432/casbin_test?sslmode=disable' go test ./...
 *
 * 只有真实数据库才能暴露方言差异 —— 标识符长度上限、索引名作用域、
 * 零值更新语义这些在 SQLite 上都看不出来。
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package gorm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/casbin/casbin/v3"
	"github.com/casbin/casbin/v3/model"
	"github.com/glebarez/sqlite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// pgDSNEnv PostgreSQL 测试库连接串的环境变量名
const pgDSNEnv = "CASBIN_TEST_PG_DSN"

// testTablePrefix 测试表统一前缀，便于清理时只删自己建的表
const testTablePrefix = "casbin_it_"

const modelText = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`

// harness 一次用例在某个后端上的运行环境
type harness struct {
	Backend string
	DB      *gorm.DB

	prefix string
}

// eachBackend 在每个可用后端上跑一遍 fn
func eachBackend(t *testing.T, fn func(t *testing.T, h *harness)) {
	t.Helper()

	type backend struct {
		name string
		open func(t *testing.T) *gorm.DB
	}

	list := []backend{{name: "sqlite", open: openSQLite}}
	if dsn := os.Getenv(pgDSNEnv); dsn != "" {
		list = append(list, backend{
			name: "postgres",
			open: func(t *testing.T) *gorm.DB { return openPostgres(t, dsn) },
		})
	}

	for _, b := range list {
		t.Run(b.name, func(t *testing.T) {
			h := &harness{Backend: b.name, DB: b.open(t), prefix: tablePrefixFor(t)}
			t.Cleanup(func() { h.dropOwnTables(t) })

			fn(t, h)
		})
	}
}

// openSQLite 打开一个仅属于本次用例的内存库
func openSQLite(t *testing.T) *gorm.DB {
	t.Helper()

	// 具名内存库：不同用例之间互不可见，省去跨用例污染
	dsn := "file:" + tablePrefixFor(t) + "?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { closeDB(db) })

	return db
}

// openPostgres 连接外部 PostgreSQL 测试库
func openPostgres(t *testing.T, dsn string) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	t.Cleanup(func() { closeDB(db) })

	return db
}

func closeDB(db *gorm.DB) {
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close()
	}
}

// Table 返回本次用例专属的表名，suffix 用于一个用例里需要多张表的场景
func (h *harness) Table(suffix ...string) string {
	name := h.prefix
	for _, s := range suffix {
		name += "_" + s
	}

	return name
}

// Adapter 在本次用例专属表上创建适配器
func (h *harness) Adapter(t *testing.T, opts ...Option) *Adapter {
	t.Helper()

	opts = append([]Option{WithTableName(h.Table())}, opts...)
	a, err := NewAdapter(h.DB, opts...)
	if err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}

	return a
}

// Enforcer 基于给定适配器创建官方执行器
func (h *harness) Enforcer(t *testing.T, a *Adapter) *casbin.Enforcer {
	t.Helper()

	m, err := model.NewModelFromString(modelText)
	if err != nil {
		t.Fatalf("NewModelFromString: %v", err)
	}
	e, err := casbin.NewEnforcer(m, a)
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}

	return e
}

// Model 返回一份新解析的模型
func (h *harness) Model(t *testing.T) model.Model {
	t.Helper()

	m, err := model.NewModelFromString(modelText)
	if err != nil {
		t.Fatalf("NewModelFromString: %v", err)
	}

	return m
}

// HasTable 判断表是否存在
func (h *harness) HasTable(name string) bool {
	return h.DB.Migrator().HasTable(name)
}

// IndexNames 直接从数据库系统表读出某张表上的索引（不含主键索引）
//
// 刻意不用 gorm 的 Migrator.HasIndex：PostgreSQL 的 pg_indexes.indexname 是
// name 类型，查询字面量在比较时会被截断到 63 字节，于是 HasIndex 会对一个
// 「其实没建出来」的长名索引返回 true —— 那正是本包要防的 bug 本身。
// 测试必须问数据库真实的索引清单，不能问同一个会说谎的接口。
func (h *harness) IndexNames(t *testing.T, table string) []string {
	t.Helper()

	var (
		names []string
		query string
	)
	switch h.Backend {
	case "postgres":
		query = "select indexname from pg_indexes where tablename = ? and indexname not like '%\\_pkey' order by 1"
	default:
		query = "select name from sqlite_master where type = 'index' and tbl_name = ? and name not like 'sqlite\\_%' order by 1"
	}

	if err := h.DB.Raw(query, table).Scan(&names).Error; err != nil {
		t.Fatalf("read indexes of %s: %v", table, err)
	}

	return names
}

// dropOwnTables 清掉本次用例建出来的表，绝不碰其他表
func (h *harness) dropOwnTables(t *testing.T) {
	t.Helper()

	tables, err := h.DB.Migrator().GetTables()
	if err != nil {
		return
	}

	for _, table := range tables {
		if !strings.HasPrefix(table, h.prefix) {
			continue
		}
		if err := h.DB.Migrator().DropTable(table); err != nil {
			t.Logf("清理表 %s 失败: %v", table, err)
		}
	}
}

// tablePrefixFor 由用例名算出一个短而稳定的表名前缀
//
// 不直接用 t.Name()：子测试名带斜杠不能做标识符，
// 而且 PostgreSQL 标识符上限 63 字节，长名字会被静默截断。
func tablePrefixFor(t *testing.T) string {
	sum := sha256.Sum256([]byte(t.Name()))

	return testTablePrefix + hex.EncodeToString(sum[:])[:12]
}

// recordingLogger 记录日志调用，用于验证 WithLogger 真的接进去了
type recordingLogger struct {
	errors []string
}

func (l *recordingLogger) InfoContextKV(context.Context, string, ...interface{}) {}
func (l *recordingLogger) WarnContextKV(context.Context, string, ...interface{}) {}
func (l *recordingLogger) ErrorContextKV(_ context.Context, msg string, _ ...interface{}) {
	l.errors = append(l.errors, msg)
}
