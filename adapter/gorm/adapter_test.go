/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\adapter\gorm\adapter_test.go
 * @Description: 适配器测试，SQLite 与 PostgreSQL 双后端
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package gorm

import (
	"errors"
	"testing"
)

func TestNewAdapterRequiresDB(t *testing.T) {
	if _, err := NewAdapter(nil); !errors.Is(err, ErrNoDB) {
		t.Fatalf("err = %v; want ErrNoDB", err)
	}
}

func TestAdapterRoundTripThroughEnforcer(t *testing.T) {
	eachBackend(t, func(t *testing.T, h *harness) {
		a := h.Adapter(t)
		e := h.Enforcer(t, a)

		if _, err := e.AddPolicy("admin", "data1", "read"); err != nil {
			t.Fatalf("AddPolicy: %v", err)
		}
		if _, err := e.AddGroupingPolicy("alice", "admin"); err != nil {
			t.Fatalf("AddGroupingPolicy: %v", err)
		}

		// 换一个 enforcer 从库里重新加载，验证真的落了库
		fresh := h.Enforcer(t, a)
		ok, err := fresh.Enforce("alice", "data1", "read")
		if err != nil {
			t.Fatalf("Enforce: %v", err)
		}
		if !ok {
			t.Fatal("policy did not survive a reload from the database")
		}
	})
}

func TestRemovePolicyDoesNotTouchLongerRules(t *testing.T) {
	eachBackend(t, func(t *testing.T, h *harness) {
		// 删除 {admin, data1} 不应连带删掉 {admin, data1, read}
		a := h.Adapter(t)

		if err := a.AddPolicy("p", "p", []string{"admin", "data1", "read"}); err != nil {
			t.Fatalf("AddPolicy 3-field: %v", err)
		}
		if err := a.AddPolicy("p", "p", []string{"admin", "data1"}); err != nil {
			t.Fatalf("AddPolicy 2-field: %v", err)
		}
		if err := a.RemovePolicy("p", "p", []string{"admin", "data1"}); err != nil {
			t.Fatalf("RemovePolicy: %v", err)
		}

		var rows []CasbinRule
		if err := a.DB().Table(a.TableName()).Find(&rows).Error; err != nil {
			t.Fatalf("Find: %v", err)
		}
		if len(rows) != 1 {
			t.Fatalf("len(rows) = %d; want only the 3-field rule left", len(rows))
		}
		if rows[0].V2 != "read" {
			t.Fatalf("remaining row = %+v; want the 3-field rule", rows[0])
		}
	})
}

func TestAdapterBatchAddAndRemovePolicies(t *testing.T) {
	eachBackend(t, func(t *testing.T, h *harness) {
		a := h.Adapter(t)
		e := h.Enforcer(t, a)

		rules := [][]string{
			{"admin", "data1", "read"},
			{"admin", "data2", "write"},
			{"viewer", "data1", "read"},
		}
		if _, err := e.AddPolicies(rules); err != nil {
			t.Fatalf("AddPolicies: %v", err)
		}

		if _, err := e.RemovePolicies(rules[:2]); err != nil {
			t.Fatalf("RemovePolicies: %v", err)
		}

		fresh := h.Enforcer(t, a)
		got, err := fresh.GetPolicy()
		if err != nil {
			t.Fatalf("GetPolicy: %v", err)
		}
		if len(got) != 1 || got[0][0] != "viewer" {
			t.Fatalf("policies = %v; want only the viewer rule", got)
		}
	})
}

func TestBatchOpsOnEmptyInputAreNoops(t *testing.T) {
	eachBackend(t, func(t *testing.T, h *harness) {
		a := h.Adapter(t)

		if err := a.AddPolicies("p", "p", nil); err != nil {
			t.Fatalf("AddPolicies(nil): %v", err)
		}
		if err := a.RemovePolicies("p", "p", nil); err != nil {
			t.Fatalf("RemovePolicies(nil): %v", err)
		}
	})
}

func TestAdapterRemoveFilteredPolicy(t *testing.T) {
	eachBackend(t, func(t *testing.T, h *harness) {
		a := h.Adapter(t)
		e := h.Enforcer(t, a)

		if _, err := e.AddPolicies([][]string{
			{"admin", "data1", "read"},
			{"admin", "data2", "write"},
			{"viewer", "data1", "read"},
		}); err != nil {
			t.Fatalf("AddPolicies: %v", err)
		}
		if _, err := e.RemoveFilteredPolicy(0, "admin"); err != nil {
			t.Fatalf("RemoveFilteredPolicy: %v", err)
		}

		fresh := h.Enforcer(t, a)
		got, err := fresh.GetPolicy()
		if err != nil {
			t.Fatalf("GetPolicy: %v", err)
		}
		if len(got) != 1 || got[0][0] != "viewer" {
			t.Fatalf("policies = %v; want only the viewer rule", got)
		}
	})
}

func TestUpdatePolicyCanClearAField(t *testing.T) {
	eachBackend(t, func(t *testing.T, h *harness) {
		// 结构体更新会忽略零值，把字段改成空串的更新必须也能生效
		a := h.Adapter(t)

		if err := a.AddPolicy("p", "p", []string{"admin", "data1", "read"}); err != nil {
			t.Fatalf("AddPolicy: %v", err)
		}
		if err := a.UpdatePolicy("p", "p",
			[]string{"admin", "data1", "read"}, []string{"admin", "data1"}); err != nil {
			t.Fatalf("UpdatePolicy: %v", err)
		}

		var rows []CasbinRule
		if err := a.DB().Table(a.TableName()).Find(&rows).Error; err != nil {
			t.Fatalf("Find: %v", err)
		}
		if len(rows) != 1 {
			t.Fatalf("len(rows) = %d; want 1", len(rows))
		}
		if rows[0].V2 != "" {
			t.Fatalf("V2 = %q; want it cleared", rows[0].V2)
		}
		if rows[0].V0 != "admin" || rows[0].V1 != "data1" {
			t.Fatalf("row = %+v; want admin/data1 kept", rows[0])
		}
	})
}

func TestUpdatePoliciesReplacesEachRule(t *testing.T) {
	eachBackend(t, func(t *testing.T, h *harness) {
		a := h.Adapter(t)
		e := h.Enforcer(t, a)

		old := [][]string{
			{"admin", "data1", "read"},
			{"viewer", "data2", "read"},
		}
		if _, err := e.AddPolicies(old); err != nil {
			t.Fatalf("AddPolicies: %v", err)
		}

		fresh := [][]string{
			{"admin", "data1", "write"},
			{"viewer", "data2", "write"},
		}
		if err := a.UpdatePolicies("p", "p", old, fresh); err != nil {
			t.Fatalf("UpdatePolicies: %v", err)
		}

		reloaded := h.Enforcer(t, a)
		got, err := reloaded.GetPolicy()
		if err != nil {
			t.Fatalf("GetPolicy: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("len = %d; want 2", len(got))
		}
		for _, rule := range got {
			if rule[2] != "write" {
				t.Fatalf("rule %v; want every act updated to write", rule)
			}
		}
	})
}

func TestUpdatePoliciesRejectsCountMismatch(t *testing.T) {
	eachBackend(t, func(t *testing.T, h *harness) {
		a := h.Adapter(t)

		err := a.UpdatePolicies("p", "p", [][]string{{"a"}}, [][]string{{"b"}, {"c"}})
		if !errors.Is(err, ErrRuleCountMismatch) {
			t.Fatalf("err = %v; want ErrRuleCountMismatch", err)
		}
	})
}

func TestUpdateFilteredPoliciesReplacesAndReturnsRemoved(t *testing.T) {
	eachBackend(t, func(t *testing.T, h *harness) {
		a := h.Adapter(t)
		e := h.Enforcer(t, a)

		if _, err := e.AddPolicies([][]string{
			{"admin", "data1", "read"},
			{"admin", "data2", "write"},
			{"viewer", "data1", "read"},
		}); err != nil {
			t.Fatalf("AddPolicies: %v", err)
		}

		removed, err := a.UpdateFilteredPolicies("p", "p",
			[][]string{{"admin", "data9", "read"}}, 0, "admin")
		if err != nil {
			t.Fatalf("UpdateFilteredPolicies: %v", err)
		}
		if len(removed) != 2 {
			t.Fatalf("removed = %v; want the two admin rules", removed)
		}
		for _, rule := range removed {
			if rule[0] != "admin" {
				t.Fatalf("removed %v; want only admin rules", rule)
			}
		}

		fresh := h.Enforcer(t, a)
		got, err := fresh.GetPolicy()
		if err != nil {
			t.Fatalf("GetPolicy: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("policies = %v; want the viewer rule plus the new admin rule", got)
		}
	})
}

func TestUpdateFilteredPoliciesRejectsOutOfRange(t *testing.T) {
	eachBackend(t, func(t *testing.T, h *harness) {
		a := h.Adapter(t)

		_, err := a.UpdateFilteredPolicies("p", "p", nil, 5, "a", "b")
		if !errors.Is(err, ErrFieldIndexOutOfRange) {
			t.Fatalf("err = %v; want ErrFieldIndexOutOfRange", err)
		}
	})
}

func TestLoadPolicyFailsLoudOnUnloadableRule(t *testing.T) {
	eachBackend(t, func(t *testing.T, h *harness) {
		// 策略行被悄悄丢掉会改变决策结果，必须报错而不是跳过
		a := h.Adapter(t)

		if err := a.AddPolicy("p", "p", []string{"admin", "data1"}); err != nil {
			t.Fatalf("AddPolicy: %v", err)
		}
		if err := a.LoadPolicy(h.Model(t)); err == nil {
			t.Fatal("LoadPolicy succeeded; want an error for a rule that does not fit the model")
		}
	})
}

func TestSavePolicyReplacesEverything(t *testing.T) {
	eachBackend(t, func(t *testing.T, h *harness) {
		a := h.Adapter(t)
		e := h.Enforcer(t, a)

		if _, err := e.AddPolicies([][]string{{"old", "data1", "read"}}); err != nil {
			t.Fatalf("AddPolicies: %v", err)
		}

		e.ClearPolicy()
		if _, err := e.AddPolicies([][]string{{"new", "data2", "write"}}); err != nil {
			t.Fatalf("AddPolicies: %v", err)
		}
		if err := e.SavePolicy(); err != nil {
			t.Fatalf("SavePolicy: %v", err)
		}

		fresh := h.Enforcer(t, a)
		got, err := fresh.GetPolicy()
		if err != nil {
			t.Fatalf("GetPolicy: %v", err)
		}
		if len(got) != 1 || got[0][0] != "new" {
			t.Fatalf("policies = %v; want only the new rule", got)
		}
	})
}

func TestSavePolicyOnEmptyModelClearsTheTable(t *testing.T) {
	eachBackend(t, func(t *testing.T, h *harness) {
		a := h.Adapter(t)
		e := h.Enforcer(t, a)

		if _, err := e.AddPolicies([][]string{{"admin", "data1", "read"}}); err != nil {
			t.Fatalf("AddPolicies: %v", err)
		}

		e.ClearPolicy()
		if err := e.SavePolicy(); err != nil {
			t.Fatalf("SavePolicy: %v", err)
		}

		var count int64
		if err := a.DB().Table(a.TableName()).Count(&count).Error; err != nil {
			t.Fatalf("Count: %v", err)
		}
		if count != 0 {
			t.Fatalf("count = %d; want the table emptied", count)
		}
	})
}

func TestLoadFilteredPolicyPushesDownToSQL(t *testing.T) {
	eachBackend(t, func(t *testing.T, h *harness) {
		a := h.Adapter(t)
		e := h.Enforcer(t, a)

		if _, err := e.AddPolicies([][]string{
			{"tenant-a-admin", "data1", "read"},
			{"tenant-b-admin", "data2", "read"},
		}); err != nil {
			t.Fatalf("AddPolicies: %v", err)
		}
		if _, err := e.AddGroupingPolicies([][]string{
			{"alice", "tenant-a-admin"},
			{"bob", "tenant-b-admin"},
		}); err != nil {
			t.Fatalf("AddGroupingPolicies: %v", err)
		}

		fresh := h.Enforcer(t, a)
		if err := fresh.LoadFilteredPolicy(&Filter{
			P: []string{"tenant-a-admin"},
			G: []string{"alice"},
		}); err != nil {
			t.Fatalf("LoadFilteredPolicy: %v", err)
		}

		policies, err := fresh.GetPolicy()
		if err != nil {
			t.Fatalf("GetPolicy: %v", err)
		}
		if len(policies) != 1 || policies[0][0] != "tenant-a-admin" {
			t.Fatalf("policies = %v; want only tenant-a rules", policies)
		}

		groups, err := fresh.GetGroupingPolicy()
		if err != nil {
			t.Fatalf("GetGroupingPolicy: %v", err)
		}
		if len(groups) != 1 || groups[0][0] != "alice" {
			t.Fatalf("grouping = %v; want only alice", groups)
		}
	})
}

func TestIsFilteredReflectsLoadMode(t *testing.T) {
	eachBackend(t, func(t *testing.T, h *harness) {
		a := h.Adapter(t)

		if err := a.LoadPolicy(h.Model(t)); err != nil {
			t.Fatalf("LoadPolicy: %v", err)
		}
		if a.IsFiltered() || a.IsFilteredCtx(t.Context()) {
			t.Fatal("IsFiltered should be false after a full load")
		}

		if err := a.LoadFilteredPolicy(h.Model(t), &Filter{P: []string{"admin"}}); err != nil {
			t.Fatalf("LoadFilteredPolicy: %v", err)
		}
		if !a.IsFiltered() || !a.IsFilteredCtx(t.Context()) {
			t.Fatal("IsFiltered should be true after a filtered load")
		}
	})
}

func TestLoadFilteredPolicyWithNilFilterLoadsEverything(t *testing.T) {
	eachBackend(t, func(t *testing.T, h *harness) {
		a := h.Adapter(t)
		e := h.Enforcer(t, a)

		if _, err := e.AddPolicies([][]string{
			{"admin", "data1", "read"},
			{"viewer", "data2", "read"},
		}); err != nil {
			t.Fatalf("AddPolicies: %v", err)
		}

		m := h.Model(t)
		if err := a.LoadFilteredPolicy(m, nil); err != nil {
			t.Fatalf("LoadFilteredPolicy(nil): %v", err)
		}
		if len(m["p"]["p"].Policy) != 2 {
			t.Fatalf("policies = %v; want both rules", m["p"]["p"].Policy)
		}
		if a.IsFiltered() {
			t.Error("a nil filter is a full load, IsFiltered should stay false")
		}
	})
}

func TestLoadFilteredPolicyRejectsUnknownFilter(t *testing.T) {
	eachBackend(t, func(t *testing.T, h *harness) {
		a := h.Adapter(t)

		if err := a.LoadFilteredPolicy(h.Model(t), "not a filter"); !errors.Is(err, ErrUnsupportedFilter) {
			t.Fatalf("err = %v; want ErrUnsupportedFilter", err)
		}
	})
}

func TestTableNameIsolatesTenants(t *testing.T) {
	eachBackend(t, func(t *testing.T, h *harness) {
		tenantA, err := NewAdapter(h.DB, WithTableName(h.Table("a")))
		if err != nil {
			t.Fatalf("NewAdapter a: %v", err)
		}
		tenantB, err := NewAdapter(h.DB, WithTableName(h.Table("b")))
		if err != nil {
			t.Fatalf("NewAdapter b: %v", err)
		}

		ea := h.Enforcer(t, tenantA)
		if _, err := ea.AddPolicy("admin", "data1", "read"); err != nil {
			t.Fatalf("AddPolicy: %v", err)
		}

		eb := h.Enforcer(t, tenantB)
		got, err := eb.GetPolicy()
		if err != nil {
			t.Fatalf("GetPolicy: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("tenant-b sees %v; want an empty policy set", got)
		}
	})
}

func TestWithAutoMigrateOffSkipsDDL(t *testing.T) {
	eachBackend(t, func(t *testing.T, h *harness) {
		// 由 DBA 统一管控 DDL 的环境要能完全关掉建表
		table := h.Table("nomigrate")

		if _, err := NewAdapter(h.DB, WithTableName(table), WithAutoMigrate(false)); err != nil {
			t.Fatalf("NewAdapter: %v", err)
		}
		if h.HasTable(table) {
			t.Fatal("WithAutoMigrate(false) must not create the table")
		}
	})
}

func TestWithLoggerReceivesAdapterEvents(t *testing.T) {
	eachBackend(t, func(t *testing.T, h *harness) {
		rec := &recordingLogger{}
		a := h.Adapter(t, WithLogger(rec))

		// 装不进模型的坏行会走错误日志
		if err := a.AddPolicy("p", "p", []string{"admin", "data1"}); err != nil {
			t.Fatalf("AddPolicy: %v", err)
		}
		if err := a.LoadPolicy(h.Model(t)); err == nil {
			t.Fatal("LoadPolicy should fail on an unloadable rule")
		}

		if len(rec.errors) == 0 {
			t.Fatal("the injected logger never saw the error")
		}
	})
}

func TestWithTableNameIgnoresEmptyValue(t *testing.T) {
	eachBackend(t, func(t *testing.T, h *harness) {
		a, err := NewAdapter(h.DB, WithTableName(h.Table()), WithTableName(""))
		if err != nil {
			t.Fatalf("NewAdapter: %v", err)
		}
		if a.TableName() != h.Table() {
			t.Fatalf("TableName = %q; want the earlier value kept", a.TableName())
		}
	})
}

func TestWithLoggerIgnoresNil(t *testing.T) {
	eachBackend(t, func(t *testing.T, h *harness) {
		if _, err := NewAdapter(h.DB, WithTableName(h.Table()), WithLogger(nil)); err != nil {
			t.Fatalf("NewAdapter: %v", err)
		}
	})
}
