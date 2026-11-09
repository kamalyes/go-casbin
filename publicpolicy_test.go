/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\publicpolicy_test.go
 * @Description: 网关三路决策原语测试
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package casbin

import (
	"context"
	"errors"
	"testing"
)

func TestIsPublicPolicyMatchesWithModelSemantics(t *testing.T) {
	e := newTestEnforcer(t, WithPublicPolicies([][]string{
		{"/v1/login", "POST"},
		{"/v1/public/*", "GET"}, // 通配要和正式策略一样走 keyMatch2
	}))

	cases := []struct {
		path, method string
		want         bool
	}{
		{"/v1/login", "POST", true},
		{"/v1/login", "GET", false},
		{"/v1/public/docs", "GET", true},
		{"/v1/users", "GET", false},
	}
	for _, c := range cases {
		got, err := e.IsPublicPolicy(c.path, c.method)
		if err != nil {
			t.Fatalf("IsPublicPolicy(%s,%s): %v", c.path, c.method, err)
		}
		if got != c.want {
			t.Errorf("IsPublicPolicy(%s,%s) = %v; want %v", c.path, c.method, got, c.want)
		}
	}
}

func TestPublicPoliciesNeverReachTheMainPolicySet(t *testing.T) {
	e := newTestEnforcer(t, WithPublicPolicies([][]string{{"/v1/login", "POST"}}))

	// 内存态策略不能混进正式策略集，否则 SavePolicy 会把它们写进库
	main, err := e.GetPolicy()
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if len(main) != 0 {
		t.Fatalf("main policy set = %v; want empty", main)
	}

	public, err := e.PublicPolicies()
	if err != nil {
		t.Fatalf("PublicPolicies: %v", err)
	}
	if len(public) != 1 || public[0][0] != SubjectAnonymous {
		t.Fatalf("public = %v; want one rule carrying the anonymous subject", public)
	}
}

func TestIsAuthSkipPolicy(t *testing.T) {
	e := newTestEnforcer(t, WithAuthSkipPolicies([][]string{{"/v1/auth/user-info", "GET"}}))

	ok, err := e.IsAuthSkipPolicy("/v1/auth/user-info", "GET")
	if err != nil {
		t.Fatalf("IsAuthSkipPolicy: %v", err)
	}
	if !ok {
		t.Error("IsAuthSkipPolicy = false; want true")
	}

	skip, err := e.AuthSkipPolicies()
	if err != nil {
		t.Fatalf("AuthSkipPolicies: %v", err)
	}
	if len(skip) != 1 || skip[0][0] != SubjectAuthenticated {
		t.Fatalf("authSkip = %v; want one rule carrying the authenticated subject", skip)
	}
}

func TestUnconfiguredPrimitivesReturnFalse(t *testing.T) {
	e := newTestEnforcer(t)

	if ok, err := e.IsPublicPolicy("/v1/login", "POST"); err != nil || ok {
		t.Fatalf("IsPublicPolicy = %v, %v; want false, nil", ok, err)
	}
	if ok, err := e.IsAuthSkipPolicy("/v1/x", "GET"); err != nil || ok {
		t.Fatalf("IsAuthSkipPolicy = %v, %v; want false, nil", ok, err)
	}
	if got, err := e.PublicPolicies(); err != nil || got != nil {
		t.Fatalf("PublicPolicies = %v, %v; want nil, nil", got, err)
	}
	if got, err := e.AuthSkipPolicies(); err != nil || got != nil {
		t.Fatalf("AuthSkipPolicies = %v, %v; want nil, nil", got, err)
	}
}

func TestInMemoryPoliciesNeedARebuildableModel(t *testing.T) {
	// WithModel 传进来的实例无法安全复制，共用会污染正式策略集
	m, err := NewModelFromString(rbacModelText)
	if err != nil {
		t.Fatalf("NewModelFromString: %v", err)
	}

	_, err = NewEnforcer(
		WithModel(m),
		WithPublicPolicies([][]string{{"/v1/login", "POST"}}),
	)
	if !errors.Is(err, ErrNoPolicySource) {
		t.Fatalf("err = %v; want ErrNoPolicySource", err)
	}
}

func TestPrimitivesHonourCancellation(t *testing.T) {
	e := newTestEnforcer(t, WithPublicPolicies([][]string{{"/v1/login", "POST"}}))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := e.IsPublicPolicyCtx(ctx, "/v1/login", "POST"); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v; want context.Canceled", err)
	}
}

func TestPrependSubject(t *testing.T) {
	got := prependSubject("S", [][]string{{"/a", "GET"}, {}, {"/b"}})

	if len(got) != 2 {
		t.Fatalf("len = %d; want 2 (the empty rule is dropped)", len(got))
	}
	if got[0][0] != "S" || got[0][1] != "/a" || got[0][2] != "GET" {
		t.Fatalf("got[0] = %v; want [S /a GET]", got[0])
	}
	if prependSubject("S", nil) != nil {
		t.Error("prependSubject(nil) should stay nil")
	}
}
