/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\examples\gateway\main.go
 * @Description: 网关三路决策示例 —— 匿名放行 / 认证免鉴权 / 正常鉴权
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package main

import (
	"context"
	"fmt"
	"log"
	"time"

	casbin "github.com/kamalyes/go-casbin"
)

func main() {
	e, err := casbin.NewEnforcer(
		casbin.WithModelPath("../../resources/rbac_model.conf"),
		casbin.WithPolicyPath("../../resources/rbac_policy.csv"),

		// 网关三路决策：这两类策略只在内存，不落库，改完重启即生效
		casbin.WithPublicPolicies([][]string{
			{"/v1/login", "POST"},
			{"/v1/refresh", "POST"},
		}),
		casbin.WithAuthSkipPolicies([][]string{
			{"/v1/auth/user-info", "GET"},
		}),

		// 存储保护：只包裹真正触达存储的调用，Enforce 是纯内存决策不受影响
		casbin.WithBreaker("casbin-store", casbin.BreakerConfig{
			MaxFailures:  5,
			ResetTimeout: 10 * time.Second,
		}),
		casbin.WithRetry(casbin.RetryConfig{MaxAttempts: 3}),
	)
	if err != nil {
		log.Fatalf("创建执行器失败: %v", err)
	}
	defer func() { _ = e.Close() }()

	ctx := context.Background()

	requests := []struct {
		user, path, method string
	}{
		{"", "/v1/login", "POST"},              // 匿名放行
		{"carol", "/v1/auth/user-info", "GET"}, // 认证免鉴权
		{"alice", "/v1/users/42", "GET"},       // 正常鉴权，alice 是 admin
		{"bob", "/v1/users", "POST"},           // 正常鉴权，bob 只是 viewer
	}

	for _, r := range requests {
		decision, reason := decide(ctx, e, r.user, r.path, r.method)
		fmt.Printf("%-6s %-22s %-5s -> %-5v (%s)\n", orDash(r.user), r.path, r.method, decision, reason)
	}

	// 官方 API 经方法提升直接可用，无需 import casbin/v3
	roles, err := e.GetRolesForUser("alice")
	if err != nil {
		log.Fatalf("查询角色失败: %v", err)
	}
	fmt.Printf("\nalice 的角色: %v\n", roles)

	status, results := e.HealthCheck()
	fmt.Printf("健康状态: %s\n", status)
	for _, r := range results {
		fmt.Printf("  - %-10s %-10s %s\n", r.Name, r.Status, r.Message)
	}

	e.LogMetrics(ctx)
}

// decide 网关的三路决策顺序：匿名放行 -> 认证免鉴权 -> 正常鉴权
func decide(ctx context.Context, e *casbin.Enforcer, user, path, method string) (bool, string) {
	if ok, err := e.IsPublicPolicyCtx(ctx, path, method); err != nil {
		return false, "公共策略判定出错: " + err.Error()
	} else if ok {
		return true, "匿名放行"
	}

	if user == "" {
		return false, "需要登录"
	}

	if ok, err := e.IsAuthSkipPolicyCtx(ctx, path, method); err != nil {
		return false, "免鉴权判定出错: " + err.Error()
	} else if ok {
		return true, "已认证，跳过鉴权"
	}

	ok, err := e.EnforceCtx(ctx, user, path, method)
	if err != nil {
		return false, "鉴权出错: " + err.Error()
	}

	return ok, "正常鉴权"
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
