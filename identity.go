/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\identity.go
 * @Description: 域身份绑定 —— 租户 ↔ 域名
 *
 * 两条路径共用同一份 p2 策略，保证登录反查与授权正向校验的数据一致：
 *   1. 正向校验 EnforceTenantHostBinding：走 Enforce 匹配，act == HOST
 *   2. 反向查询 ResolveTenantByHost：按 act=HOST 过滤 p2，读 dom 列拿 tenantID
 *
 * 模型需声明 p2 段，形如：
 *   [policy_definition]
 *   p2 = sub_rule, dom, obj, act
 *   [matchers]
 *   m = ... || (eval(p2.sub_rule) && r.dom == p2.dom && r.obj == p2.obj && r.act == p2.act)
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package casbin

import (
	"context"
	"net"
	"strings"
)

// DefaultIdentitySuffix 域身份绑定默认使用的模型段后缀
const DefaultIdentitySuffix = "2"

const (
	// domainIdentityAction 域身份绑定动作（正向校验与反向查询共用）
	domainIdentityAction = "HOST"
	// domainIdentityResourcePrefix 资源前缀
	domainIdentityResourcePrefix = "domain::"
)

// TenantHostBinding 租户域名绑定关系
type TenantHostBinding struct {
	TenantID string
	Host     string
}

// NormalizeDomainHost 归一化请求域名
// 依次处理：X-Forwarded-Host 多值取首、剥离 host:port 端口、去 IPv6 方括号、小写、去尾点
func NormalizeDomainHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}

	if forwarded := strings.Split(host, ",")[0]; strings.TrimSpace(forwarded) != "" {
		host = strings.TrimSpace(forwarded)
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")

	return strings.ToLower(strings.TrimSuffix(host, "."))
}

// identityPType 返回域身份绑定使用的策略类型名（如 "p2"）
func (e *Enforcer) identityPType() string {
	return "p" + e.opts.identitySuffix
}

// identitySubRule 返回 eval(p2.sub_rule) 中存放的主体规则
//
// 规则里的请求段必须与决策时使用的 RType 一致：这次决策走 r2 段，
// 求值环境里的参数名就是 r2_sub，写成 r.sub 会报 "No parameter 'r_sub' found"。
func (e *Enforcer) identitySubRule() string {
	return `r` + e.opts.identitySuffix + `.sub != ""`
}

// normalizeHost 应用配置的归一化函数
func (e *Enforcer) normalizeHost(host string) string {
	if e.opts.normalizeHost != nil {
		return e.opts.normalizeHost(host)
	}
	return NormalizeDomainHost(host)
}

// SyncTenantHostBindings 批量同步租户域名绑定
// tenantID 为空时直接跳过（无域名限制的域）；addHosts 新增、removeHosts 删除
func (e *Enforcer) SyncTenantHostBindings(ctx context.Context, tenantID string, addHosts, removeHosts []string) error {
	if tenantID == "" {
		return nil
	}

	return e.Guarded(ctx, func() error {
		for _, host := range addHosts {
			if err := e.addTenantHostBinding(tenantID, host); err != nil {
				return err
			}
		}
		for _, host := range removeHosts {
			if err := e.removeTenantHostBinding(tenantID, host); err != nil {
				return err
			}
		}
		return nil
	})
}

// EnforceTenantHostBinding 校验 tenantID 是否绑定了 host（正向校验）
// 仅用于已认证场景，三个参数任一为空即判定不通过
func (e *Enforcer) EnforceTenantHostBinding(ctx context.Context, tenantID, userID, host string) (bool, error) {
	host = e.normalizeHost(host)
	if tenantID == "" || userID == "" || host == "" {
		return false, nil
	}

	// 必须切到独立段：官方一次决策只遍历一种策略类型
	return e.EnforceCtx(ctx, NewEnforceContext(e.opts.identitySuffix),
		userID, tenantID, domainIdentityResourcePrefix+host, domainIdentityAction)
}

// ResolveTenantByHost 按 host 反查绑定的 tenantID
// 供登录、忘记密码等未认证场景解析租户；返回空串表示未绑定
func (e *Enforcer) ResolveTenantByHost(host string) (string, error) {
	host = e.normalizeHost(host)
	if host == "" {
		return "", nil
	}

	resource := domainIdentityResourcePrefix + host
	bindings, err := e.GetFilteredNamedPolicy(e.identityPType(), 2, resource, domainIdentityAction)
	if err != nil {
		return "", err
	}

	for _, p := range bindings {
		if len(p) > 1 && p[1] != "" {
			return p[1], nil
		}
	}

	return "", nil
}

// ListTenantHostBindings 列出域名绑定
// tenantID 为空列出全部租户，非空只列出指定租户
func (e *Enforcer) ListTenantHostBindings(tenantID string) ([]TenantHostBinding, error) {
	bindings := make([]TenantHostBinding, 0)

	rules, err := e.GetFilteredNamedPolicy(e.identityPType(), 3, domainIdentityAction)
	if err != nil {
		return nil, err
	}

	for _, p := range rules {
		// p = [sub_rule, tenantID, domain::host, action]
		if len(p) < 3 || p[1] == "" {
			continue
		}
		if tenantID != "" && p[1] != tenantID {
			continue
		}

		host := strings.TrimPrefix(p[2], domainIdentityResourcePrefix)
		if host == "" {
			continue
		}

		bindings = append(bindings, TenantHostBinding{TenantID: p[1], Host: host})
	}

	return bindings, nil
}

// addTenantHostBinding 添加绑定（幂等）
func (e *Enforcer) addTenantHostBinding(tenantID, host string) error {
	host = e.normalizeHost(host)
	if host == "" || tenantID == "" {
		return nil
	}

	resource := domainIdentityResourcePrefix + host
	exists, err := e.HasNamedPolicy(e.identityPType(), e.identitySubRule(), tenantID, resource, domainIdentityAction)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}

	_, err = e.AddNamedPolicy(e.identityPType(), e.identitySubRule(), tenantID, resource, domainIdentityAction)

	return err
}

// removeTenantHostBinding 删除绑定
func (e *Enforcer) removeTenantHostBinding(tenantID, host string) error {
	host = e.normalizeHost(host)
	if host == "" || tenantID == "" {
		return nil
	}

	resource := domainIdentityResourcePrefix + host
	_, err := e.RemoveNamedPolicy(e.identityPType(), e.identitySubRule(), tenantID, resource, domainIdentityAction)

	return err
}
