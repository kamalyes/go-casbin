/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-08-01 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-08-01 00:15:16
 * @FilePath: \go-casbin\enforcer\domain_identity.go
 * @Description: 租户域名身份绑定（正向校验 + 主机→租户反向映射联动）
 *
 * p2 策略同时承载两类策略，通过 act 区分，互不干扰：
 *  1. 正向校验：p2 = r.sub != "", <tenantID>, "domain::<host>", HOST
 *     EnforceTenantHostBinding 通过 Enforce 匹配，r.act == HOST 天然过滤反向映射
 *  2. 反向映射：p2 = r.sub != "", <tenantID>, "domain::<host>", HOST_TENANT_MAP
 *     ResolveTenantByHost 通过 GetFilteredNamedPolicy 按 act 过滤，读取 dom 字段获取 tenantID
 *
 * 联动保证：SyncTenantHostBindings 对每个 host 同时添加/删除正向+反向策略，
 * 确保登录反查（ResolveTenantByHost）和授权正向校验（EnforceTenantHostBinding）数据一致
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package enforcer

import (
	"net"
	"strings"
)

// TenantHostBinding 租户域名绑定关系
type TenantHostBinding struct {
	TenantID string
	Host     string
}

const (
	// domainIdentityAction 正向校验动作
	domainIdentityAction = "HOST"

	// hostTenantMapAction 反向映射动作（与正向校验区分，避免 Enforce 误匹配）
	hostTenantMapAction = "HOST_TENANT_MAP"

	// domainIdentitySubRule 主体规则（sub 非空即可，不限定具体用户）
	domainIdentitySubRule = `r.sub != ""`

	// domainIdentityResourcePrefix 资源前缀
	domainIdentityResourcePrefix = "domain::"
)

// NormalizeDomainHost 归一化请求域名标识
// 处理 X-Forwarded-Host 多值取首、host:port 剥离端口、IPv6 括号、trailing dot、小写
func NormalizeDomainHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if forwardedHost := strings.Split(host, ",")[0]; forwardedHost != "" {
		host = strings.TrimSpace(forwardedHost)
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

// SyncTenantHostBindings 批量同步租户域名绑定（正向校验 + 反向映射联动）
// 对 addHosts 中每个 host 同时添加正向+反向策略；removeHosts 同理同时删除
// tenantID 为空时跳过（OPS 域无域名限制）
func (e *Enforcer) SyncTenantHostBindings(tenantID string, addHosts, removeHosts []string) error {
	if tenantID == "" {
		return nil
	}
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
}

// EnforceTenantHostBinding 校验 tenantID 是否绑定了 host（正向校验）
// 通过 p2 正向校验策略匹配，仅用于已认证场景（需 userID）
func (e *Enforcer) EnforceTenantHostBinding(tenantID, userID, host string) (bool, error) {
	host = NormalizeDomainHost(host)
	if tenantID == "" || userID == "" || host == "" {
		return false, nil
	}
	return e.Enforce(userID, tenantID, domainIdentityResourcePrefix+host, domainIdentityAction)
}

// ResolveTenantByHost 根据 host 反查绑定的 tenantID（反向映射查询）
// 供登录/忘记密码等未认证场景按 host 解析租户；空串表示未绑定
func (e *Enforcer) ResolveTenantByHost(host string) (string, error) {
	host = NormalizeDomainHost(host)
	if host == "" {
		return "", nil
	}
	resource := domainIdentityResourcePrefix + host
	for _, p := range e.GetFilteredNamedPolicy("p2", 2, resource, hostTenantMapAction) {
		if len(p) > 1 && p[1] != "" {
			return p[1], nil
		}
	}
	return "", nil
}

// ListTenantHostBindings 列出租户域名绑定（反向映射策略）
// tenantID 为空时列出所有租户的绑定，非空时仅列出指定租户的绑定
func (e *Enforcer) ListTenantHostBindings(tenantID string) []TenantHostBinding {
	bindings := make([]TenantHostBinding, 0)
	for _, p := range e.GetFilteredNamedPolicy("p2", 3, hostTenantMapAction) {
		// p = [v0=sub_rule, v1=tenantID, v2=domain::host, v3=action]
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
	return bindings
}

// addTenantHostBinding 添加租户 host 绑定（正向+反向映射联动，幂等）
func (e *Enforcer) addTenantHostBinding(tenantID, host string) error {
	host = NormalizeDomainHost(host)
	if host == "" || tenantID == "" {
		return nil
	}
	resource := domainIdentityResourcePrefix + host
	// 正向校验策略
	if !e.HasNamedPolicy("p2", domainIdentitySubRule, tenantID, resource, domainIdentityAction) {
		if err := e.AddNamedPolicy("p2", domainIdentitySubRule, tenantID, resource, domainIdentityAction); err != nil {
			return err
		}
	}
	// 反向映射策略
	if !e.HasNamedPolicy("p2", domainIdentitySubRule, tenantID, resource, hostTenantMapAction) {
		if err := e.AddNamedPolicy("p2", domainIdentitySubRule, tenantID, resource, hostTenantMapAction); err != nil {
			return err
		}
	}
	return nil
}

// removeTenantHostBinding 删除租户 host 绑定（正向+反向映射联动）
func (e *Enforcer) removeTenantHostBinding(tenantID, host string) error {
	host = NormalizeDomainHost(host)
	if host == "" || tenantID == "" {
		return nil
	}
	resource := domainIdentityResourcePrefix + host
	if err := e.RemoveNamedPolicy("p2", domainIdentitySubRule, tenantID, resource, domainIdentityAction); err != nil {
		return err
	}
	return e.RemoveNamedPolicy("p2", domainIdentitySubRule, tenantID, resource, hostTenantMapAction)
}
