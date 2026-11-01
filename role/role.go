/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\role\role.go
 * @Description: 角色定义与接口
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package role

// Role 角色接口
// 定义角色的基本操作，是 RBAC 角色继承体系的核心抽象
// 每个角色维护一个直接继承的角色列表（links），形成有向图
//
// 典型用法：
//
//	admin → editor → viewer 构成继承链
//	alice 继承 admin，则 alice 也拥有 editor 和 viewer 的权限
type Role interface {
	Name() string              // 获取角色名称
	AddLink(name2 string)      // 添加角色继承链接（name 继承 name2）
	DeleteLink(name2 string)   // 删除角色继承链接
	HasLink(name2 string) bool // 检查是否直接继承指定角色
	GetLinks() []string        // 获取所有直接继承的角色列表
}

// RoleNode 角色节点实现
// 使用名称 + 链接列表表示角色继承关系
// links 存储该角色直接继承的其他角色名称（不包含间接继承）
type RoleNode struct {
	name  string   // 角色名称
	links []string // 直接继承的角色列表
}

// NewRoleNode 创建新的角色节点
// name: 角色名称（如 "admin"、"viewer"）
func NewRoleNode(name string) *RoleNode {
	return &RoleNode{
		name:  name,
		links: make([]string, 0),
	}
}

// Name 获取角色名称
func (rn *RoleNode) Name() string {
	return rn.name
}

// AddLink 添加角色继承链接
// 如果已存在则跳过（幂等操作）
// name2: 被继承的角色名称
func (rn *RoleNode) AddLink(name2 string) {
	for _, l := range rn.links {
		if l == name2 {
			return
		}
	}
	rn.links = append(rn.links, name2)
}

// DeleteLink 删除角色继承链接
// 如果链接不存在则静默返回
func (rn *RoleNode) DeleteLink(name2 string) {
	for i, l := range rn.links {
		if l == name2 {
			rn.links = append(rn.links[:i], rn.links[i+1:]...)
			return
		}
	}
}

// HasLink 检查是否直接继承指定角色
// 仅检查直接继承关系，不检查间接继承（间接继承由 RoleHierarchy.HasLink 处理）
func (rn *RoleNode) HasLink(name2 string) bool {
	for _, l := range rn.links {
		if l == name2 {
			return true
		}
	}
	return false
}

// GetLinks 获取所有直接继承的角色列表
// 返回副本，避免外部修改影响内部数据
func (rn *RoleNode) GetLinks() []string {
	result := make([]string, len(rn.links))
	copy(result, rn.links)
	return result
}
