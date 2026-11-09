/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\casbin.go
 * @Description: 官方 casbin 类型与构造器的再导出门面
 *
 * 业务方只需 import 本包，即可拿到官方 casbin v3 的完整能力，
 * 无需再单独引入 github.com/casbin/casbin/v3。
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package casbin

import (
	upstream "github.com/casbin/casbin/v3"
	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
	"github.com/casbin/casbin/v3/persist/cache"
	fileadapter "github.com/casbin/casbin/v3/persist/file-adapter"
	"github.com/casbin/casbin/v3/rbac"
)

// ==================== 引擎类型 ====================

// 官方引擎的全部变体。本包的 Enforcer 内嵌 *SyncedCachedEnforcer，
// 不需要企业层时可直接用下列类型及其构造器
type (
	// CoreEnforcer 官方基础执行器（非并发安全）
	CoreEnforcer = upstream.Enforcer
	// SyncedEnforcer 官方并发安全执行器（RWMutex）
	SyncedEnforcer = upstream.SyncedEnforcer
	// CachedEnforcer 官方带结果缓存的执行器（版本号 O(1) 失效）
	CachedEnforcer = upstream.CachedEnforcer
	// SyncedCachedEnforcer 官方并发安全 + 结果缓存执行器
	SyncedCachedEnforcer = upstream.SyncedCachedEnforcer
	// ContextEnforcer 官方 context 感知执行器（存储操作可超时取消）
	ContextEnforcer = upstream.ContextEnforcer
	// IEnforcerContext 官方 context 感知执行器接口
	IEnforcerContext = upstream.IEnforcerContext
	// TransactionalEnforcer 官方事务执行器
	TransactionalEnforcer = upstream.TransactionalEnforcer
	// DistributedEnforcer 官方分布式执行器（配合 Dispatcher）
	DistributedEnforcer = upstream.DistributedEnforcer
	// Transaction 官方策略事务句柄
	Transaction = upstream.Transaction
	// IEnforcer 官方执行器接口
	IEnforcer = upstream.IEnforcer
	// EnforceContext 指定本次决策使用的 r/p/e/m 段，用于一个模型里承载多套策略语义
	EnforceContext = upstream.EnforceContext
)

// NewEnforceContext 按后缀构造决策段选择器
// 传 "2" 得到 {RType: "r2", PType: "p2", EType: "e2", MType: "m2"}
func NewEnforceContext(suffix string) EnforceContext {
	return upstream.NewEnforceContext(suffix)
}

// ==================== 模型类型 ====================

type (
	// Model 权限模型（PERM 元模型，100% 兼容官方 model.conf 语法）
	Model = model.Model
	// AssertionMap 断言集合
	AssertionMap = model.AssertionMap
	// Assertion 单条断言（r/p/g/e/m 之一）
	Assertion = model.Assertion
	// FunctionMap matcher 自定义函数表
	FunctionMap = model.FunctionMap
	// RoleManager 角色管理器
	RoleManager = rbac.RoleManager
)

// ==================== 存储适配器接口 ====================

// 自研适配器（gorm / kafka 等）实现下列官方接口即可被本包直接接入。
type (
	// Adapter 基础适配器：LoadPolicy / SavePolicy / AddPolicy / RemovePolicy / RemoveFilteredPolicy
	Adapter = persist.Adapter
	// BatchAdapter 批量适配器：AddPolicies / RemovePolicies
	BatchAdapter = persist.BatchAdapter
	// FilteredAdapter 过滤加载适配器：LoadFilteredPolicy（多租户分片按需加载）
	FilteredAdapter = persist.FilteredAdapter
	// UpdatableAdapter 原地更新适配器：UpdatePolicy / UpdatePolicies
	UpdatableAdapter = persist.UpdatableAdapter
	// ContextAdapter context 感知适配器：*Ctx 系列，存储操作可超时取消
	ContextAdapter = persist.ContextAdapter
	// ContextBatchAdapter context 感知批量适配器
	ContextBatchAdapter = persist.ContextBatchAdapter
	// ContextFilteredAdapter context 感知过滤加载适配器
	ContextFilteredAdapter = persist.ContextFilteredAdapter
	// ContextUpdatableAdapter context 感知原地更新适配器
	ContextUpdatableAdapter = persist.ContextUpdatableAdapter
	// TransactionalAdapter 事务适配器：BeginTransaction
	TransactionalAdapter = persist.TransactionalAdapter
	// TransactionContext 事务上下文：Commit / Rollback
	TransactionContext = persist.TransactionContext
	// Dispatcher 分布式一致性分发器
	Dispatcher = persist.Dispatcher
)

// ==================== 策略变更通知接口 ====================

// 自研通知器（kafka / nats 等）实现下列官方接口即可被 WithWatcher 接入。
type (
	// Watcher 基础通知器：SetUpdateCallback / Update / Close
	Watcher = persist.Watcher
	// WatcherEx 增强通知器：按变更类型分别广播，支持增量 reload
	WatcherEx = persist.WatcherEx
	// UpdatableWatcher 可增量更新的通知器
	UpdatableWatcher = persist.UpdatableWatcher
)

// ==================== 内置适配器与缓存 ====================

type (
	// FileAdapter 官方文件适配器
	FileAdapter = fileadapter.Adapter
	// FilteredFileAdapter 官方过滤文件适配器
	FilteredFileAdapter = fileadapter.FilteredAdapter
	// Filter 过滤加载条件
	Filter = fileadapter.Filter
	// Cache 结果缓存接口
	Cache = cache.Cache
)

// ==================== 模型构造器 ====================

// NewModel 创建空模型
func NewModel() Model { return model.NewModel() }

// NewModelFromFile 从 model.conf 文件加载模型
func NewModelFromFile(path string) (Model, error) { return model.NewModelFromFile(path) }

// NewModelFromString 从模型文本加载模型
func NewModelFromString(text string) (Model, error) { return model.NewModelFromString(text) }

// ==================== 适配器与缓存构造器 ====================

// NewFileAdapter 创建文件适配器
func NewFileAdapter(path string) *FileAdapter { return fileadapter.NewAdapter(path) }

// NewFilteredFileAdapter 创建过滤文件适配器
func NewFilteredFileAdapter(path string) *FilteredFileAdapter {
	return fileadapter.NewFilteredAdapter(path)
}

// NewDefaultCache 创建默认结果缓存（非并发安全，配合 CachedEnforcer 自带锁使用）
func NewDefaultCache() (Cache, error) { return cache.NewDefaultCache() }

// NewSyncCache 创建并发安全结果缓存
func NewSyncCache() (Cache, error) { return cache.NewSyncCache() }

// ==================== 官方引擎构造器 ====================

// 下列构造器直接转发到官方实现，参数语义与官方完全一致。
// 需要熔断 / 重试 / 指标 / 公共策略等企业层能力时请改用 NewEnforcer。

// NewCoreEnforcer 创建官方基础执行器
func NewCoreEnforcer(params ...interface{}) (*CoreEnforcer, error) {
	return upstream.NewEnforcer(params...)
}

// NewSyncedEnforcer 创建官方并发安全执行器
func NewSyncedEnforcer(params ...interface{}) (*SyncedEnforcer, error) {
	return upstream.NewSyncedEnforcer(params...)
}

// NewCachedEnforcer 创建官方带缓存执行器
func NewCachedEnforcer(params ...interface{}) (*CachedEnforcer, error) {
	return upstream.NewCachedEnforcer(params...)
}

// NewSyncedCachedEnforcer 创建官方并发安全 + 缓存执行器
func NewSyncedCachedEnforcer(params ...interface{}) (*SyncedCachedEnforcer, error) {
	return upstream.NewSyncedCachedEnforcer(params...)
}

// NewContextEnforcer 创建官方 context 感知执行器
func NewContextEnforcer(params ...interface{}) (IEnforcerContext, error) {
	return upstream.NewContextEnforcer(params...)
}

// NewTransactionalEnforcer 创建官方事务执行器
func NewTransactionalEnforcer(params ...interface{}) (*TransactionalEnforcer, error) {
	return upstream.NewTransactionalEnforcer(params...)
}

// NewDistributedEnforcer 创建官方分布式执行器
func NewDistributedEnforcer(params ...interface{}) (*DistributedEnforcer, error) {
	return upstream.NewDistributedEnforcer(params...)
}
