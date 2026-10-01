/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-08-07 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-08-07 00:16:56
 * @FilePath: \go-casbin\enforcer\enforcer_deadlock_test.go
 * @Description: 死锁风险与边界场景测试
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */
package enforcer

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/kamalyes/go-casbin/policy"
	"github.com/kamalyes/go-toolbox/pkg/retry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==================== SetNotifier 死锁测试 ====================

// TestSetNotifier_NoDeadlock 验证 SetNotifier 不会与 EventLoop 回调死锁
// 修复前：SetNotifier 持 e.mu.Lock → Close → handlerWG.Wait()
//
//	EventLoop handler → handlePolicyChange → ReloadPolicy → 等 e.mu.Lock
//	→ 死锁
//
// 修复后：SetNotifier 锁内只替换引用，锁外调用 Close/Subscribe
func TestSetNotifier_NoDeadlock(t *testing.T) {
	e := newMemoryEnforcer(t, rbacModelPath)

	n1 := &mockNotifier{}
	err := e.SetNotifier(n1)
	require.NoError(t, err)

	err = e.AddPolicy("alice", "data1", "read")
	require.NoError(t, err)

	// 异步触发事件：handlePolicyChange → ReloadPolicy 需要获取 e.mu.Lock
	n1.triggerHandler(policy.NewChangeEvent(policy.EventTypePolicyReload, "", "test"))

	// 等待 handler 开始执行（进入 ReloadPolicy 等 e.mu.Lock）
	time.Sleep(20 * time.Millisecond)

	// 此时 handler 正在等待 e.mu.Lock
	// 调用 SetNotifier 替换 notifier，验证不会死锁
	n2 := &mockNotifier{}

	done := make(chan error, 1)
	go func() {
		done <- e.SetNotifier(n2)
	}()

	select {
	case err := <-done:
		assert.NoError(t, err)
		assert.True(t, n1.closed, "old notifier should be closed")
		assert.Equal(t, n2, e.notifier, "new notifier should be set")
	case <-time.After(5 * time.Second):
		t.Fatal("SetNotifier deadlocked: Close waited for handler while holding e.mu.Lock")
	}
}

// failingSubscribeNotifier Subscribe 总是返回错误
type failingSubscribeNotifier struct {
	mockNotifier
}

func (m *failingSubscribeNotifier) Subscribe(_ context.Context, _ policy.ChangeEventHandler) error {
	return assert.AnError
}

// TestSetNotifier_SubscribeErrorFix 验证 Subscribe 失败时回滚 notifier 引用
func TestSetNotifier_SubscribeErrorFix(t *testing.T) {
	e := newMemoryEnforcer(t, rbacModelPath)

	n1 := &mockNotifier{}
	err := e.SetNotifier(n1)
	require.NoError(t, err)

	// 创建一个 Subscribe 会失败的 notifier
	n2 := &failingSubscribeNotifier{}
	err = e.SetNotifier(n2)
	assert.Error(t, err)
	// notifier 引用应回滚为 n1
	assert.Equal(t, n1, e.notifier, "notifier should rollback on subscribe error")
}

// TestSetNotifier_Concurrent 并发 SetNotifier + Enforce，验证无死锁无 panic
func TestSetNotifier_Concurrent(t *testing.T) {
	e := newMemoryEnforcer(t, rbacModelPath)
	err := e.AddPolicy("alice", "data1", "read")
	require.NoError(t, err)

	var wg sync.WaitGroup
	const iterations = 50

	// 并发 SetNotifier
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			_ = e.SetNotifier(&mockNotifier{})
		}
	}()

	// 并发 Enforce
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			_, _ = e.Enforce("alice", "data1", "read")
		}
	}()

	wg.Wait()
}

// ==================== handlePolicyChange 事件类型测试 ====================

// TestHandlePolicyChange_IncrementalEvent 增量事件保留 enforceCache
// EventTypePolicyAdded → reloadPolicyForRemoteChange（不清空缓存）
func TestHandlePolicyChange_IncrementalEvent(t *testing.T) {
	e := newMemoryEnforcer(t, rbacModelPath)

	err := e.AddPolicy("alice", "data1", "read")
	require.NoError(t, err)

	// 填充缓存
	ok, err := e.Enforce("alice", "data1", "read")
	require.NoError(t, err)
	require.True(t, ok)

	versionBefore := e.enforceCache.Version()

	// 触发增量事件
	e.handlePolicyChange(policy.NewChangeEvent(policy.EventTypePolicyAdded, "p", "remote"))

	// 增量事件走 reloadPolicyForRemoteChange，不清空 enforceCache
	versionAfter := e.enforceCache.Version()
	assert.Equal(t, versionBefore, versionAfter, "incremental event should not invalidate enforceCache")
}

// TestHandlePolicyChange_FullEvent 全量事件清空 enforceCache
// EventTypePolicyReload → ReloadPolicy（调用 invalidateExtraPoliciesCache）
func TestHandlePolicyChange_FullEvent(t *testing.T) {
	e := newMemoryEnforcer(t, rbacModelPath)

	err := e.AddPolicy("alice", "data1", "read")
	require.NoError(t, err)

	// 填充缓存
	ok, err := e.Enforce("alice", "data1", "read")
	require.NoError(t, err)
	require.True(t, ok)

	versionBefore := e.enforceCache.Version()

	// 触发全量事件
	e.handlePolicyChange(policy.NewChangeEvent(policy.EventTypePolicyReload, "", "remote"))

	// 全量事件走 ReloadPolicy，调用 invalidateExtraPoliciesCache → 版本号递增
	versionAfter := e.enforceCache.Version()
	assert.Greater(t, versionAfter, versionBefore, "full event should invalidate enforceCache")
}

// ==================== ExecuteInTransaction 边界测试 ====================

// TestExecuteInTransaction_CancelledContext 上下文已取消时不开启事务
func TestExecuteInTransaction_CancelledContext(t *testing.T) {
	e := newMemoryEnforcer(t, rbacModelPath)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := e.ExecuteInTransaction(ctx, func() error {
		t.Fatal("fn should not be executed with cancelled context")
		return nil
	})
	assert.Error(t, err)
	assert.Equal(t, context.Canceled, err)
}

// TestExecuteInTransaction_FnErrorFix fn 返回错误时正确传播
func TestExecuteInTransaction_FnErrorFix(t *testing.T) {
	e := newMemoryEnforcer(t, rbacModelPath)

	err := e.ExecuteInTransaction(context.Background(), func() error {
		return assert.AnError
	})
	assert.Error(t, err)
}

// ==================== enforceCache 代际轮转测试 ====================

// TestEnforceCache_InvalidateOrphanedEntries 验证策略变更后旧版本条目全部失效
func TestEnforceCache_InvalidateOrphanedEntries(t *testing.T) {
	e := newMemoryEnforcer(t, rbacModelPath)

	err := e.AddPolicy("alice", "data1", "read")
	require.NoError(t, err)

	// 填充缓存
	_, _ = e.Enforce("alice", "data1", "read")

	// 缓存应命中
	_, hit := e.enforceCache.Load("alice|data1|read|")
	assert.True(t, hit)

	// 策略变更递增版本号并重建两代
	e.invalidateEnforceCache()

	// 旧版本条目应立即失效
	_, hit = e.enforceCache.Load("alice|data1|read|")
	assert.False(t, hit, "orphaned cache entries should be invalidated")
}

// TestEnforceCache_GenerationalRotation 验证代际轮转行为
// 到期后旧代降级为 prev 仍可命中，再次轮转后旧条目彻底消失
func TestEnforceCache_GenerationalRotation(t *testing.T) {
	e := newMemoryEnforcer(t, rbacModelPath)

	err := e.AddPolicy("alice", "data1", "read")
	require.NoError(t, err)

	// 填充 current 代
	_, _ = e.Enforce("alice", "data1", "read")
	require.NotNil(t, e.enforceCache.current.Load())

	// 强制 current 代过期后手动轮转：旧 current 降级为 prev，条目在 prev 仍可命中
	e.enforceCache.current.Load().expiresAt = time.Now().Add(-time.Second).UnixNano()
	e.enforceCache.rotateLocked(time.Now())
	_, hit := e.enforceCache.Load("alice|data1|read|")
	assert.True(t, hit, "entries demoted to prev gen should still be readable")

	// 二次轮转：原 prev 整体废弃，条目彻底消失
	e.enforceCache.current.Load().expiresAt = time.Now().Add(-time.Second).UnixNano()
	e.enforceCache.rotateLocked(time.Now())
	_, hit = e.enforceCache.Load("alice|data1|read|")
	assert.False(t, hit, "entries dropped with old prev gen should be gone")
}

// TestEnforceCache_ConcurrentRotate 并发 Enforce + 轮转/失效，验证无 panic 无 race
func TestEnforceCache_ConcurrentRotate(t *testing.T) {
	e := newMemoryEnforcer(t, rbacModelPath)

	err := e.AddPolicy("alice", "data1", "read")
	require.NoError(t, err)

	var wg sync.WaitGroup
	const iterations = 100

	// 并发 Enforce（填充缓存 + 触发轮转检查）
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			_, _ = e.Enforce("alice", "data1", "read")
		}
	}()

	// 并发轮转与失效
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			e.enforceCache.rotateLocked(time.Now().Add(2 * enforceCacheTTL))
			e.invalidateEnforceCache()
		}
	}()

	wg.Wait()
}

// ==================== enforceCore 错误路径测试 ====================

// TestEnforceCore_RetryExhausted retry 耗尽后返回错误
func TestEnforceCore_RetryExhausted(t *testing.T) {
	// 使用无效参数让 doEnforce 每次都返回错误，retry 耗尽后应返回错误
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	e.retry = newFastRetry()

	// 参数数量不匹配，doEnforce 返回错误，retry 重试后耗尽
	_, err := e.EnforceContext(context.Background(), "alice")
	assert.Error(t, err)
}

// TestEnforceCore_BreakerAndRetry breaker 和 retry 同时存在时走 breaker 路径
func TestEnforceCore_BreakerAndRetry(t *testing.T) {
	e := newTestEnforcer(t, rbacModelPath, rbacPolicyPath)
	e.retry = newFastRetry()

	// breaker 正常时，Enforce 应成功
	ok, err := e.EnforceContext(context.Background(), "alice", "data1", "read")
	assert.NoError(t, err)
	assert.True(t, ok)
}

// newFastRetry 创建一个快速重试的 retry（2 次，1ms 间隔）
func newFastRetry() *retry.Retry {
	return retry.NewRetry().SetAttemptCount(2).SetInterval(time.Millisecond)
}
