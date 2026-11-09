/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\adapter\base\notifier.go
 * @Description: 策略变更通知器的公共骨架
 *
 * 实现官方 persist.WatcherEx 的全部广播方法、回调管理与自环过滤。
 * 具体中间件只需提供「把一段字节发出去」的函数，以及自己的连接与消费循环：
 *
 *	type Watcher struct {
 *	    *base.Notifier
 *	    conn *someClient
 *	}
 *
 *	w.Notifier = base.NewNotifier(source, w.send)
 *
 * 收到消息时调用 w.Dispatch(ctx, payload) 即可完成解码、自环过滤与回调。
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package base

import (
	"context"
	"sync"
	"time"

	"github.com/casbin/casbin/v3/model"
	"github.com/google/uuid"
)

// PublishFunc 把一条已编码的事件发送出去
type PublishFunc func(ctx context.Context, payload []byte) error

// Notifier 通知器公共骨架
//
// 只负责「事件编码 + 回调管理 + 自环过滤」，不持有任何连接，
// 因此连接生命周期（Close 顺序、重连）完全由各适配器自己掌握。
type Notifier struct {
	source     string
	ignoreSelf bool
	publish    PublishFunc
	log        Logger

	mu       sync.RWMutex
	callback func(string)
}

// NotifierOption 通知器可选配置
type NotifierOption func(*Notifier)

// WithNotifierLogger 设置日志记录器
func WithNotifierLogger(l Logger) NotifierOption {
	return func(n *Notifier) {
		if l != nil {
			n.log = l
		}
	}
}

// WithIgnoreSelf 设置是否丢弃自身发出的事件，默认 true
// 关闭后本节点也会处理自己的广播，一般只在排查问题时使用
func WithIgnoreSelf(ignore bool) NotifierOption {
	return func(n *Notifier) { n.ignoreSelf = ignore }
}

// NewNotifier 创建通知器骨架
// source 为本节点标识，用于过滤自环；留空时自动生成
func NewNotifier(source string, publish PublishFunc, opts ...NotifierOption) *Notifier {
	if source == "" {
		source = NewSource()
	}

	n := &Notifier{
		source:     source,
		ignoreSelf: true,
		publish:    publish,
		log:        NopLogger{},
	}
	for _, opt := range opts {
		opt(n)
	}

	return n
}

// NewSource 生成一个节点标识
func NewSource() string { return "casbin-" + uuid.NewString() }

// Source 返回本节点标识
func (n *Notifier) Source() string { return n.source }

// Logger 返回日志记录器，供各适配器复用同一个实例
func (n *Notifier) Logger() Logger { return n.log }

// ==================== persist.Watcher ====================

// SetUpdateCallback 设置远端策略变更的回调
func (n *Notifier) SetUpdateCallback(fn func(string)) error {
	n.mu.Lock()
	n.callback = fn
	n.mu.Unlock()

	return nil
}

// Update 广播一次通用变更，接收方全量重载
func (n *Notifier) Update() error {
	return n.Emit(&Event{Op: OpUpdate})
}

// ==================== persist.WatcherEx ====================

// UpdateForAddPolicy 广播新增单条策略
func (n *Notifier) UpdateForAddPolicy(sec, ptype string, params ...string) error {
	return n.Emit(&Event{Op: OpAddPolicy, Sec: sec, PType: ptype, Rules: [][]string{params}})
}

// UpdateForRemovePolicy 广播删除单条策略
func (n *Notifier) UpdateForRemovePolicy(sec, ptype string, params ...string) error {
	return n.Emit(&Event{Op: OpRemovePolicy, Sec: sec, PType: ptype, Rules: [][]string{params}})
}

// UpdateForRemoveFilteredPolicy 广播按字段过滤删除
func (n *Notifier) UpdateForRemoveFilteredPolicy(sec, ptype string, fieldIndex int, fieldValues ...string) error {
	return n.Emit(&Event{
		Op: OpRemoveFilteredPolicy, Sec: sec, PType: ptype,
		FieldIndex: fieldIndex, FieldValues: fieldValues,
	})
}

// UpdateForSavePolicy 广播全量覆盖
//
// 刻意不附带策略快照，只带条数用于观测：
//   - 快照用不上。OpSavePolicy 的语义就是「全量覆盖」，接收方要做的
//     是回源重载，本仓的 onPolicyChanged 对任何事件都是全量 LoadPolicy，
//     压根不读 Rules。
//   - 快照还会把广播打爆。实测 1 万条策略编码后约 340 KB、5 万条约 1.7 MB，
//     而 Kafka 的 message.max.bytes 与 NATS 的 max_payload 默认都是 1 MB，
//     策略集一大，这条广播就会被 broker 拒收 —— 于是全量覆盖彻底同步不出去，
//     这正是最不能出问题的那种变更。
func (n *Notifier) UpdateForSavePolicy(m model.Model) error {
	return n.Emit(&Event{Op: OpSavePolicy, RuleCount: CountPolicies(m)})
}

// UpdateForAddPolicies 广播新增多条策略
func (n *Notifier) UpdateForAddPolicies(sec string, ptype string, rules ...[]string) error {
	return n.Emit(&Event{Op: OpAddPolicies, Sec: sec, PType: ptype, Rules: rules})
}

// UpdateForRemovePolicies 广播删除多条策略
func (n *Notifier) UpdateForRemovePolicies(sec string, ptype string, rules ...[]string) error {
	return n.Emit(&Event{Op: OpRemovePolicies, Sec: sec, PType: ptype, Rules: rules})
}

// ==================== 收发 ====================

// Emit 补齐事件元信息后交给传输层发送
func (n *Notifier) Emit(event *Event) error {
	return n.EmitCtx(context.Background(), event)
}

// EmitCtx 补齐事件元信息后交给传输层发送
func (n *Notifier) EmitCtx(ctx context.Context, event *Event) error {
	if n.publish == nil {
		return ErrNoTransport
	}

	event.ID = uuid.NewString()
	event.Source = n.source
	event.TimestampMs = time.Now().UnixMilli()

	payload, err := event.Marshal()
	if err != nil {
		return err
	}

	if err := n.publish(ctx, payload); err != nil {
		n.log.ErrorContextKV(ctx, "casbin publish policy change failed",
			"source", n.source, "op", string(event.Op), "error", err.Error())
		return err
	}

	return nil
}

// Dispatch 处理一条收到的消息：解码、过滤自环、投递回调
// 返回是否真的触发了回调，便于各适配器记录指标
func (n *Notifier) Dispatch(ctx context.Context, payload []byte) bool {
	event, err := UnmarshalEvent(payload)
	if err != nil {
		n.log.WarnContextKV(ctx, "casbin got a malformed policy change event",
			"source", n.source, "error", err.Error())
		return false
	}

	if n.ignoreSelf && event.Source == n.source {
		return false
	}

	n.mu.RLock()
	callback := n.callback
	n.mu.RUnlock()

	if callback == nil {
		return false
	}

	// 回调在锁外执行：回调里通常是 LoadPolicy，持锁调用容易和策略写入互锁
	callback(string(payload))

	return true
}
