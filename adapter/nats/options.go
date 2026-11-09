/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\adapter\nats\options.go
 * @Description: 配置与选项
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package nats

import (
	"errors"
	"time"

	"github.com/kamalyes/go-casbin/adapter/base"
	natsgo "github.com/nats-io/nats.go"
)

// ErrNoURLs 未提供 NATS 地址
var ErrNoURLs = errors.New("go-casbin/nats: at least one server URL is required")

// 事件类型与日志接口沿用公共骨架，混用不同中间件的集群之间事件也能互相理解
type (
	// Logger 最小日志接口，与 go-logger 的 *Logger 签名一致，可直接传入
	Logger = base.Logger
	// Event 策略变更事件
	Event = base.Event
	// Operation 策略变更类型
	Operation = base.Operation
)

// UnmarshalEvent 反序列化策略变更事件
func UnmarshalEvent(data []byte) (*Event, error) { return base.UnmarshalEvent(data) }

// Config NATS 连接配置
type Config struct {
	// URLs NATS 地址列表，必填
	URLs []string
	// Subject 策略变更主题，默认 casbin.policy.changes
	Subject string
	// Source 本节点标识，用于过滤自环，留空时自动生成
	Source string

	// JetStream 是否启用 JetStream 持久化
	//
	// 关闭时走核心 pub/sub：投递即忘，副本重启期间发生的变更收不到，
	// 只能靠下次全量 reload 兜底。
	// 开启后事件落盘，配合 Durable 消费者，副本重启后能补齐缺口。
	JetStream bool
	// StreamName JetStream 流名，默认 CASBIN_POLICY
	StreamName string
	// Durable 持久消费者名，留空时不补齐历史
	//
	// 需要「重启补齐」语义时必须显式指定且副本间保持稳定，
	// 通常用 StatefulSet 的 Pod 序号之类的固定标识。
	Durable string
	// MaxAge 事件保留时长，默认 24h，仅 JetStream 生效
	MaxAge time.Duration

	// Options 透传给 nats.Connect 的原生选项（TLS / 认证 / 重连策略等）
	Options []natsgo.Option
}

// settings 可选配置的收敛结果
type settings struct {
	log        Logger
	ignoreSelf bool
}

// Option 可选配置
type Option func(*settings)

// WithLogger 设置日志记录器
func WithLogger(l Logger) Option {
	return func(s *settings) {
		if l != nil {
			s.log = l
		}
	}
}

// WithIgnoreSelf 设置是否丢弃自身发出的事件，默认 true
func WithIgnoreSelf(ignore bool) Option {
	return func(s *settings) { s.ignoreSelf = ignore }
}
