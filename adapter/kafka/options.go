/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\adapter\kafka\options.go
 * @Description: 配置与选项
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package kafka

import (
	"errors"
	"time"

	"github.com/IBM/sarama"
	"github.com/kamalyes/go-casbin/adapter/base"
)

// ErrNoBrokers 未提供 Kafka 地址
var ErrNoBrokers = errors.New("go-casbin/kafka: at least one broker is required")

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

// Config Kafka 连接配置
type Config struct {
	// Brokers Kafka 地址列表，必填
	Brokers []string
	// Topic 策略变更主题，默认 casbin-policy-changes
	Topic string
	// GroupID 消费者组 ID
	//
	// 每个副本必须用不同的 GroupID：策略广播要求「所有副本都收到」，
	// 而同一消费者组内一条消息只会被其中一个成员消费。
	// 留空时自动生成，保证副本间不串组。
	GroupID string
	// Source 本节点标识，用于过滤自环，留空时自动生成
	Source string
	// Version Kafka 协议版本，默认 sarama.V2_8_0_0
	Version sarama.KafkaVersion
	// Sarama SASL / TLS 等高级参数直接改这里，非 nil 时覆盖上面全部默认值
	Sarama *sarama.Config
}

// settings 可选配置的收敛结果
type settings struct {
	log            Logger
	publishTimeout time.Duration
	ignoreSelf     bool
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

// WithPublishTimeout 设置单次广播等待 broker 应答的超时，默认 3s
// 落到 sarama.Config.Producer.Timeout；自带 Config.Sarama 时本项不生效
func WithPublishTimeout(d time.Duration) Option {
	return func(s *settings) {
		if d > 0 {
			s.publishTimeout = d
		}
	}
}

// WithIgnoreSelf 设置是否丢弃自身发出的事件，默认 true
// 关闭后本节点也会处理自己的广播，一般只在排查问题时使用
func WithIgnoreSelf(ignore bool) Option {
	return func(s *settings) { s.ignoreSelf = ignore }
}
