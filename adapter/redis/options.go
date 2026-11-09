/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\adapter\redis\options.go
 * @Description: 配置与选项
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package redis

import "github.com/kamalyes/go-casbin/adapter/base"

// 事件类型、日志接口与过滤条件沿用公共骨架
type (
	// Logger 最小日志接口，与 go-logger 的 *Logger 签名一致，可直接传入
	Logger = base.Logger
	// Event 策略变更事件
	Event = base.Event
	// Operation 策略变更类型
	Operation = base.Operation
	// Filter 过滤加载条件，字段与官方 file-adapter 的 Filter 同形
	Filter = base.Filter
)

// ErrUnsupportedFilter 过滤条件类型不支持
var ErrUnsupportedFilter = base.ErrUnsupportedFilter

// UnmarshalEvent 反序列化策略变更事件
func UnmarshalEvent(data []byte) (*Event, error) { return base.UnmarshalEvent(data) }

// Option 可选配置
type Option func(*Adapter)

// WithKeyPrefix 设置键名前缀，默认 casbin
// 多租户按前缀隔离：每个租户独立前缀，互不可见
func WithKeyPrefix(prefix string) Option {
	return func(a *Adapter) {
		if prefix != "" {
			a.keys = newKeyBuilder(prefix)
		}
	}
}

// WithLogger 设置日志记录器
func WithLogger(l Logger) Option {
	return func(a *Adapter) {
		if l != nil {
			a.log = l
		}
	}
}
