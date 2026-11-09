/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\adapter\base\logger.go
 * @Description: 最小日志接口（零依赖）
 *
 * 本模块不依赖任何日志库，只声明所需的最小接口。
 * github.com/kamalyes/go-logger 的 *Logger 方法签名与此一致，可直接传入、无需适配器。
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package base

import "context"

// Logger 结构化日志接口
// 只要求 context 版键值方法：策略变更都发生在请求链路上，带上 ctx 才能挂到调用方的 trace
type Logger interface {
	InfoContextKV(ctx context.Context, msg string, keysAndValues ...interface{})
	WarnContextKV(ctx context.Context, msg string, keysAndValues ...interface{})
	ErrorContextKV(ctx context.Context, msg string, keysAndValues ...interface{})
}

// NopLogger 丢弃全部日志，未设置日志记录器时的默认实现
type NopLogger struct{}

func (NopLogger) InfoContextKV(context.Context, string, ...interface{})  {}
func (NopLogger) WarnContextKV(context.Context, string, ...interface{})  {}
func (NopLogger) ErrorContextKV(context.Context, string, ...interface{}) {}
