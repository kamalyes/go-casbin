/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\logger.go
 * @Description: 最小日志接口（零依赖）
 *
 * 本包不依赖任何具体日志库，只声明所需的最小接口
 * github.com/kamalyes/go-logger 的 *Logger 的方法签名与此完全一致，因此可直接传入、无需编写适配器：
 *
 *	e, err := casbin.NewEnforcer(
 *	    casbin.WithModelPath("resources/rbac_model.conf"),
 *	    casbin.WithLogger(logger.NewLogger()),
 *	)
 *
 * 接入其他日志库时，实现下面 4 个方法即可
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package casbin

import "context"

// Logger 结构化日志接口
// 只要求 context 版键值方法：决策与策略变更都发生在请求链路上，
// 带上 ctx 才能让日志挂到调用方的 trace 上。
type Logger interface {
	DebugContextKV(ctx context.Context, msg string, keysAndValues ...interface{})
	InfoContextKV(ctx context.Context, msg string, keysAndValues ...interface{})
	WarnContextKV(ctx context.Context, msg string, keysAndValues ...interface{})
	ErrorContextKV(ctx context.Context, msg string, keysAndValues ...interface{})
}

// NopLogger 丢弃全部日志，未设置 WithLogger 时的默认实现
type NopLogger struct{}

func (NopLogger) DebugContextKV(context.Context, string, ...interface{}) {}
func (NopLogger) InfoContextKV(context.Context, string, ...interface{})  {}
func (NopLogger) WarnContextKV(context.Context, string, ...interface{})  {}
func (NopLogger) ErrorContextKV(context.Context, string, ...interface{}) {}
