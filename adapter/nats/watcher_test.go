/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\adapter\nats\watcher_test.go
 * @Description: 通知器测试（不依赖真实 NATS）
 *
 * 事件编解码、自环过滤、广播语义的测试都在 adapter/base，
 * 这里只覆盖 NATS 特有的配置部分。
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package nats

import (
	"errors"
	"testing"
	"time"

	"github.com/kamalyes/go-casbin/adapter/base"
)

func TestNewWatcherRequiresURLs(t *testing.T) {
	if _, err := NewWatcher(Config{}); !errors.Is(err, ErrNoURLs) {
		t.Fatalf("err = %v; want ErrNoURLs", err)
	}
}

func TestConfigDefaults(t *testing.T) {
	got := Config{URLs: []string{"nats://a:4222"}}.withDefaults()

	if got.Subject != defaultSubject {
		t.Errorf("Subject = %q; want %q", got.Subject, defaultSubject)
	}
	if got.StreamName != defaultStreamName {
		t.Errorf("StreamName = %q; want %q", got.StreamName, defaultStreamName)
	}
	if got.MaxAge != 24*time.Hour {
		t.Errorf("MaxAge = %v; want 24h", got.MaxAge)
	}
}

func TestConfigKeepsExplicitValues(t *testing.T) {
	in := Config{
		URLs:       []string{"nats://a:4222"},
		Subject:    "my.subject",
		StreamName: "MY_STREAM",
		MaxAge:     time.Hour,
	}

	got := in.withDefaults()
	if got.Subject != "my.subject" || got.StreamName != "MY_STREAM" || got.MaxAge != time.Hour {
		t.Fatalf("got %+v; want the explicit values kept", got)
	}
}

func TestNonPositiveMaxAgeFallsBackToDefault(t *testing.T) {
	if got := (Config{MaxAge: -time.Hour}).withDefaults().MaxAge; got != 24*time.Hour {
		t.Fatalf("MaxAge = %v; want the default", got)
	}
}

func TestOptionsAreApplied(t *testing.T) {
	s := &settings{log: base.NopLogger{}, ignoreSelf: true}

	WithIgnoreSelf(false)(s)
	WithLogger(nil)(s) // nil 不应把默认实现覆盖掉

	if s.ignoreSelf {
		t.Error("ignoreSelf should be off")
	}
	if s.log == nil {
		t.Error("a nil logger must not clear the default")
	}
}

func TestEventAliasesPointAtBase(t *testing.T) {
	in := &Event{Op: base.OpSavePolicy, Source: "node-1"}

	payload, err := in.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	out, err := UnmarshalEvent(payload)
	if err != nil {
		t.Fatalf("UnmarshalEvent: %v", err)
	}
	if out.Op != base.OpSavePolicy || out.Source != "node-1" {
		t.Fatalf("out = %+v", out)
	}
}
