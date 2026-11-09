/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\adapter\kafka\watcher_test.go
 * @Description: 通知器测试（不依赖真实 Kafka）
 *
 * 事件编解码、自环过滤、广播语义的测试都在 adapter/base，
 * 这里只覆盖 Kafka 特有的配置与传输部分。
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package kafka

import (
	"errors"
	"testing"
	"time"

	"github.com/IBM/sarama"
	"github.com/kamalyes/go-casbin/adapter/base"
)

func TestNewWatcherRequiresBrokers(t *testing.T) {
	if _, err := NewWatcher(Config{}); !errors.Is(err, ErrNoBrokers) {
		t.Fatalf("err = %v; want ErrNoBrokers", err)
	}
}

func TestSettingsDefaults(t *testing.T) {
	s := &settings{log: base.NopLogger{}, publishTimeout: defaultPublishTimeout, ignoreSelf: true}

	if s.publishTimeout != 3*time.Second || !s.ignoreSelf {
		t.Fatalf("defaults = %+v", s)
	}
}

func TestOptionsAreApplied(t *testing.T) {
	s := &settings{log: base.NopLogger{}, publishTimeout: defaultPublishTimeout, ignoreSelf: true}

	for _, opt := range []Option{
		WithPublishTimeout(9 * time.Second),
		WithIgnoreSelf(false),
		WithLogger(base.NopLogger{}),
	} {
		opt(s)
	}

	if s.publishTimeout != 9*time.Second {
		t.Errorf("publishTimeout = %v; want 9s", s.publishTimeout)
	}
	if s.ignoreSelf {
		t.Error("ignoreSelf should be off")
	}
}

func TestOptionsIgnoreUselessValues(t *testing.T) {
	s := &settings{log: base.NopLogger{}, publishTimeout: defaultPublishTimeout}

	WithPublishTimeout(0)(s)
	WithPublishTimeout(-time.Second)(s)
	WithLogger(nil)(s)

	if s.publishTimeout != defaultPublishTimeout {
		t.Errorf("publishTimeout = %v; want the default kept", s.publishTimeout)
	}
	if s.log == nil {
		t.Error("a nil logger must not clear the default")
	}
}

func TestPublishTimeoutLandsOnSaramaConfig(t *testing.T) {
	// SyncProducer.SendMessage 不接受 context，超时必须落到 sarama 配置上，
	// 否则 WithPublishTimeout 只是个摆设
	sc := buildSaramaConfig(Config{}, 7*time.Second)

	if sc.Producer.Timeout != 7*time.Second {
		t.Fatalf("Producer.Timeout = %v; want 7s", sc.Producer.Timeout)
	}
	if !sc.Producer.Return.Successes {
		t.Error("SyncProducer requires Return.Successes")
	}
	if sc.Producer.RequiredAcks != sarama.WaitForAll {
		t.Errorf("RequiredAcks = %v; want WaitForAll", sc.Producer.RequiredAcks)
	}
	if sc.Version != sarama.V2_8_0_0 {
		t.Errorf("Version = %v; want the default", sc.Version)
	}
}

func TestExplicitVersionIsKept(t *testing.T) {
	sc := buildSaramaConfig(Config{Version: sarama.V3_6_0_0}, time.Second)

	if sc.Version != sarama.V3_6_0_0 {
		t.Fatalf("Version = %v; want V3_6_0_0", sc.Version)
	}
}

func TestCustomSaramaConfigIsUsedVerbatim(t *testing.T) {
	// 自带配置用于 SASL / TLS 等场景，不能被默认值覆盖
	mine := sarama.NewConfig()
	mine.Producer.Timeout = 42 * time.Second

	sc := buildSaramaConfig(Config{Sarama: mine}, time.Second)
	if sc != mine {
		t.Fatal("a caller-supplied sarama config must be used as is")
	}
	if sc.Producer.Timeout != 42*time.Second {
		t.Fatalf("Producer.Timeout = %v; want the caller's value", sc.Producer.Timeout)
	}
}

func TestGroupIDDefaultsToSomethingUnique(t *testing.T) {
	// 同组内一条消息只会被一个成员消费，副本必须各自成组
	a, b := base.NewSource(), base.NewSource()
	if a == b || a == "" {
		t.Fatalf("generated group ids must be unique and non-empty: %q / %q", a, b)
	}
}

func TestEventAliasesPointAtBase(t *testing.T) {
	in := &Event{Op: base.OpAddPolicy, Source: "node-1"}

	payload, err := in.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	out, err := UnmarshalEvent(payload)
	if err != nil {
		t.Fatalf("UnmarshalEvent: %v", err)
	}
	if out.Op != base.OpAddPolicy || out.Source != "node-1" {
		t.Fatalf("out = %+v", out)
	}
}
