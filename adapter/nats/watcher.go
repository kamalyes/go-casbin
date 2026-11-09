/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\adapter\nats\watcher.go
 * @Description: 基于 NATS / JetStream 的策略变更通知器，实现官方 persist.WatcherEx
 *
 * 两种投递语义：
 *   - 核心 pub/sub：最轻量，投递即忘，副本重启期间的变更会丢
 *   - JetStream：事件落盘 + Durable 消费者，副本重启后能补齐缺口
 *
 * 广播语义、回调管理与自环过滤都在 base.Notifier，这里只负责 NATS 传输。
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package nats

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/casbin/casbin/v3/persist"
	"github.com/kamalyes/go-casbin/adapter/base"
	natsgo "github.com/nats-io/nats.go"
)

// 默认值
const (
	defaultSubject    = "casbin.policy.changes"
	defaultStreamName = "CASBIN_POLICY"
	defaultMaxAge     = 24 * time.Hour
)

// Watcher 基于 NATS 的策略变更通知器
type Watcher struct {
	*base.Notifier

	subject string
	log     Logger

	conn *natsgo.Conn
	js   natsgo.JetStreamContext
	sub  *natsgo.Subscription

	closeOnce sync.Once
}

// 编译期确认实现了官方接口
var (
	_ persist.Watcher   = (*Watcher)(nil)
	_ persist.WatcherEx = (*Watcher)(nil)
)

// NewWatcher 创建 NATS 通知器并开始订阅
//
//	w, err := nats.NewWatcher(nats.Config{
//	    URLs:      []string{"nats://127.0.0.1:4222"},
//	    JetStream: true,
//	    Durable:   os.Getenv("POD_NAME"), // 稳定标识才能在重启后补齐
//	})
//	e.SetWatcher(w)
func NewWatcher(cfg Config, opts ...Option) (*Watcher, error) {
	if len(cfg.URLs) == 0 {
		return nil, ErrNoURLs
	}

	s := &settings{log: base.NopLogger{}, ignoreSelf: true}
	for _, opt := range opts {
		opt(s)
	}

	cfg = cfg.withDefaults()

	conn, err := natsgo.Connect(strings.Join(cfg.URLs, ","), cfg.Options...)
	if err != nil {
		return nil, err
	}

	w := &Watcher{
		subject: cfg.Subject,
		log:     s.log,
		conn:    conn,
	}
	w.Notifier = base.NewNotifier(cfg.Source, w.send,
		base.WithNotifierLogger(s.log),
		base.WithIgnoreSelf(s.ignoreSelf),
	)

	if err := w.subscribe(cfg); err != nil {
		conn.Close()
		return nil, err
	}

	w.log.InfoContextKV(context.Background(), "casbin nats watcher started",
		"subject", cfg.Subject, "jetstream", cfg.JetStream, "source", w.Source())

	return w, nil
}

// withDefaults 补齐缺省配置
func (c Config) withDefaults() Config {
	if c.Subject == "" {
		c.Subject = defaultSubject
	}
	if c.StreamName == "" {
		c.StreamName = defaultStreamName
	}
	if c.MaxAge <= 0 {
		c.MaxAge = defaultMaxAge
	}

	return c
}

// Close 退订并关闭连接
func (w *Watcher) Close() {
	w.closeOnce.Do(func() {
		if w.sub != nil {
			_ = w.sub.Unsubscribe()
		}
		if w.conn != nil {
			// Drain 让在途消息处理完再断开，避免丢掉已收到但未回调的事件
			_ = w.conn.Drain()
		}

		w.log.InfoContextKV(context.Background(), "casbin nats watcher closed",
			"subject", w.subject)
	})
}

// subscribe 建立订阅
func (w *Watcher) subscribe(cfg Config) error {
	if !cfg.JetStream {
		sub, err := w.conn.Subscribe(w.subject, w.handle)
		if err != nil {
			return err
		}
		w.sub = sub

		return nil
	}

	js, err := w.conn.JetStream()
	if err != nil {
		return err
	}
	w.js = js

	if err := ensureStream(js, cfg); err != nil {
		return err
	}

	subOpts := []natsgo.SubOpt{natsgo.DeliverNew()}
	if cfg.Durable != "" {
		// 持久消费者：位点落在服务端，副本重启后从上次位点继续
		subOpts = append(subOpts, natsgo.Durable(cfg.Durable))
	}

	sub, err := js.Subscribe(w.subject, w.handle, subOpts...)
	if err != nil {
		return err
	}
	w.sub = sub

	return nil
}

// ensureStream 幂等地创建承载策略事件的流
func ensureStream(js natsgo.JetStreamContext, cfg Config) error {
	if _, err := js.StreamInfo(cfg.StreamName); err == nil {
		return nil
	} else if !errors.Is(err, natsgo.ErrStreamNotFound) {
		return err
	}

	_, err := js.AddStream(&natsgo.StreamConfig{
		Name:      cfg.StreamName,
		Subjects:  []string{cfg.Subject},
		Storage:   natsgo.FileStorage,
		Retention: natsgo.LimitsPolicy,
		MaxAge:    cfg.MaxAge,
	})

	return err
}

// send 把一条已编码的事件发到 subject
// 启用 JetStream 时等待服务端 ack，确认落盘后才返回
func (w *Watcher) send(_ context.Context, payload []byte) error {
	if w.js != nil {
		_, err := w.js.Publish(w.subject, payload)
		return err
	}

	return w.conn.Publish(w.subject, payload)
}

// handle 处理一条订阅消息
func (w *Watcher) handle(msg *natsgo.Msg) {
	// JetStream 消息需要 ack，否则会被重投
	if w.js != nil {
		defer func() { _ = msg.Ack() }()
	}

	w.Dispatch(context.Background(), msg.Data)
}
