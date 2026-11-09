/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\adapter\redis\pubsub.go
 * @Description: 基于 Redis Pub/Sub 的策略变更通知器，实现官方 persist.WatcherEx
 *
 * Redis Pub/Sub 没有持久化：订阅方掉线期间的消息不会补发。
 * 需要「副本重启后补齐变更」的场景请用 adapter/nats 的 JetStream 模式，
 * 或配合 go-casbin 的 WithAutoLoad 做周期性兜底重载。
 *
 * 广播语义、回调管理与自环过滤都在 base.Notifier，这里只负责 Redis 传输。
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package redis

import (
	"context"
	"sync"

	"github.com/casbin/casbin/v3/persist"
	"github.com/kamalyes/go-casbin/adapter/base"
	"github.com/redis/go-redis/v9"
)

// defaultChannel 默认广播频道
const defaultChannel = "casbin:policy:changes"

// Watcher 基于 Redis Pub/Sub 的策略变更通知器
type Watcher struct {
	*base.Notifier

	client  redis.UniversalClient
	channel string
	log     Logger

	pubsub *redis.PubSub

	cancel    context.CancelFunc
	consumeWG sync.WaitGroup
	closeOnce sync.Once
}

// 编译期确认实现了官方接口
var (
	_ persist.Watcher   = (*Watcher)(nil)
	_ persist.WatcherEx = (*Watcher)(nil)
)

// watcherSettings 通知器可选配置的收敛结果
type watcherSettings struct {
	channel    string
	source     string
	log        Logger
	ignoreSelf bool
}

// WatcherOption 通知器可选配置
type WatcherOption func(*watcherSettings)

// WithWatcherChannel 设置广播频道，默认 casbin:policy:changes
func WithWatcherChannel(channel string) WatcherOption {
	return func(s *watcherSettings) {
		if channel != "" {
			s.channel = channel
		}
	}
}

// WithWatcherSource 设置本节点标识，用于过滤自环，留空时自动生成
func WithWatcherSource(source string) WatcherOption {
	return func(s *watcherSettings) {
		if source != "" {
			s.source = source
		}
	}
}

// WithWatcherLogger 设置日志记录器
func WithWatcherLogger(l Logger) WatcherOption {
	return func(s *watcherSettings) {
		if l != nil {
			s.log = l
		}
	}
}

// WithWatcherIgnoreSelf 设置是否丢弃自身发出的事件，默认 true
func WithWatcherIgnoreSelf(ignore bool) WatcherOption {
	return func(s *watcherSettings) { s.ignoreSelf = ignore }
}

// NewWatcher 创建 Redis 通知器并开始订阅
//
//	w, err := redis.NewWatcher(client, redis.WithWatcherSource(os.Getenv("POD_NAME")))
//	e.SetWatcher(w)
func NewWatcher(client redis.UniversalClient, opts ...WatcherOption) (*Watcher, error) {
	if client == nil {
		return nil, ErrNoClient
	}

	s := &watcherSettings{
		channel:    defaultChannel,
		log:        base.NopLogger{},
		ignoreSelf: true,
	}
	for _, opt := range opts {
		opt(s)
	}

	w := &Watcher{
		client:  client,
		channel: s.channel,
		log:     s.log,
	}
	w.Notifier = base.NewNotifier(s.source, w.send,
		base.WithNotifierLogger(s.log),
		base.WithIgnoreSelf(s.ignoreSelf),
	)

	ctx, cancel := context.WithCancel(context.Background())
	w.cancel = cancel
	w.pubsub = client.Subscribe(ctx, w.channel)

	w.consumeWG.Add(1)
	go w.consume(ctx)

	w.log.InfoContextKV(ctx, "casbin redis watcher started",
		"channel", w.channel, "source", w.Source())

	return w, nil
}

// Close 退订并停止消费
func (w *Watcher) Close() {
	w.closeOnce.Do(func() {
		if w.cancel != nil {
			w.cancel()
		}
		if w.pubsub != nil {
			_ = w.pubsub.Close()
		}
		// 先断订阅再等循环退出，否则 Channel() 不会关闭、Wait 会一直挂住
		w.consumeWG.Wait()

		w.log.InfoContextKV(context.Background(), "casbin redis watcher closed",
			"channel", w.channel)
	})
}

// send 把一条已编码的事件发到频道
func (w *Watcher) send(ctx context.Context, payload []byte) error {
	return w.client.Publish(ctx, w.channel, payload).Err()
}

// consume 消费循环
func (w *Watcher) consume(ctx context.Context) {
	defer w.consumeWG.Done()

	messages := w.pubsub.Channel()
	for {
		select {
		case msg, ok := <-messages:
			if !ok {
				return
			}
			w.Dispatch(ctx, []byte(msg.Payload))
		case <-ctx.Done():
			return
		}
	}
}
