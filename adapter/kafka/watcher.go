/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\adapter\kafka\watcher.go
 * @Description: 基于 Kafka 的策略变更通知器，实现官方 persist.WatcherEx
 *
 * A 节点改完策略后向 topic 广播变更事件，其余副本消费后重载本地策略。
 * 相比轮询兜底的方案，Kafka 提供消息持久化与回溯：副本重启期间的变更不会丢。
 *
 * 广播语义、回调管理与自环过滤都在 base.Notifier，这里只负责 Kafka 传输。
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package kafka

import (
	"context"
	"sync"
	"time"

	"github.com/IBM/sarama"
	"github.com/casbin/casbin/v3/persist"
	"github.com/kamalyes/go-casbin/adapter/base"
)

// 默认值
const (
	defaultTopic          = "casbin-policy-changes"
	defaultPublishTimeout = 3 * time.Second
)

// Watcher 基于 Kafka 的策略变更通知器
type Watcher struct {
	*base.Notifier

	topic string
	log   Logger

	producer sarama.SyncProducer
	group    sarama.ConsumerGroup

	cancel    context.CancelFunc
	consumeWG sync.WaitGroup
	closeOnce sync.Once
}

// 编译期确认实现了官方接口
var (
	_ persist.Watcher   = (*Watcher)(nil)
	_ persist.WatcherEx = (*Watcher)(nil)
)

// NewWatcher 创建 Kafka 通知器并开始消费
//
//	w, err := kafka.NewWatcher(kafka.Config{
//	    Brokers: []string{"kafka-1:9092"},
//	    Source:  os.Getenv("POD_NAME"),
//	})
//	e.SetWatcher(w)
func NewWatcher(cfg Config, opts ...Option) (*Watcher, error) {
	if len(cfg.Brokers) == 0 {
		return nil, ErrNoBrokers
	}

	s := &settings{
		log:            base.NopLogger{},
		publishTimeout: defaultPublishTimeout,
		ignoreSelf:     true,
	}
	for _, opt := range opts {
		opt(s)
	}

	if cfg.Topic == "" {
		cfg.Topic = defaultTopic
	}
	// 每个副本必须独立成组，否则广播会被组内分摊、部分副本收不到
	if cfg.GroupID == "" {
		cfg.GroupID = base.NewSource()
	}

	producer, group, err := dial(cfg, s.publishTimeout)
	if err != nil {
		return nil, err
	}

	w := &Watcher{
		topic:    cfg.Topic,
		log:      s.log,
		producer: producer,
		group:    group,
	}
	w.Notifier = base.NewNotifier(cfg.Source, w.send,
		base.WithNotifierLogger(s.log),
		base.WithIgnoreSelf(s.ignoreSelf),
	)

	ctx, cancel := context.WithCancel(context.Background())
	w.cancel = cancel
	w.consumeWG.Add(1)
	go w.consume(ctx)

	w.log.InfoContextKV(ctx, "casbin kafka watcher started",
		"topic", cfg.Topic, "group", cfg.GroupID, "source", w.Source())

	return w, nil
}

// Close 停止消费并释放连接
func (w *Watcher) Close() {
	w.closeOnce.Do(func() {
		if w.cancel != nil {
			w.cancel()
		}
		// 先停消费循环再关连接，避免 ConsumeClaim 用到已关闭的 group
		w.consumeWG.Wait()

		if w.group != nil {
			_ = w.group.Close()
		}
		if w.producer != nil {
			_ = w.producer.Close()
		}

		w.log.InfoContextKV(context.Background(), "casbin kafka watcher closed", "topic", w.topic)
	})
}

// buildSaramaConfig 构造 sarama 配置
// 调用方自带 Config.Sarama 时原样使用，不做任何覆盖
func buildSaramaConfig(cfg Config, publishTimeout time.Duration) *sarama.Config {
	if cfg.Sarama != nil {
		return cfg.Sarama
	}

	sc := sarama.NewConfig()

	sc.Version = cfg.Version
	if sc.Version == (sarama.KafkaVersion{}) {
		sc.Version = sarama.V2_8_0_0
	}

	sc.Producer.Return.Successes = true
	sc.Producer.RequiredAcks = sarama.WaitForAll
	sc.Producer.Retry.Max = 3
	// SyncProducer.SendMessage 不接受 context，超时只能在这里约定
	sc.Producer.Timeout = publishTimeout

	sc.Consumer.Offsets.Initial = sarama.OffsetNewest
	sc.Consumer.Return.Errors = true

	return sc
}

// dial 建立生产者与消费组
func dial(cfg Config, publishTimeout time.Duration) (sarama.SyncProducer, sarama.ConsumerGroup, error) {
	sc := buildSaramaConfig(cfg, publishTimeout)

	producer, err := sarama.NewSyncProducer(cfg.Brokers, sc)
	if err != nil {
		return nil, nil, err
	}

	group, err := sarama.NewConsumerGroup(cfg.Brokers, cfg.GroupID, sc)
	if err != nil {
		_ = producer.Close()
		return nil, nil, err
	}

	return producer, group, nil
}

// send 把一条已编码的事件投到 topic
func (w *Watcher) send(_ context.Context, payload []byte) error {
	_, _, err := w.producer.SendMessage(&sarama.ProducerMessage{
		Topic: w.topic,
		Value: sarama.ByteEncoder(payload),
	})

	return err
}

// consume 消费循环，连接断开时由 sarama 自行重连，这里只负责重入
func (w *Watcher) consume(ctx context.Context) {
	defer w.consumeWG.Done()

	handler := &consumerHandler{watcher: w}

	for {
		if err := ctx.Err(); err != nil {
			return
		}

		if err := w.group.Consume(ctx, []string{w.topic}, handler); err != nil {
			if ctx.Err() != nil {
				return
			}
			w.log.WarnContextKV(ctx, "casbin kafka consume interrupted, retrying",
				"topic", w.topic, "error", err.Error())

			// 退避一下再重入，避免 broker 不可用时空转打满 CPU
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
		}
	}
}

// consumerHandler sarama 消费组回调
type consumerHandler struct {
	watcher *Watcher
}

func (h *consumerHandler) Setup(sarama.ConsumerGroupSession) error   { return nil }
func (h *consumerHandler) Cleanup(sarama.ConsumerGroupSession) error { return nil }

func (h *consumerHandler) ConsumeClaim(session sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	for {
		select {
		case msg, ok := <-claim.Messages():
			if !ok {
				return nil
			}
			h.watcher.Dispatch(session.Context(), msg.Value)
			session.MarkMessage(msg, "")
		case <-session.Context().Done():
			return nil
		}
	}
}
