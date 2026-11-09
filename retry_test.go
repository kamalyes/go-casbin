/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\retry_test.go
 * @Description: 重试器测试
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package casbin

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRetryDefaultsAreApplied(t *testing.T) {
	r := NewRetry(RetryConfig{})

	if r.cfg.MaxAttempts != 3 || r.cfg.BaseDelay != 50*time.Millisecond || r.cfg.MaxDelay != 2*time.Second {
		t.Fatalf("defaults = %+v", r.cfg)
	}
	if r.cfg.Retryable == nil {
		t.Fatal("Retryable should get a default")
	}
}

func TestRetryClampsJitter(t *testing.T) {
	if got := NewRetry(RetryConfig{Jitter: -1}).cfg.Jitter; got != 0 {
		t.Errorf("Jitter = %v; want clamped to 0", got)
	}
	if got := NewRetry(RetryConfig{Jitter: 5}).cfg.Jitter; got != 1 {
		t.Errorf("Jitter = %v; want clamped to 1", got)
	}
}

func TestRetrySucceedsOnFirstTry(t *testing.T) {
	r := NewRetry(RetryConfig{MaxAttempts: 3, BaseDelay: time.Millisecond})

	var calls int
	if err := r.Do(context.Background(), func() error { calls++; return nil }); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if calls != 1 {
		t.Fatalf("calls = %d; want 1", calls)
	}
}

func TestRetryGivesUpAfterMaxAttempts(t *testing.T) {
	r := NewRetry(RetryConfig{MaxAttempts: 3, BaseDelay: time.Millisecond})

	var calls int
	err := r.Do(context.Background(), func() error { calls++; return errBoom })
	if !errors.Is(err, errBoom) {
		t.Fatalf("err = %v; want the last error", err)
	}
	if calls != 3 {
		t.Fatalf("calls = %d; want 3", calls)
	}
}

func TestRetryStopsOnNonRetryableError(t *testing.T) {
	fatal := errors.New("fatal")
	r := NewRetry(RetryConfig{
		MaxAttempts: 5,
		BaseDelay:   time.Millisecond,
		Retryable:   func(err error) bool { return !errors.Is(err, fatal) },
	})

	var calls int
	if err := r.Do(context.Background(), func() error { calls++; return fatal }); !errors.Is(err, fatal) {
		t.Fatalf("err = %v; want fatal", err)
	}
	if calls != 1 {
		t.Fatalf("calls = %d; want 1 (no retry on a fatal error)", calls)
	}
}

func TestRetryDoesNotRetryAnOpenBreaker(t *testing.T) {
	// 熔断已打开说明下游正在故障，重试只会放大压力
	r := NewRetry(RetryConfig{MaxAttempts: 5, BaseDelay: time.Millisecond})

	var calls int
	if err := r.Do(context.Background(), func() error { calls++; return ErrBreakerOpen }); !errors.Is(err, ErrBreakerOpen) {
		t.Fatalf("err = %v; want ErrBreakerOpen", err)
	}
	if calls != 1 {
		t.Fatalf("calls = %d; want 1", calls)
	}
}

func TestRetryHonoursCancellationBeforeFirstCall(t *testing.T) {
	r := NewRetry(RetryConfig{MaxAttempts: 3, BaseDelay: time.Millisecond})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var calls int
	if err := r.Do(ctx, func() error { calls++; return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v; want context.Canceled", err)
	}
	if calls != 0 {
		t.Fatalf("calls = %d; want 0", calls)
	}
}

func TestRetryHonoursCancellationDuringBackoff(t *testing.T) {
	r := NewRetry(RetryConfig{MaxAttempts: 5, BaseDelay: time.Hour})

	ctx, cancel := context.WithCancel(context.Background())

	var calls int
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err := r.Do(ctx, func() error { calls++; return errBoom })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v; want context.Canceled", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Do blocked for %v; cancellation should cut the backoff short", elapsed)
	}
	if calls != 1 {
		t.Fatalf("calls = %d; want 1", calls)
	}
}

func TestRetryBackoffGrowsAndStaysCapped(t *testing.T) {
	r := NewRetry(RetryConfig{BaseDelay: 10 * time.Millisecond, MaxDelay: 40 * time.Millisecond, Jitter: 0})

	cases := []struct {
		attempt int
		want    time.Duration
	}{
		{0, 10 * time.Millisecond},
		{1, 20 * time.Millisecond},
		{2, 40 * time.Millisecond},
		{3, 40 * time.Millisecond}, // 到顶后不再增长
		{9, 40 * time.Millisecond},
	}
	for _, c := range cases {
		if got := r.backoff(c.attempt); got != c.want {
			t.Errorf("backoff(%d) = %v; want %v", c.attempt, got, c.want)
		}
	}
}

func TestRetryJitterOnlyShortensTheDelay(t *testing.T) {
	// 抖动只缩不放，保证永远不超过 MaxDelay
	r := NewRetry(RetryConfig{BaseDelay: 100 * time.Millisecond, MaxDelay: 100 * time.Millisecond, Jitter: 0.5})

	for i := 0; i < 200; i++ {
		got := r.backoff(0)
		if got > 100*time.Millisecond {
			t.Fatalf("backoff = %v; must never exceed MaxDelay", got)
		}
		if got < 50*time.Millisecond {
			t.Fatalf("backoff = %v; must stay within the jitter band", got)
		}
	}
}
