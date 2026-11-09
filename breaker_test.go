/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\breaker_test.go
 * @Description: 熔断器测试
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package casbin

import (
	"errors"
	"sync"
	"testing"
	"time"
)

var errBoom = errors.New("boom")

func TestBreakerDefaultsAreApplied(t *testing.T) {
	b := NewBreaker("t", BreakerConfig{})

	if b.cfg.MaxFailures != 5 || b.cfg.ResetTimeout != 10*time.Second || b.cfg.HalfOpenSuccesses != 1 {
		t.Fatalf("defaults = %+v", b.cfg)
	}
	if b.Name() != "t" {
		t.Fatalf("Name = %q", b.Name())
	}
	if b.State() != BreakerClosed {
		t.Fatalf("State = %v; want closed", b.State())
	}
}

func TestBreakerOpensAfterConsecutiveFailures(t *testing.T) {
	b := NewBreaker("t", BreakerConfig{MaxFailures: 3, ResetTimeout: time.Hour})

	for i := 0; i < 2; i++ {
		if err := b.Execute(func() error { return errBoom }); !errors.Is(err, errBoom) {
			t.Fatalf("attempt %d: err = %v", i, err)
		}
		if b.State() != BreakerClosed {
			t.Fatalf("after %d failures state = %v; want still closed", i+1, b.State())
		}
	}

	if err := b.Execute(func() error { return errBoom }); !errors.Is(err, errBoom) {
		t.Fatalf("third failure: err = %v", err)
	}
	if b.State() != BreakerOpen {
		t.Fatalf("state = %v; want open", b.State())
	}

	var called bool
	if err := b.Execute(func() error { called = true; return nil }); !errors.Is(err, ErrBreakerOpen) {
		t.Fatalf("err = %v; want ErrBreakerOpen", err)
	}
	if called {
		t.Error("fn must not run while the breaker is open")
	}
}

func TestBreakerSuccessResetsFailureStreak(t *testing.T) {
	b := NewBreaker("t", BreakerConfig{MaxFailures: 2, ResetTimeout: time.Hour})

	_ = b.Execute(func() error { return errBoom })
	_ = b.Execute(func() error { return nil }) // 连续失败被打断
	_ = b.Execute(func() error { return errBoom })

	if b.State() != BreakerClosed {
		t.Fatalf("state = %v; want closed (the streak was broken)", b.State())
	}
}

func TestBreakerHalfOpenRecoversToClosed(t *testing.T) {
	b := NewBreaker("t", BreakerConfig{
		MaxFailures:       1,
		ResetTimeout:      10 * time.Millisecond,
		HalfOpenSuccesses: 2,
	})

	_ = b.Execute(func() error { return errBoom })
	if b.State() != BreakerOpen {
		t.Fatalf("state = %v; want open", b.State())
	}

	time.Sleep(20 * time.Millisecond)
	if b.State() != BreakerHalfOpen {
		t.Fatalf("state = %v; want half-open after the reset timeout", b.State())
	}

	// 需要连续 2 次成功才闭合
	if err := b.Execute(func() error { return nil }); err != nil {
		t.Fatalf("probe 1: %v", err)
	}
	if b.State() != BreakerHalfOpen {
		t.Fatalf("state = %v; want still half-open after one success", b.State())
	}
	if err := b.Execute(func() error { return nil }); err != nil {
		t.Fatalf("probe 2: %v", err)
	}
	if b.State() != BreakerClosed {
		t.Fatalf("state = %v; want closed", b.State())
	}
}

func TestBreakerHalfOpenFailureReopensImmediately(t *testing.T) {
	b := NewBreaker("t", BreakerConfig{
		MaxFailures:       5, // 阈值很高，但半开失败应立刻回到打开
		ResetTimeout:      10 * time.Millisecond,
		HalfOpenSuccesses: 1,
	})

	for i := 0; i < 5; i++ {
		_ = b.Execute(func() error { return errBoom })
	}
	if b.State() != BreakerOpen {
		t.Fatalf("state = %v; want open", b.State())
	}

	time.Sleep(20 * time.Millisecond)
	if b.State() != BreakerHalfOpen {
		t.Fatalf("state = %v; want half-open", b.State())
	}

	_ = b.Execute(func() error { return errBoom })
	if b.State() != BreakerOpen {
		t.Fatalf("state = %v; want open again after a failed probe", b.State())
	}
}

func TestBreakerResetForcesClosed(t *testing.T) {
	b := NewBreaker("t", BreakerConfig{MaxFailures: 1, ResetTimeout: time.Hour})

	_ = b.Execute(func() error { return errBoom })
	if b.State() != BreakerOpen {
		t.Fatalf("state = %v; want open", b.State())
	}

	b.Reset()
	if b.State() != BreakerClosed {
		t.Fatalf("state = %v; want closed after Reset", b.State())
	}
	if err := b.Execute(func() error { return nil }); err != nil {
		t.Fatalf("Execute after Reset: %v", err)
	}
}

func TestBreakerReportsStateTransitions(t *testing.T) {
	type transition struct{ from, to BreakerState }

	var (
		mu     sync.Mutex
		events []transition
	)
	b := NewBreaker("t", BreakerConfig{
		MaxFailures:       1,
		ResetTimeout:      10 * time.Millisecond,
		HalfOpenSuccesses: 1,
		OnStateChange: func(from, to BreakerState) {
			mu.Lock()
			events = append(events, transition{from, to})
			mu.Unlock()
		},
	})

	_ = b.Execute(func() error { return errBoom }) // closed -> open
	time.Sleep(20 * time.Millisecond)
	_ = b.Execute(func() error { return nil }) // open -> half-open -> closed

	mu.Lock()
	defer mu.Unlock()
	if len(events) != 3 {
		t.Fatalf("events = %v; want 3 transitions", events)
	}
	want := []transition{
		{BreakerClosed, BreakerOpen},
		{BreakerOpen, BreakerHalfOpen},
		{BreakerHalfOpen, BreakerClosed},
	}
	for i, w := range want {
		if events[i] != w {
			t.Errorf("events[%d] = %v; want %v", i, events[i], w)
		}
	}
}

func TestBreakerStateString(t *testing.T) {
	cases := map[BreakerState]string{
		BreakerClosed:   "closed",
		BreakerOpen:     "open",
		BreakerHalfOpen: "half-open",
	}
	for state, want := range cases {
		if got := state.String(); got != want {
			t.Errorf("%d.String() = %q; want %q", state, got, want)
		}
	}
}

func TestBreakerIsSafeUnderConcurrency(t *testing.T) {
	b := NewBreaker("t", BreakerConfig{MaxFailures: 10, ResetTimeout: time.Millisecond})

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = b.Execute(func() error {
				if i%2 == 0 {
					return errBoom
				}
				return nil
			})
			_ = b.State()
		}(i)
	}
	wg.Wait()
}
