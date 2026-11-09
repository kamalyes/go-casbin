/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-11-09 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-11-09 00:00:00
 * @FilePath: \go-casbin\adapter\base\base_test.go
 * @Description: 公共骨架测试
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package base

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
)

const modelText = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`

// recorder 记录 Notifier 发出的事件
type recorder struct {
	mu     sync.Mutex
	events []*Event
	err    error
}

func (r *recorder) publish(_ context.Context, payload []byte) error {
	if r.err != nil {
		return r.err
	}

	event, err := UnmarshalEvent(payload)
	if err != nil {
		return err
	}

	r.mu.Lock()
	r.events = append(r.events, event)
	r.mu.Unlock()

	return nil
}

func (r *recorder) last() *Event {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.events) == 0 {
		return nil
	}
	return r.events[len(r.events)-1]
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.events)
}

// 骨架必须满足官方两个通知器接口，各适配器只要内嵌它再补 Close 即可
type embeddedWatcher struct{ *Notifier }

func (embeddedWatcher) Close() {}

var (
	_ persist.Watcher   = embeddedWatcher{}
	_ persist.WatcherEx = embeddedWatcher{}
)

func TestEventRoundTrip(t *testing.T) {
	in := &Event{
		Op:          OpAddPolicies,
		Sec:         "p",
		PType:       "p",
		Rules:       [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}},
		Source:      "node-1",
		FieldIndex:  2,
		FieldValues: []string{"read"},
	}

	payload, err := in.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	out, err := UnmarshalEvent(payload)
	if err != nil {
		t.Fatalf("UnmarshalEvent: %v", err)
	}

	if out.Op != in.Op || out.Sec != in.Sec || out.PType != in.PType || out.Source != in.Source {
		t.Fatalf("scalar fields mismatch: got %+v want %+v", out, in)
	}
	if len(out.Rules) != 2 || out.Rules[1][2] != "write" {
		t.Fatalf("Rules = %v", out.Rules)
	}
	if out.FieldIndex != 2 || len(out.FieldValues) != 1 {
		t.Fatalf("filter fields mismatch: %+v", out)
	}
}

func TestUnmarshalEventRejectsGarbage(t *testing.T) {
	if _, err := UnmarshalEvent([]byte("not json")); err == nil {
		t.Fatal("want an error for a malformed payload")
	}
}

func TestSnapshotPoliciesCoversPAndG(t *testing.T) {
	m, err := model.NewModelFromString(modelText)
	if err != nil {
		t.Fatalf("NewModelFromString: %v", err)
	}
	m.AddPolicy("p", "p", []string{"admin", "data1", "read"})
	m.AddPolicy("g", "g", []string{"alice", "admin"})

	rules := SnapshotPolicies(m)
	if len(rules) != 2 {
		t.Fatalf("len(rules) = %d; want 2", len(rules))
	}

	seen := map[string]bool{}
	for _, r := range rules {
		seen[r[0]] = true // 首列是 ptype
	}
	if !seen["p"] || !seen["g"] {
		t.Fatalf("rules = %v; want both p and g rows", rules)
	}
}

func TestNewNotifierGeneratesSource(t *testing.T) {
	a := NewNotifier("", nil)
	b := NewNotifier("", nil)

	if a.Source() == "" || b.Source() == "" {
		t.Fatal("source should be generated when left empty")
	}
	if a.Source() == b.Source() {
		t.Fatal("generated sources must differ, otherwise replicas filter each other out")
	}
	if NewNotifier("fixed", nil).Source() != "fixed" {
		t.Fatal("an explicit source must be kept")
	}
}

func TestEmitWithoutTransportFails(t *testing.T) {
	n := NewNotifier("node-1", nil)

	if err := n.Update(); !errors.Is(err, ErrNoTransport) {
		t.Fatalf("err = %v; want ErrNoTransport", err)
	}
}

func TestEmitStampsEventMetadata(t *testing.T) {
	rec := &recorder{}
	n := NewNotifier("node-1", rec.publish)

	if err := n.Update(); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got := rec.last()
	if got.Op != OpUpdate {
		t.Errorf("Op = %q; want update", got.Op)
	}
	if got.Source != "node-1" {
		t.Errorf("Source = %q; want node-1", got.Source)
	}
	if got.ID == "" {
		t.Error("ID should be stamped")
	}
	if got.TimestampMs == 0 {
		t.Error("TimestampMs should be stamped")
	}
}

func TestEmitPropagatesTransportError(t *testing.T) {
	boom := errors.New("broker down")
	n := NewNotifier("node-1", (&recorder{err: boom}).publish)

	if err := n.Update(); !errors.Is(err, boom) {
		t.Fatalf("err = %v; want the transport error", err)
	}
}

func TestWatcherExMethodsEmitTheRightOperations(t *testing.T) {
	m, err := model.NewModelFromString(modelText)
	if err != nil {
		t.Fatalf("NewModelFromString: %v", err)
	}
	m.AddPolicy("p", "p", []string{"admin", "data1", "read"})

	cases := []struct {
		name string
		call func(n *Notifier) error
		want Operation
	}{
		{"add policy", func(n *Notifier) error {
			return n.UpdateForAddPolicy("p", "p", "alice", "data1", "read")
		}, OpAddPolicy},
		{"remove policy", func(n *Notifier) error {
			return n.UpdateForRemovePolicy("p", "p", "alice", "data1", "read")
		}, OpRemovePolicy},
		{"remove filtered", func(n *Notifier) error {
			return n.UpdateForRemoveFilteredPolicy("p", "p", 0, "alice")
		}, OpRemoveFilteredPolicy},
		{"save policy", func(n *Notifier) error {
			return n.UpdateForSavePolicy(m)
		}, OpSavePolicy},
		{"add policies", func(n *Notifier) error {
			return n.UpdateForAddPolicies("p", "p", []string{"alice", "data1", "read"})
		}, OpAddPolicies},
		{"remove policies", func(n *Notifier) error {
			return n.UpdateForRemovePolicies("p", "p", []string{"alice", "data1", "read"})
		}, OpRemovePolicies},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := &recorder{}
			n := NewNotifier("node-1", rec.publish)

			if err := c.call(n); err != nil {
				t.Fatalf("call: %v", err)
			}
			got := rec.last()
			if got.Op != c.want {
				t.Fatalf("Op = %q; want %q", got.Op, c.want)
			}
		})
	}
}

func TestUpdateForSavePolicyCarriesCountNotSnapshot(t *testing.T) {
	// 带快照会把广播打爆：5 万条策略编码后约 1.7 MB，
	// 超过 Kafka / NATS 默认的 1 MB 上限，整条全量覆盖就同步不出去了
	m, err := model.NewModelFromString(modelText)
	if err != nil {
		t.Fatalf("NewModelFromString: %v", err)
	}
	m.AddPolicy("p", "p", []string{"admin", "data1", "read"})
	m.AddPolicy("g", "g", []string{"alice", "admin"})

	rec := &recorder{}
	n := NewNotifier("node-1", rec.publish)

	if err := n.UpdateForSavePolicy(m); err != nil {
		t.Fatalf("UpdateForSavePolicy: %v", err)
	}

	got := rec.last()
	if len(got.Rules) != 0 {
		t.Fatalf("Rules = %v; want no snapshot in the payload", got.Rules)
	}
	if got.RuleCount != 2 {
		t.Fatalf("RuleCount = %d; want 2", got.RuleCount)
	}
}

func TestSavePolicyPayloadStaysSmallForLargePolicySets(t *testing.T) {
	m, err := model.NewModelFromString(modelText)
	if err != nil {
		t.Fatalf("NewModelFromString: %v", err)
	}
	for i := 0; i < 50000; i++ {
		m.AddPolicy("p", "p", []string{fmt.Sprintf("group%d", i), "data1", "read"})
	}

	rec := &recorder{}
	n := NewNotifier("node-1", rec.publish)
	if err := n.UpdateForSavePolicy(m); err != nil {
		t.Fatalf("UpdateForSavePolicy: %v", err)
	}

	payload, err := rec.last().Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	// Kafka message.max.bytes 与 NATS max_payload 默认都是 1 MiB
	const brokerDefaultLimit = 1 << 20
	if len(payload) >= brokerDefaultLimit {
		t.Fatalf("payload = %d bytes; must stay well under the %d byte broker default",
			len(payload), brokerDefaultLimit)
	}
	if rec.last().RuleCount != 50000 {
		t.Fatalf("RuleCount = %d; want 50000", rec.last().RuleCount)
	}
}

func TestCountPoliciesCoversPAndG(t *testing.T) {
	m, err := model.NewModelFromString(modelText)
	if err != nil {
		t.Fatalf("NewModelFromString: %v", err)
	}
	m.AddPolicy("p", "p", []string{"admin", "data1", "read"})
	m.AddPolicy("p", "p", []string{"admin", "data2", "read"})
	m.AddPolicy("g", "g", []string{"alice", "admin"})

	if got := CountPolicies(m); got != 3 {
		t.Fatalf("CountPolicies = %d; want 3", got)
	}
}

func TestDispatchFiltersSelfEvents(t *testing.T) {
	n := NewNotifier("node-1", (&recorder{}).publish)

	var got int
	if err := n.SetUpdateCallback(func(string) { got++ }); err != nil {
		t.Fatalf("SetUpdateCallback: %v", err)
	}

	self, _ := (&Event{Op: OpUpdate, Source: "node-1"}).Marshal()
	other, _ := (&Event{Op: OpUpdate, Source: "node-2"}).Marshal()

	if n.Dispatch(context.Background(), self) {
		t.Error("Dispatch reported a self event as delivered")
	}
	if got != 0 {
		t.Fatalf("callback ran %d times for a self event; want 0", got)
	}

	if !n.Dispatch(context.Background(), other) {
		t.Error("Dispatch should report a remote event as delivered")
	}
	if got != 1 {
		t.Fatalf("callback ran %d times for a remote event; want 1", got)
	}
}

func TestIgnoreSelfCanBeDisabled(t *testing.T) {
	n := NewNotifier("node-1", (&recorder{}).publish, WithIgnoreSelf(false))

	var got int
	_ = n.SetUpdateCallback(func(string) { got++ })

	self, _ := (&Event{Op: OpUpdate, Source: "node-1"}).Marshal()
	if !n.Dispatch(context.Background(), self) {
		t.Error("self event should be delivered once ignoreSelf is off")
	}
	if got != 1 {
		t.Fatalf("callback ran %d times; want 1", got)
	}
}

func TestDispatchIsSafeWithoutCallbackOrOnGarbage(t *testing.T) {
	n := NewNotifier("node-1", (&recorder{}).publish)

	payload, _ := (&Event{Op: OpUpdate, Source: "node-2"}).Marshal()
	if n.Dispatch(context.Background(), payload) {
		t.Error("no callback is set, nothing should be delivered")
	}

	_ = n.SetUpdateCallback(func(string) { t.Fatal("garbage must not reach the callback") })
	if n.Dispatch(context.Background(), []byte("not json")) {
		t.Error("malformed payload should not be delivered")
	}
}

func TestNotifierIsSafeUnderConcurrency(t *testing.T) {
	rec := &recorder{}
	n := NewNotifier("node-1", rec.publish)

	payload, _ := (&Event{Op: OpUpdate, Source: "node-2"}).Marshal()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = n.SetUpdateCallback(func(string) {})
		}()
		go func() {
			defer wg.Done()
			n.Dispatch(context.Background(), payload)
			_ = n.Update()
		}()
	}
	wg.Wait()

	if rec.count() != 50 {
		t.Fatalf("published %d events; want 50", rec.count())
	}
}

func TestLoggerDefaultsToNop(t *testing.T) {
	n := NewNotifier("node-1", nil)
	if n.Logger() == nil {
		t.Fatal("Logger() should never be nil")
	}

	custom := NopLogger{}
	if NewNotifier("n", nil, WithNotifierLogger(custom)).Logger() == nil {
		t.Fatal("explicit logger should be kept")
	}
	// nil 不应把默认实现覆盖掉
	if NewNotifier("n", nil, WithNotifierLogger(nil)).Logger() == nil {
		t.Fatal("a nil logger must not clear the default")
	}
}

func TestToFilter(t *testing.T) {
	want := Filter{P: []string{"alice"}}

	if got, err := ToFilter(want); err != nil || len(got.P) != 1 {
		t.Fatalf("ToFilter(value) = %v, %v", got, err)
	}
	if got, err := ToFilter(&want); err != nil || len(got.P) != 1 {
		t.Fatalf("ToFilter(pointer) = %v, %v", got, err)
	}
	if got, err := ToFilter((*Filter)(nil)); err != nil || len(got.P) != 0 {
		t.Fatalf("ToFilter(nil pointer) = %v, %v; want an empty filter", got, err)
	}
	if _, err := ToFilter("nope"); !errors.Is(err, ErrUnsupportedFilter) {
		t.Fatalf("err = %v; want ErrUnsupportedFilter", err)
	}
}

func TestFilterByPTypeDropsEmptyBranches(t *testing.T) {
	got := FilterByPType(Filter{P: []string{"alice"}, G2: []string{"", "tenant-a"}})

	if len(got) != 2 {
		t.Fatalf("got %v; want only the p and g2 branches", got)
	}
	if got["p"][0] != "alice" || got["g2"][1] != "tenant-a" {
		t.Fatalf("got %v", got)
	}
	if len(FilterByPType(Filter{})) != 0 {
		t.Fatal("an empty filter should produce no branches")
	}
}

func TestMatchesFilter(t *testing.T) {
	rule := []string{"alice", "data1", "read"}

	cases := []struct {
		name       string
		fieldIndex int
		values     []string
		want       bool
	}{
		{"exact match", 0, []string{"alice", "data1", "read"}, true},
		{"blank is a wildcard", 0, []string{"", "data1", ""}, true},
		{"mismatch", 0, []string{"bob"}, false},
		{"offset match", 1, []string{"data1"}, true},
		{"out of range", 5, []string{"x"}, false},
		{"no constraint", 0, nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := MatchesFilter(rule, c.fieldIndex, c.values); got != c.want {
				t.Fatalf("MatchesFilter = %v; want %v", got, c.want)
			}
		})
	}
}
