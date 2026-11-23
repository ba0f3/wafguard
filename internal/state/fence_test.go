package state_test

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	"github.com/ba0f3/haproxy-waf-spoe/internal/event"
	"github.com/ba0f3/haproxy-waf-spoe/internal/policy"
	"github.com/ba0f3/haproxy-waf-spoe/internal/state"
)

func observeDeny(t *testing.T, store *state.Store, d event.Decision, ip netip.Addr, rid string) {
	t.Helper()
	ev := event.Event{
		Request:    event.Request{Application: "sample_app", ClientIP: ip, RequestID: rid},
		ID:         event.EventID("sample_app", rid, event.KindWafVerdict),
		Kind:       event.KindWafVerdict,
		Admission:  d.Admission,
		RequestWAF: event.Verdict{Action: "deny", Source: "enforced"},
	}
	if err := store.Observe(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
}

func TestSetPolicyStaleRevision(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	_, err := store.SetPolicy(ctx, "sample_app", 99, policy.DefaultConfig(), event.ModeObserve)
	if err == nil {
		t.Fatal("want stale revision error")
	}
}

func TestUnbanFence(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	ip := netip.MustParseAddr("192.0.2.55")
	d1, _ := store.Check(ctx, event.Request{Application: "sample_app", ClientIP: ip})
	for i := 0; i < 3; i++ {
		observeDeny(t, store, d1, ip, fmt.Sprintf("750e8400-e29b-41d4-a716-4466554400%d", i))
	}
	if _, err := store.Unban(ctx, state.UnbanRequest{Application: "sample_app", ClientIP: ip}); err != nil {
		t.Fatal(err)
	}
	ev := event.Event{
		Request:    event.Request{Application: "sample_app", ClientIP: ip, RequestID: "750e8400-e29b-41d4-a716-446655440099"},
		ID:         event.EventID("sample_app", "750e8400-e29b-41d4-a716-446655440099", event.KindWafVerdict),
		Kind:       event.KindWafVerdict,
		Admission:  d1.Admission,
		RequestWAF: event.Verdict{Action: "deny", Source: "enforced"},
	}
	_ = store.Observe(ctx, ev)
	d2, _ := store.Check(ctx, event.Request{Application: "sample_app", ClientIP: ip})
	if d2.Action == event.ActionBan {
		t.Fatal("stale admission observe must be fenced")
	}
}

func TestModeRevisionFence(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	ip := netip.MustParseAddr("192.0.2.56")
	d1, _ := store.Check(ctx, event.Request{Application: "sample_app", ClientIP: ip})
	old := d1.Admission
	_, err := store.SetPolicy(ctx, "sample_app", 0, policy.DefaultConfig(), event.ModeObserve)
	if err != nil {
		t.Fatal(err)
	}
	ev := event.Event{
		Request:    event.Request{Application: "sample_app", ClientIP: ip, RequestID: "850e8400-e29b-41d4-a716-446655440001"},
		ID:         event.EventID("sample_app", "850e8400-e29b-41d4-a716-446655440001", event.KindWafVerdict),
		Kind:       event.KindWafVerdict,
		Admission:  old,
		RequestWAF: event.Verdict{Action: "deny", Source: "enforced"},
	}
	_ = store.Observe(ctx, ev)
	d2, _ := store.Check(ctx, event.Request{Application: "sample_app", ClientIP: ip})
	if d2.Action == event.ActionBan {
		t.Fatal("mode revision fence should drop old admission event")
	}
}

func TestNewAdmissionAfterPolicyChangeCounts(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	ip := netip.MustParseAddr("192.0.2.58")
	_, err := store.SetPolicy(ctx, "sample_app", 0, policy.DefaultConfig(), event.ModeEnforce)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := store.Check(ctx, event.Request{Application: "sample_app", ClientIP: ip})
	for i := 0; i < 3; i++ {
		observeDeny(t, store, d, ip, fmt.Sprintf("950e8400-e29b-41d4-a716-4466554400%d", i))
	}
	dBan, _ := store.Check(ctx, event.Request{Application: "sample_app", ClientIP: ip})
	if dBan.Action != event.ActionBan {
		t.Fatalf("post-policy admissions must count toward ban, got %s", dBan.Action)
	}
}

func TestUnbanClearsActiveBan(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	ip := netip.MustParseAddr("192.0.2.57")
	d1, _ := store.Check(ctx, event.Request{Application: "sample_app", ClientIP: ip})
	for i := 0; i < 3; i++ {
		observeDeny(t, store, d1, ip, fmt.Sprintf("950e8400-e29b-41d4-a716-44665544000%d", i))
	}
	dBan, _ := store.Check(ctx, event.Request{Application: "sample_app", ClientIP: ip})
	if dBan.Action != event.ActionBan {
		t.Fatalf("want ban got %s", dBan.Action)
	}
	if _, err := store.Unban(ctx, state.UnbanRequest{Application: "sample_app", ClientIP: ip, OperationID: "op-1"}); err != nil {
		t.Fatal(err)
	}
	d2, _ := store.Check(ctx, event.Request{Application: "sample_app", ClientIP: ip})
	if d2.Action != event.ActionAllow {
		t.Fatalf("after unban want allow got %s", d2.Action)
	}
}
