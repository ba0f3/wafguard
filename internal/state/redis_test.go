package state_test

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/ba0f3/haproxy-waf-spoe/internal/event"
	"github.com/ba0f3/haproxy-waf-spoe/internal/policy"
	"github.com/ba0f3/haproxy-waf-spoe/internal/state"
	"github.com/redis/go-redis/v9"
)

func testStore(t *testing.T) (*state.Store, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	store, err := state.New(client, state.Config{
		Namespace:   "test",
		DefaultMode: event.ModeEnforce,
		Apps:        map[string]policy.Config{"sample_app": policy.DefaultConfig()},
	})
	if err != nil {
		t.Fatal(err)
	}
	return store, mr
}

func TestLostCommitObserveFenced(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	ip := netip.MustParseAddr("192.0.2.66")
	rid := "550e8400-e29b-41d4-a716-446655440088"
	d1, _ := store.Check(ctx, event.Request{Application: "sample_app", ClientIP: ip, RequestID: rid})
	if _, err := store.Unban(ctx, state.UnbanRequest{Application: "sample_app", ClientIP: ip, OperationID: "op-lost"}); err != nil {
		t.Fatal(err)
	}
	d2, _ := store.Check(ctx, event.Request{Application: "sample_app", ClientIP: ip})
	ev := event.Event{
		Request:    event.Request{Application: "sample_app", ClientIP: ip, RequestID: rid},
		ID:         event.EventID("sample_app", rid, event.KindWafVerdict),
		Kind:       event.KindWafVerdict,
		Admission:  d1.Admission,
		RequestWAF: event.Verdict{Action: "deny", Source: "enforced"},
	}
	if err := store.Observe(ctx, ev); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		ev.ID = event.EventID("sample_app", fmt.Sprintf("550e8400-e29b-41d4-a716-44665544009%d", i), event.KindWafVerdict)
		ev.Request.RequestID = fmt.Sprintf("550e8400-e29b-41d4-a716-44665544009%d", i)
		ev.Admission = d2.Admission
		_ = store.Observe(ctx, ev)
	}
	d3, _ := store.Check(ctx, event.Request{Application: "sample_app", ClientIP: ip})
	if d3.Action == event.ActionBan {
		t.Fatal("fenced stale admission must not commit ban")
	}
}

func TestSharedBan(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	ip := netip.MustParseAddr("192.0.2.8")
	req := event.Request{Application: "sample_app", ClientIP: ip}
	ids := []string{
		"550e8400-e29b-41d4-a716-446655440001",
		"550e8400-e29b-41d4-a716-446655440002",
		"550e8400-e29b-41d4-a716-446655440003",
	}
	for _, rid := range ids {
		r := req
		r.RequestID = rid
		admission, err := store.Check(ctx, r)
		if err != nil {
			t.Fatal(err)
		}
		ev := event.Event{
			Request:    r,
			ID:         event.EventID("sample_app", rid, event.KindWafVerdict),
			Kind:       event.KindWafVerdict,
			Phase:      event.PhaseRequest,
			Admission:  admission.Admission,
			RequestWAF: event.Verdict{Action: "deny", Source: "enforced"},
		}
		if err := store.Observe(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	d2, err := store.Check(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if d2.Action != event.ActionBan {
		t.Fatalf("want ban got %s", d2.Action)
	}
}

func TestAuthReceiptJoinBothOrders(t *testing.T) {
	store, mr := testStore(t)
	ctx := context.Background()

	rid := "550e8400-e29b-41d4-a716-446655440020"
	key := "test:auth:sample_app:" + rid
	admit1, _ := store.Check(ctx, event.Request{Application: "sample_app", RequestID: rid, ClientIP: netip.MustParseAddr("192.0.2.1")})
	if err := store.RecordAuth(ctx, policy.AuthReceipt{
		Application: "sample_app",
		RequestID:   rid,
		Outcome:     policy.AuthFailure,
		SourceID:    "login-app",
		ClientIP:    netip.MustParseAddr("192.0.2.1"),
	}); err != nil {
		t.Fatal(err)
	}
	ev := event.Event{
		Request:    event.Request{Application: "sample_app", RequestID: rid, ClientIP: netip.MustParseAddr("192.0.2.1")},
		ID:         event.EventID("sample_app", rid, event.KindWafVerdict),
		Kind:       event.KindWafVerdict,
		RequestWAF: event.Verdict{Action: "allow", Source: "enforced"},
	}
	ev.Admission = admit1.Admission
	if err := store.Observe(ctx, ev); err != nil {
		t.Fatal(err)
	}
	if o := mr.HGet(key, "outcome"); o != "failure" {
		t.Fatalf("auth before observe join outcome %q", o)
	}
	if j := mr.HGet(key, "joined"); j != "1" {
		t.Fatalf("auth before observe joined %q", j)
	}

	rid2 := "550e8400-e29b-41d4-a716-446655440021"
	key2 := "test:auth:sample_app:" + rid2
	ev2 := event.Event{
		Request:    event.Request{Application: "sample_app", RequestID: rid2, ClientIP: netip.MustParseAddr("192.0.2.2")},
		ID:         event.EventID("sample_app", rid2, event.KindWafVerdict),
		Kind:       event.KindWafVerdict,
		RequestWAF: event.Verdict{Action: "allow", Source: "enforced"},
	}
	d2, _ := store.Check(ctx, ev2.Request)
	ev2.Admission = d2.Admission
	if err := store.Observe(ctx, ev2); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAuth(ctx, policy.AuthReceipt{
		Application: "sample_app",
		RequestID:   rid2,
		Outcome:     policy.AuthSuccess,
		SourceID:    "login-app",
		ClientIP:    netip.MustParseAddr("192.0.2.2"),
	}); err != nil {
		t.Fatal(err)
	}
	if o := mr.HGet(key2, "outcome"); o != "success" {
		t.Fatalf("observe before auth join outcome %q", o)
	}
	if j := mr.HGet(key2, "joined"); j != "1" {
		t.Fatalf("observe before auth joined %q", j)
	}
}

func TestAuthReceiptDuplicateRejected(t *testing.T) {
	store, mr := testStore(t)
	ctx := context.Background()
	rid := "550e8400-e29b-41d4-a716-446655440012"
	key := "test:auth:sample_app:" + rid
	_, _ = store.Check(ctx, event.Request{Application: "sample_app", RequestID: rid, ClientIP: netip.MustParseAddr("192.0.2.3")})
	if err := store.RecordAuth(ctx, policy.AuthReceipt{
		Application: "sample_app", RequestID: rid, Outcome: policy.AuthFailure, SourceID: "login-app", ClientIP: netip.MustParseAddr("192.0.2.3"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAuth(ctx, policy.AuthReceipt{
		Application: "sample_app", RequestID: rid, Outcome: policy.AuthSuccess, SourceID: "login-app", ClientIP: netip.MustParseAddr("192.0.2.3"),
	}); err != nil {
		t.Fatal(err)
	}
	if o := mr.HGet(key, "outcome"); o != "failure" {
		t.Fatalf("duplicate must keep first outcome %q", o)
	}
}

func TestAuthReceiptStoredOnce(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	rid := "550e8400-e29b-41d4-a716-446655440010"
	rid2 := "550e8400-e29b-41d4-a716-446655440011"
	ip := netip.MustParseAddr("192.0.2.4")
	_, _ = store.Check(ctx, event.Request{Application: "sample_app", RequestID: rid, ClientIP: ip})
	_, _ = store.Check(ctx, event.Request{Application: "sample_app", RequestID: rid2, ClientIP: ip})
	for i := 0; i < 2; i++ {
		if err := store.RecordAuth(ctx, policy.AuthReceipt{
			Application: "sample_app", RequestID: rid, Outcome: policy.AuthFailure,
			SourceID: "login-app", ClientIP: ip,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.RecordAuth(ctx, policy.AuthReceipt{
		Application: "sample_app", RequestID: rid2, Outcome: policy.AuthSuccess,
		SourceID: "login-app", ClientIP: ip,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestObserveModeShadow(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	store, err := state.New(client, state.Config{
		Namespace:   "test2",
		DefaultMode: event.ModeObserve,
		Apps:        map[string]policy.Config{"sample_app": policy.DefaultConfig()},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ip := netip.MustParseAddr("192.0.2.9")
	for i := 0; i < 3; i++ {
		rid := fmt.Sprintf("650e8400-e29b-41d4-a716-44665544000%d", i+1)
		d, _ := store.Check(ctx, event.Request{Application: "sample_app", ClientIP: ip, RequestID: rid})
		ev := event.Event{
			Request:    event.Request{Application: "sample_app", ClientIP: ip, RequestID: rid},
			ID:         event.EventID("sample_app", rid, event.KindWafVerdict),
			Kind:       event.KindWafVerdict,
			Admission:  d.Admission,
			RequestWAF: event.Verdict{Action: "deny", Source: "enforced"},
		}
		_ = store.Observe(ctx, ev)
	}
	d2, _ := store.Check(ctx, event.Request{Application: "sample_app", ClientIP: ip})
	if d2.Action == event.ActionBan {
		t.Fatal("observe mode should not enforce ban")
	}
}
