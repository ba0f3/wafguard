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
	d1, _ := store.Check(ctx, event.Request{Application: "sample_app", ClientIP: ip})
	if _, err := store.Unban(ctx, state.UnbanRequest{Application: "sample_app", ClientIP: ip, OperationID: "op-lost"}); err != nil {
		t.Fatal(err)
	}
	d2, _ := store.Check(ctx, event.Request{Application: "sample_app", ClientIP: ip})
	ev := event.Event{
		Request:    event.Request{Application: "sample_app", ClientIP: ip, RequestID: "550e8400-e29b-41d4-a716-446655440088"},
		ID:         event.EventID("sample_app", "550e8400-e29b-41d4-a716-446655440088", event.KindWafVerdict),
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
	d1, err := store.Check(ctx, req)
	if err != nil || d1.Action != event.ActionAllow {
		t.Fatalf("first check: %v %v", d1, err)
	}
	ids := []string{
		"550e8400-e29b-41d4-a716-446655440001",
		"550e8400-e29b-41d4-a716-446655440002",
		"550e8400-e29b-41d4-a716-446655440003",
	}
	for _, rid := range ids {
		r := req
		r.RequestID = rid
		ev := event.Event{
			Request:    r,
			ID:         event.EventID("sample_app", rid, event.KindWafVerdict),
			Kind:       event.KindWafVerdict,
			Phase:      event.PhaseRequest,
			Admission:  d1.Admission,
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

func TestAuthReceiptStoredOnce(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	rid := "550e8400-e29b-41d4-a716-446655440010"
	for i := 0; i < 2; i++ {
		if err := store.RecordAuth(ctx, policy.AuthReceipt{
			Application: "sample_app",
			RequestID:   rid,
			Outcome:     policy.AuthFailure,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.RecordAuth(ctx, policy.AuthReceipt{
		Application: "sample_app",
		RequestID:   "550e8400-e29b-41d4-a716-446655440011",
		Outcome:     policy.AuthSuccess,
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
	d, _ := store.Check(ctx, event.Request{Application: "sample_app", ClientIP: ip})
	for i := 0; i < 3; i++ {
		rid := fmt.Sprintf("650e8400-e29b-41d4-a716-44665544000%d", i+1)
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

