//go:build integration

package state_test

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/ba0f3/haproxy-waf-spoe/internal/event"
	"github.com/ba0f3/haproxy-waf-spoe/internal/policy"
	"github.com/ba0f3/haproxy-waf-spoe/internal/state"
	"github.com/redis/go-redis/v9"
)

func testBruteStore(t *testing.T) (*state.Store, redis.UniversalClient, string) {
	t.Helper()
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		addr = "127.0.0.1:6379"
	}
	client := redis.NewClient(&redis.Options{Addr: addr})
	if err := client.Ping(context.Background()).Err(); err != nil {
		t.Skip("redis not available:", err)
	}
	ns := fmt.Sprintf("it_brute_%d", time.Now().UnixNano())
	cfg := policy.DefaultConfig()
	cfg.BruteFailures = 10
	cfg.BruteWindowSec = 60
	store, err := state.New(client, state.Config{
		Namespace:   ns,
		DefaultMode: event.ModeEnforce,
		Apps:        map[string]policy.Config{"sample_app": cfg},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	_ = client.Set(ctx, ns+":mode:sample_app", "enforce", 0).Err()
	return store, client, ns
}

func postAuthObserve(t *testing.T, store *state.Store, ip netip.Addr, rid string, orderAuthFirst bool) {
	t.Helper()
	ctx := context.Background()
	rcpt := policy.AuthReceipt{
		Application: "sample_app",
		RequestID:   rid,
		Outcome:     policy.AuthFailure,
		SourceID:    "login",
		ClientIP:    ip,
	}
	ev := event.Event{
		Request:    event.Request{Application: "sample_app", RequestID: rid, ClientIP: ip},
		ID:         event.EventID("sample_app", rid, event.KindWafVerdict),
		Kind:       event.KindWafVerdict,
		RequestWAF: event.Verdict{Action: "allow", Source: "enforced"},
	}
	d, _ := store.Check(ctx, ev.Request)
	ev.Admission = d.Admission
	if orderAuthFirst {
		if err := store.RecordAuth(ctx, rcpt); err != nil {
			t.Fatal(err)
		}
		if err := store.Observe(ctx, ev); err != nil {
			t.Fatal(err)
		}
		return
	}
	if err := store.Observe(ctx, ev); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAuth(ctx, rcpt); err != nil {
		t.Fatal(err)
	}
}

func TestBruteForceNineVersusTenRealRedis(t *testing.T) {
	store, client, ns := testBruteStore(t)
	ctx := context.Background()
	ip := netip.MustParseAddr("192.0.2.55")
	banKey := ns + ":ban:sample_app:" + ip.String()
	bruteKey := ns + ":brute:sample_app:" + ip.String()
	_ = client.Del(ctx, banKey, bruteKey).Err()

	for i := 0; i < 9; i++ {
		rid := fmt.Sprintf("550e8400-e29b-41d4-a716-4466554400%02d", 40+i)
		postAuthObserve(t, store, ip, rid, i%2 == 0)
	}
	if n, _ := client.ZCard(ctx, bruteKey).Result(); n != 9 {
		t.Fatalf("brute zcard %d want 9", n)
	}
	if _, err := client.Get(ctx, banKey).Result(); err != redis.Nil {
		t.Fatalf("9 failures must not ban yet: %v", err)
	}
	rid10 := "550e8400-e29b-41d4-a716-446655440049"
	postAuthObserve(t, store, ip, rid10, true)
	if ban, err := client.Get(ctx, banKey).Result(); err != nil || ban == "" {
		t.Fatalf("10th failure must ban, got %q err=%v", ban, err)
	}
	t.Cleanup(func() { _ = client.FlushDB(ctx).Err() })
}

func TestBruteForceDuplicateAuthReceiptRealRedis(t *testing.T) {
	store, client, ns := testBruteStore(t)
	ctx := context.Background()
	ip := netip.MustParseAddr("192.0.2.56")
	rid := "550e8400-e29b-41d4-a716-446655440060"
	bruteKey := ns + ":brute:sample_app:" + ip.String()
	rcpt := policy.AuthReceipt{
		Application: "sample_app", RequestID: rid, Outcome: policy.AuthFailure,
		SourceID: "login", ClientIP: ip,
	}
	_ = store.RecordAuth(ctx, rcpt)
	_ = store.RecordAuth(ctx, rcpt)
	ev := event.Event{
		Request:    event.Request{Application: "sample_app", RequestID: rid, ClientIP: ip},
		ID:         event.EventID("sample_app", rid, event.KindWafVerdict),
		Kind:       event.KindWafVerdict,
		RequestWAF: event.Verdict{Action: "allow", Source: "enforced"},
	}
	d, _ := store.Check(ctx, ev.Request)
	ev.Admission = d.Admission
	_ = store.Observe(ctx, ev)
	if n, _ := client.ZCard(ctx, bruteKey).Result(); n != 1 {
		t.Fatalf("joined failure counts once, got %d", n)
	}
	_ = store.RecordAuth(ctx, rcpt)
	if n, _ := client.ZCard(ctx, bruteKey).Result(); n != 1 {
		t.Fatalf("duplicate after join must not recount, got %d", n)
	}
}
