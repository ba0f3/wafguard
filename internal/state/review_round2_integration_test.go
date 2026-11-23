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

// Finding 4: real Redis PTTL of the per-IP metadata hash created by the first
// status observation, including after a policy update moved the fence.
func TestResponseMetaPTTLRealRedis(t *testing.T) {
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		addr = "127.0.0.1:6379"
	}
	client := redis.NewClient(&redis.Options{Addr: addr})
	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		t.Skip("redis not available:", err)
	}
	defer client.Close()
	ns := fmt.Sprintf("it_pttl_%d", time.Now().UnixNano())
	store, err := state.New(client, state.Config{
		Namespace: ns, DefaultMode: event.ModeEnforce,
		Apps:       map[string]policy.Config{"sample_app": policy.DefaultConfig()},
		AuthSource: "login-app",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		keys, _ := client.Keys(ctx, ns+":*").Result()
		if len(keys) > 0 {
			_ = client.Del(ctx, keys...).Err()
		}
	})
	if _, err := store.SetPolicy(ctx, "sample_app", 0, policy.DefaultConfig(), event.ModeEnforce); err != nil {
		t.Fatal(err)
	}
	observeStatus := func(rid string) {
		t.Helper()
		ip := netip.MustParseAddr("192.0.2.94")
		d, err := store.Check(ctx, event.Request{Application: "sample_app", ClientIP: ip, RequestID: rid})
		if err != nil {
			t.Fatal(err)
		}
		status := 200
		ev := event.Event{
			Request:      event.Request{Application: "sample_app", ClientIP: ip, RequestID: rid},
			ID:           event.EventID("sample_app", rid, event.KindObserveResponse),
			Kind:         event.KindObserveResponse,
			Admission:    d.Admission,
			OriginStatus: &status,
		}
		if err := store.Observe(ctx, ev); err != nil {
			t.Fatal(err)
		}
		metaKey := ns + ":meta:sample_app:" + ip.String()
		pttl, err := client.PTTL(ctx, metaKey).Result()
		if err != nil {
			t.Fatal(err)
		}
		if pttl <= 0 || pttl > 120*time.Second {
			t.Fatalf("meta PTTL for %s = %v, want bounded", rid, pttl)
		}
		if got := client.HGet(ctx, metaKey, "origin_status").Val(); got != "200" {
			t.Fatalf("origin_status %q", got)
		}
	}
	observeStatus("330e8400-e29b-41d4-a716-446655440001")
	// A policy update moves the fence; a fresh admission and a new IP must
	// still get a bounded meta key, not a permanent one.
	if _, err := store.SetPolicy(ctx, "sample_app", 1, policy.DefaultConfig(), event.ModeEnforce); err != nil {
		t.Fatal(err)
	}
	observeStatus("330e8400-e29b-41d4-a716-446655440002")
}
