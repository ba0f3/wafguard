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

func TestAuthJoinRealRedis(t *testing.T) {
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		addr = "127.0.0.1:6379"
	}
	client := redis.NewClient(&redis.Options{Addr: addr})
	if err := client.Ping(context.Background()).Err(); err != nil {
		t.Skip("redis not available:", err)
	}
	ns := fmt.Sprintf("it_auth_%d", time.Now().UnixNano())
	store, err := state.New(client, state.Config{
		Namespace:   ns,
		DefaultMode: event.ModeEnforce,
		Apps:        map[string]policy.Config{"sample_app": policy.DefaultConfig()},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	rid := "550e8400-e29b-41d4-a716-446655440030"
	authKey := ns + ":auth:sample_app:" + rid
	if err := store.RecordAuth(ctx, policy.AuthReceipt{
		Application: "sample_app", RequestID: rid, Outcome: policy.AuthFailure, SourceID: "login",
	}); err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("192.0.2.77")
	ev := event.Event{
		Request:    event.Request{Application: "sample_app", RequestID: rid, ClientIP: ip},
		ID:         event.EventID("sample_app", rid, event.KindWafVerdict),
		Kind:       event.KindWafVerdict,
		RequestWAF: event.Verdict{Action: "allow", Source: "enforced"},
	}
	d, _ := store.Check(ctx, ev.Request)
	ev.Admission = d.Admission
	if err := store.Observe(ctx, ev); err != nil {
		t.Fatal(err)
	}
	joined, err := client.HGet(ctx, authKey, "joined").Result()
	if err != nil || joined != "1" {
		t.Fatalf("joined %q err %v", joined, err)
	}
	t.Cleanup(func() { _ = client.FlushDB(ctx).Err() })
}
