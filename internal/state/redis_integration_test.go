//go:build integration

package state_test

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"testing"

	"github.com/ba0f3/haproxy-waf-spoe/internal/event"
	"github.com/ba0f3/haproxy-waf-spoe/internal/policy"
	"github.com/ba0f3/haproxy-waf-spoe/internal/state"
	"github.com/redis/go-redis/v9"
)

func TestSharedBanRedis(t *testing.T) {
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		addr = "127.0.0.1:6379"
	}
	client := redis.NewClient(&redis.Options{Addr: addr})
	if err := client.Ping(context.Background()).Err(); err != nil {
		t.Skip("redis not available:", err)
	}
	store, err := state.New(client, state.Config{
		Namespace:   fmt.Sprintf("it%x", t.Name()),
		DefaultMode: event.ModeEnforce,
		Apps:        map[string]policy.Config{"sample_app": policy.DefaultConfig()},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ip := netip.MustParseAddr("192.0.2.44")
	d1, err := store.Check(ctx, event.Request{Application: "sample_app", ClientIP: ip})
	if err != nil || d1.Action != event.ActionAllow {
		t.Fatalf("check: %v %v", d1, err)
	}
	for i := 0; i < 3; i++ {
		rid := fmt.Sprintf("750e8400-e29b-41d4-a716-44665544000%d", i)
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
	}
	d2, _ := store.Check(ctx, event.Request{Application: "sample_app", ClientIP: ip})
	if d2.Action != event.ActionBan {
		t.Fatalf("want ban got %s", d2.Action)
	}
}
