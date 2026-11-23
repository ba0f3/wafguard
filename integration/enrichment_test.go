//go:build integration

package integration

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/ba0f3/haproxy-waf-spoe/internal/enrich"
	"github.com/ba0f3/haproxy-waf-spoe/internal/event"
	"github.com/ba0f3/haproxy-waf-spoe/internal/policy"
	"github.com/ba0f3/haproxy-waf-spoe/internal/state"
	"github.com/redis/go-redis/v9"
)

func TestEnrichmentStock(t *testing.T) {
	requireCompose(t)
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		addr = "127.0.0.1:6379"
	}
	client := redis.NewClient(&redis.Options{Addr: addr})
	if err := client.Ping(context.Background()).Err(); err != nil {
		t.Fatal(err)
	}
	store, err := state.New(client, state.Config{
		Namespace:   "enrich",
		DefaultMode: event.ModeObserve,
		Apps:        map[string]policy.Config{"sample_app": policy.DefaultConfig()},
	})
	if err != nil {
		t.Fatal(err)
	}
	line := []byte(`{"unique_id":"550e8400-e29b-41d4-a716-446655440099","ruleid":1001,"tags":["marker"],"severity":5,"phase":1}`)
	m, err := enrich.Parse(bytes.NewReader(line), enrich.Source{Application: "sample_app"}, enrich.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := store.Enrich(ctx, m); err != nil {
		t.Fatal(err)
	}
	ok, err := store.HasEnrichment(ctx, m.Application, m.RequestID)
	if err != nil || !ok {
		t.Fatalf("join %v %v", ok, err)
	}
	if err := store.Enrich(ctx, m); err != nil {
		t.Fatal(err)
	}
}
