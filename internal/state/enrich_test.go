package state_test

import (
	"context"
	"testing"

	"github.com/ba0f3/haproxy-waf-spoe/internal/enrich"
)

func TestEnrichmentJoinRedis(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	m := enrich.Match{
		Application: "sample_app",
		RequestID:   "550e8400-e29b-41d4-a716-446655440010",
		RuleID:      1001,
		Tags:        []string{"marker"},
		Severity:    5,
		PhaseID:     1,
	}
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
