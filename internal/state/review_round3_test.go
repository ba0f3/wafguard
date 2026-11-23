package state_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/ba0f3/haproxy-waf-spoe/internal/event"
	"github.com/ba0f3/haproxy-waf-spoe/internal/policy"
	"github.com/ba0f3/haproxy-waf-spoe/internal/state"
	"github.com/redis/go-redis/v9"
)

// Two admitted apps must not share one auth source: the listener is bound to
// exactly one application and receipts for the other app are rejected.
func TestAuthSourceBoundToOneAdmittedApp(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer func() { _ = client.Close() }()
	store, err := state.New(client, state.Config{
		DefaultMode: event.ModeEnforce, AuthSource: "login-app",
		Apps: map[string]policy.Config{"sample_app": policy.DefaultConfig(), "other_app": policy.DefaultConfig()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if store.AuthApplication() != "sample_app" {
		t.Fatalf("default auth binding %q want sample_app", store.AuthApplication())
	}
	ctx := context.Background()
	rid := "550e8400-e29b-41d4-a716-446655440000"
	otherRID := "550e8400-e29b-41d4-a716-446655440001"
	for _, row := range []struct{ app, id string }{{"sample_app", rid}, {"other_app", otherRID}} {
		if _, err := store.Check(ctx, event.Request{
			Application: row.app, RequestID: row.id, ClientIP: netip.MustParseAddr("192.0.2.1"),
		}); err != nil {
			t.Fatal(err)
		}
	}
	receipt := policy.AuthReceipt{
		Application: "sample_app", SourceID: "login-app", RequestID: rid, Outcome: policy.AuthSuccess,
	}
	if err := store.RecordAuth(ctx, receipt); err != nil {
		t.Fatalf("bound app receipt rejected: %v", err)
	}
	receipt.Application = "other_app"
	receipt.RequestID = otherRID
	if err := store.RecordAuth(ctx, receipt); err == nil {
		t.Fatal("auth source accepted for another admitted application")
	}
	if mr.Exists("wg:auth:sample_app:" + otherRID) {
		t.Fatal("cross-app receipt was persisted")
	}
}

// A retry with the same id but a different reason (or suppression) must be a
// conflict; an exact retry is idempotent down to the returned expiry.
func TestUnbanFingerprintIncludesReason(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer func() { _ = client.Close() }()
	store, err := state.New(client, state.Config{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	req := state.UnbanRequest{
		Application: "sample_app", ClientIP: netip.MustParseAddr("192.0.2.1"),
		OperationID: "op-reason", Reason: "original", Suppression: time.Minute,
	}
	first, err := store.Unban(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := store.Unban(ctx, req)
	if err != nil || retry != first {
		t.Fatalf("exact retry: %+v err %v want %+v", retry, err, first)
	}
	changed := req
	changed.Reason = "changed"
	if _, err := store.Unban(ctx, changed); err != state.ErrOperationConflict {
		t.Fatalf("changed reason err=%v want ErrOperationConflict", err)
	}
	changed = req
	changed.Suppression = 2 * time.Minute
	if _, err := store.Unban(ctx, changed); err != state.ErrOperationConflict {
		t.Fatalf("changed suppression err=%v want ErrOperationConflict", err)
	}
}
