package state_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/ba0f3/haproxy-waf-spoe/internal/event"
	"github.com/ba0f3/haproxy-waf-spoe/internal/policy"
	"github.com/ba0f3/haproxy-waf-spoe/internal/state"
	"github.com/redis/go-redis/v9"
)

// Finding 7: a mode-only rollback to observe must stop enforcement even while
// an active ban key still exists; re-enabling enforce restores the ban.
func TestObserveRollbackDoesNotEnforceActiveBan(t *testing.T) {
	mr := miniredis.RunT(t)
	store := newFixStore(t, mr, "rollback")
	ctx := context.Background()
	ip := netip.MustParseAddr("192.0.2.91")
	for i, rid := range []string{fixRid1, fixRid2, fixRid3} {
		d := admit(t, store, rid, ip)
		if err := store.Observe(ctx, denyEvent(rid, ip, d)); err != nil {
			t.Fatal(err)
		}
		if i == 2 && mrGet(t, mr, "rollback:ban:sample_app:"+ip.String()) == "" {
			t.Fatal("setup ban missing")
		}
	}
	if d, _ := store.Check(ctx, event.Request{Application: "sample_app", ClientIP: ip}); d.Action != event.ActionBan {
		t.Fatalf("setup check %s want ban", d.Action)
	}

	if _, err := store.SetPolicy(ctx, "sample_app", 0, policy.DefaultConfig(), event.ModeObserve); err != nil {
		t.Fatal(err)
	}
	if mrGet(t, mr, "rollback:ban:sample_app:"+ip.String()) == "" {
		t.Fatal("mode-only rollback deleted the ban key")
	}
	d, err := store.Check(ctx, event.Request{Application: "sample_app", ClientIP: ip})
	if err != nil {
		t.Fatal(err)
	}
	if d.Action == event.ActionBan {
		t.Fatal("observe mode must not enforce an existing ban")
	}
	if d.Explanation != "observe-mode" {
		t.Fatalf("explanation %q want observe-mode", d.Explanation)
	}

	rev, _ := store.PolicyRevision(ctx, "sample_app")
	if _, err := store.SetPolicy(ctx, "sample_app", rev, policy.DefaultConfig(), event.ModeEnforce); err != nil {
		t.Fatal(err)
	}
	d, _ = store.Check(ctx, event.Request{Application: "sample_app", ClientIP: ip})
	if d.Action != event.ActionBan {
		t.Fatalf("re-enforce check %s want ban", d.Action)
	}
}

// Finding 6: when a newer revision is in play but its config cannot be loaded,
// the operation fails closed instead of silently using an older cached config.
func TestNewerPolicyLoadFailureFailsClosed(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer client.Close()
	store, err := state.New(client, state.Config{
		Namespace: "stalecfg", DefaultMode: event.ModeEnforce,
		Apps:       map[string]policy.Config{"sample_app": policy.DefaultConfig()},
		AuthSource: "login-app",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	// Replica B keeps its own cache at revision 0 and only learns about the
	// new revision through Redis.
	storeB, err := state.New(client, state.Config{
		Namespace: "stalecfg", DefaultMode: event.ModeEnforce,
		Apps:       map[string]policy.Config{"sample_app": policy.DefaultConfig()},
		AuthSource: "login-app",
	})
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("192.0.2.92")
	cfg := policy.DefaultConfig()
	cfg.WAFDenyThreshold = 2
	if _, err := store.SetPolicy(ctx, "sample_app", 0, cfg, event.ModeEnforce); err != nil {
		t.Fatal(err)
	}
	// Simulate a failed config load at the new revision.
	if err := client.Del(ctx, "stalecfg:policy:sample_app:config").Err(); err != nil {
		t.Fatal(err)
	}
	fresh := admit(t, store, fixRid2, ip)
	if err := storeB.Observe(ctx, denyEvent(fixRid2, ip, fresh)); err == nil {
		t.Fatal("observe must fail closed when new policy config is unavailable")
	}
}

// Coordinator follow-up: a Lua rejection (stale fence) must surface as an
// error, not a silent 204; a genuine duplicate stays a success.
func TestRecordAuthSurfacesLuaOutcome(t *testing.T) {
	mr := miniredis.RunT(t)
	store := newFixStore(t, mr, "authoutcome")
	ctx := context.Background()
	ip := netip.MustParseAddr("192.0.2.97")
	rid := fixRid1
	_ = admit(t, store, rid, ip)
	receipt := policy.AuthReceipt{
		Application: "sample_app", RequestID: rid, Outcome: policy.AuthFailure,
		SourceID: "login-app", ClientIP: ip,
	}
	if err := store.RecordAuth(ctx, receipt); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAuth(ctx, receipt); err != nil {
		t.Fatalf("duplicate must be idempotent: %v", err)
	}
	rid2 := fixRid2
	stale := admit(t, store, rid2, ip)
	if _, err := store.SetPolicy(ctx, "sample_app", 0, policy.DefaultConfig(), event.ModeEnforce); err != nil {
		t.Fatal(err)
	}
	_ = stale
	receipt.RequestID = rid2
	if err := store.RecordAuth(ctx, receipt); err == nil {
		t.Fatal("fenced Lua outcome must surface as an error")
	}
	if mr.Exists("authoutcome:auth:sample_app:" + rid2) {
		t.Fatal("fenced auth persisted a hash")
	}
}

// Finding 6: auth receipts are scoped to the configured app/source and a
// rejected receipt never contributes to the brute window.
func TestAuthScopeNoFalseBruteCount(t *testing.T) {
	mr := miniredis.RunT(t)
	store := newFixStore(t, mr, "scope")
	ctx := context.Background()
	ip := netip.MustParseAddr("192.0.2.93")
	cfg := policy.DefaultConfig()
	cfg.BruteFailures = 2
	if _, err := store.SetPolicy(ctx, "sample_app", 0, cfg, event.ModeEnforce); err != nil {
		t.Fatal(err)
	}
	rid := fixRid1
	admission := admit(t, store, rid, ip)
	if err := store.RecordAuth(ctx, policy.AuthReceipt{
		Application: "other_app", RequestID: rid, Outcome: policy.AuthFailure,
		SourceID: "login-app", ClientIP: ip,
	}); err == nil {
		t.Fatal("auth for an out-of-scope app must be rejected")
	}
	if err := store.RecordAuth(ctx, policy.AuthReceipt{
		Application: "sample_app", RequestID: rid, Outcome: policy.AuthFailure,
		SourceID: "untrusted", ClientIP: ip,
	}); err == nil {
		t.Fatal("untrusted source must be rejected")
	}
	if err := store.Observe(ctx, denyEvent(rid, ip, admission)); err != nil {
		t.Fatal(err)
	}
	if n := zcard(t, mr, "scope:brute:sample_app:"+ip.String()); n != 0 {
		t.Fatalf("rejected receipts counted %d brute failures", n)
	}
}
