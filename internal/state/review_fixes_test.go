package state_test

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/ba0f3/haproxy-waf-spoe/internal/enrich"
	"github.com/ba0f3/haproxy-waf-spoe/internal/event"
	"github.com/ba0f3/haproxy-waf-spoe/internal/policy"
	"github.com/ba0f3/haproxy-waf-spoe/internal/state"
	"github.com/redis/go-redis/v9"
)

const (
	fixRid1 = "110e8400-e29b-41d4-a716-446655440001"
	fixRid2 = "110e8400-e29b-41d4-a716-446655440002"
	fixRid3 = "110e8400-e29b-41d4-a716-446655440003"
	fixRid4 = "110e8400-e29b-41d4-a716-446655440004"
	fixRid5 = "110e8400-e29b-41d4-a716-446655440005"
	fixRid6 = "110e8400-e29b-41d4-a716-446655440006"
)

func newFixStore(t *testing.T, mr *miniredis.Miniredis, ns string) *state.Store {
	t.Helper()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	store, err := state.New(client, state.Config{
		Namespace: ns, DefaultMode: event.ModeEnforce,
		Apps:       map[string]policy.Config{"sample_app": policy.DefaultConfig()},
		AuthSource: "login-app",
	})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func admit(t *testing.T, store *state.Store, rid string, ip netip.Addr) event.Decision {
	t.Helper()
	d, err := store.Check(context.Background(), event.Request{
		Application: "sample_app", ClientIP: ip, RequestID: rid, SchemaVersion: event.SchemaVersion,
	})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func denyEvent(rid string, ip netip.Addr, d event.Decision) event.Event {
	return event.Event{
		Request: event.Request{Application: "sample_app", ClientIP: ip, RequestID: rid, SchemaVersion: event.SchemaVersion},
		ID:      event.EventID("sample_app", rid, event.KindWafVerdict),
		Kind:    event.KindWafVerdict, Phase: event.PhaseRequest,
		Admission:  d.Admission,
		RequestWAF: event.Verdict{Action: "deny", Source: "enforced"},
	}
}

// Finding 3: every script must recover from SCRIPT FLUSH via Script.Run's EVAL
// fallback, without restarting wafguard and without changing request semantics.
func TestScriptCacheFlushRecoveryAllFour(t *testing.T) {
	mr := miniredis.RunT(t)
	store := newFixStore(t, mr, "fix3")
	ctx := context.Background()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer client.Close()
	ip := netip.MustParseAddr("198.51.100.10")

	d := admit(t, store, fixRid1, ip)
	if err := store.Observe(ctx, denyEvent(fixRid1, ip, d)); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAuth(ctx, policy.AuthReceipt{
		Application: "sample_app", RequestID: fixRid1, Outcome: policy.AuthFailure,
		SourceID: "login-app", ClientIP: ip,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Enrich(ctx, enrich.Match{Application: "sample_app", RequestID: fixRid1, RuleID: 7, Severity: 2, PhaseID: 1}); err != nil {
		t.Fatal(err)
	}
	if err := client.Do(ctx, "script", "flush", "sync").Err(); err != nil {
		t.Fatal(err)
	}

	// After the flush the same operations must still work through EVAL fallback.
	d2 := admit(t, store, fixRid2, ip)
	if d2.Admission == nil {
		t.Fatal("check lost admission after script flush")
	}
	if err := store.Observe(ctx, denyEvent(fixRid2, ip, d2)); err != nil {
		t.Fatalf("observe after flush: %v", err)
	}
	if err := store.RecordAuth(ctx, policy.AuthReceipt{
		Application: "sample_app", RequestID: fixRid2, Outcome: policy.AuthFailure,
		SourceID: "login-app", ClientIP: ip,
	}); err != nil {
		t.Fatalf("record auth after flush: %v", err)
	}
	if err := store.Enrich(ctx, enrich.Match{Application: "sample_app", RequestID: fixRid2, RuleID: 9, Severity: 2, PhaseID: 1}); err != nil {
		t.Fatalf("enrich after flush: %v", err)
	}
	// Semantics are preserved: enrichment was actually stored.
	if ok, err := store.HasEnrichment(ctx, "sample_app", fixRid2); err != nil || !ok {
		t.Fatalf("enrichment after flush ok=%v err=%v", ok, err)
	}
}

// Finding 4: dedupe TTL is in milliseconds, asserted with a real PTTL.
func TestDedupePTTLMilliseconds(t *testing.T) {
	mr := miniredis.RunT(t)
	store := newFixStore(t, mr, "fix4")
	ip := netip.MustParseAddr("198.51.100.11")
	d := admit(t, store, fixRid1, ip)
	if err := store.Observe(context.Background(), denyEvent(fixRid1, ip, d)); err != nil {
		t.Fatal(err)
	}
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer client.Close()
	key := "fix4:dedupe:" + event.EventID("sample_app", fixRid1, event.KindWafVerdict)
	pttl, err := client.PTTL(context.Background(), key).Result()
	if err != nil {
		t.Fatal(err)
	}
	if pttl <= 0 || pttl > 120*time.Second {
		t.Fatalf("dedupe PTTL %v want within 0..120s", pttl)
	}
	mr.FastForward(121 * time.Second)
	if mr.Exists(key) {
		t.Fatal("dedupe key must expire after max_event_age")
	}
}

// Finding 9: idle meta/contrib/brute/admission keys are bounded; a stale
// admission cannot be replayed once its binding expires.
func TestIdleKeysBoundedAndStaleAdmissionFenced(t *testing.T) {
	mr := miniredis.RunT(t)
	store := newFixStore(t, mr, "fix9")
	ctx := context.Background()
	ip := netip.MustParseAddr("198.51.100.12")
	d := admit(t, store, fixRid1, ip)
	if err := store.Observe(ctx, denyEvent(fixRid1, ip, d)); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAuth(ctx, policy.AuthReceipt{
		Application: "sample_app", RequestID: fixRid1, Outcome: policy.AuthFailure,
		SourceID: "login-app", ClientIP: ip,
	}); err != nil {
		t.Fatal(err)
	}
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer client.Close()
	for _, suffix := range []string{
		"meta:sample_app:" + ip.String(), "contrib:sample_app:" + ip.String(),
		"brute:sample_app:" + ip.String(), "admission:sample_app:" + fixRid1,
	} {
		ttl, err := client.PTTL(ctx, "fix9:"+suffix).Result()
		if err != nil || ttl <= 0 || ttl > 300*time.Second {
			t.Fatalf("%s PTTL=%v err=%v want bounded", suffix, ttl, err)
		}
	}
	// Expire the admission token: replay of the old admission must be fenced.
	mr.FastForward(121 * time.Second)
	if err := store.Observe(ctx, denyEvent(fixRid2, ip, d)); err != nil {
		t.Fatal(err)
	}
	ban := mrGet(t, mr, "fix9:ban:sample_app:"+ip.String())
	if ban != "" {
		t.Fatalf("stale admission after token expiry must not ban (ban=%q)", ban)
	}
}

// Findings 10 & 11: policy config converges to a second replica and revision
// comparison plus writes are atomic (exactly one of two racers succeeds).
func TestPolicyConvergenceAndAtomicCAS(t *testing.T) {
	mr := miniredis.RunT(t)
	storeA := newFixStore(t, mr, "fix10")
	storeB := newFixStore(t, mr, "fix10")
	ctx := context.Background()
	ip := netip.MustParseAddr("198.51.100.13")
	cfg := policy.DefaultConfig()
	cfg.WAFDenyThreshold = 2

	if _, err := storeA.SetPolicy(ctx, "sample_app", 0, cfg, event.ModeEnforce); err != nil {
		t.Fatal(err)
	}
	revB, err := storeB.PolicyRevision(ctx, "sample_app")
	if err != nil || revB != 1 {
		t.Fatalf("replica B revision %d err %v want 1", revB, err)
	}
	// Replica B observes with config published by A: second deny bans.
	for i, rid := range []string{fixRid1, fixRid2} {
		d := admit(t, storeB, rid, ip)
		if err := storeB.Observe(ctx, denyEvent(rid, ip, d)); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			if mrGet(t, mr, "fix10:ban:sample_app:"+ip.String()) != "" {
				t.Fatal("threshold 2 must not ban on first denial")
			}
		}
	}
	if mrGet(t, mr, "fix10:ban:sample_app:"+ip.String()) == "" {
		t.Fatal("replica B must enforce converged threshold 2")
	}

	var ok, conflict int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := storeA.SetPolicy(ctx, "sample_app", revB, cfg, event.ModeObserve)
			if err == nil {
				atomic.AddInt32(&ok, 1)
			} else if strings.Contains(err.Error(), "stale revision") {
				atomic.AddInt32(&conflict, 1)
			}
		}()
	}
	wg.Wait()
	if ok != 1 || conflict != 7 {
		t.Fatalf("CAS winners=%d conflicts=%d want 1/7", ok, conflict)
	}
	// No stale in-flight event may pass the new revision.
	_, _ = storeA.Unban(ctx, state.UnbanRequest{Application: "sample_app", ClientIP: ip, OperationID: "op-fix10"})
	old := admit(t, storeA, fixRid3, ip)
	_, _ = storeA.SetPolicy(ctx, "sample_app", revB+1, cfg, event.ModeEnforce)
	if err := storeA.Observe(ctx, denyEvent(fixRid3, ip, old)); err != nil {
		t.Fatal(err)
	}
	if mrGet(t, mr, "fix10:ban:sample_app:"+ip.String()) != "" {
		t.Fatal("event minted before policy update must be fenced")
	}
}

// Finding 12: unban is atomic and idempotent by operation id; a retry cannot
// clear a newer ban; an empty id gets an assigned id returned to the caller.
func TestUnbanIdempotentAndNewerBanProtected(t *testing.T) {
	mr := miniredis.RunT(t)
	store := newFixStore(t, mr, "fix12")
	ctx := context.Background()
	ip := netip.MustParseAddr("198.51.100.14")
	for _, rid := range []string{fixRid1, fixRid2, fixRid3} {
		d := admit(t, store, rid, ip)
		if err := store.Observe(ctx, denyEvent(rid, ip, d)); err != nil {
			t.Fatal(err)
		}
	}
	if mrGet(t, mr, "fix12:ban:sample_app:"+ip.String()) == "" {
		t.Fatal("setup ban missing")
	}
	first, err := store.Unban(ctx, state.UnbanRequest{Application: "sample_app", ClientIP: ip, OperationID: "op-fix-12"})
	if err != nil {
		t.Fatal(err)
	}
	if first.OperationID != "op-fix-12" || first.Generation == "" {
		t.Fatalf("unban result %+v", first)
	}
	// A new ban is created after the first unban, with fresh event ids so
	// the dedupe window from the first round does not suppress it.
	for _, rid := range []string{fixRid4, fixRid5, fixRid6} {
		d := admit(t, store, rid, ip)
		if err := store.Observe(ctx, denyEvent(rid, ip, d)); err != nil {
			t.Fatal(err)
		}
	}
	second, err := store.Unban(ctx, state.UnbanRequest{Application: "sample_app", ClientIP: ip, OperationID: "op-fix-12"})
	if err != nil {
		t.Fatal(err)
	}
	if second.Generation != first.Generation {
		t.Fatalf("retry changed generation %q -> %q", first.Generation, second.Generation)
	}
	if mrGet(t, mr, "fix12:ban:sample_app:"+ip.String()) == "" {
		t.Fatal("idempotent retry cleared a newer ban")
	}
	assigned, err := store.Unban(ctx, state.UnbanRequest{Application: "sample_app", ClientIP: ip})
	if err != nil || assigned.OperationID == "" {
		t.Fatalf("empty operation id: %+v err %v", assigned, err)
	}
	if _, err := store.Unban(ctx, state.UnbanRequest{Application: "sample_app", ClientIP: netip.MustParseAddr("198.51.100.99"), OperationID: "op-fix-12"}); err == nil {
		t.Fatal("reusing an operation id for a different target must conflict")
	}
}

// Finding 15: a partial operator config must not ban on the first failure.
func TestPartialOperatorPolicyNoFirstFailureBan(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer client.Close()
	store, err := state.New(client, state.Config{
		Namespace: "fix15", DefaultMode: event.ModeEnforce,
		Apps: map[string]policy.Config{"sample_app": {
			WAFDenyWindowSec: 30, WAFDenyThreshold: 3, WAFDenyBanSec: 900,
			MaxEventAgeSec: 120, AdmissionTTL: 120,
		}},
		AuthSource: "login-app",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ip := netip.MustParseAddr("198.51.100.15")
	d := admit(t, store, fixRid1, ip)
	if err := store.RecordAuth(ctx, policy.AuthReceipt{
		Application: "sample_app", RequestID: fixRid1, Outcome: policy.AuthFailure,
		SourceID: "login-app", ClientIP: ip,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Observe(ctx, denyEvent(fixRid1, ip, d)); err != nil {
		t.Fatal(err)
	}
	if mrGet(t, mr, "fix15:ban:sample_app:"+ip.String()) != "" {
		t.Fatal("one failure with unconfigured brute force must not ban")
	}
}

// Finding 16: auth correlation requires the real admission, in either arrival
// order, rejects mismatches/staleness, and never double-counts a request.
func TestAuthCorrelationAdmissionBound(t *testing.T) {
	mr := miniredis.RunT(t)
	store := newFixStore(t, mr, "fix16")
	ctx := context.Background()
	ip := netip.MustParseAddr("198.51.100.16")
	cfg := policy.DefaultConfig()
	cfg.BruteFailures = 2
	cfg.BruteWindowSec = 60
	if _, err := store.SetPolicy(ctx, "sample_app", 0, cfg, event.ModeEnforce); err != nil {
		t.Fatal(err)
	}

	// Unjoined auth (no admission) is rejected and writes nothing.
	if err := store.RecordAuth(ctx, policy.AuthReceipt{
		Application: "sample_app", RequestID: fixRid1, Outcome: policy.AuthFailure,
		SourceID: "login-app", ClientIP: ip,
	}); err == nil {
		t.Fatal("auth without admission must be rejected")
	}

	// Auth arrives before the verdict.
	d1 := admit(t, store, fixRid1, ip)
	if err := store.RecordAuth(ctx, policy.AuthReceipt{
		Application: "sample_app", RequestID: fixRid1, Outcome: policy.AuthFailure,
		SourceID: "login-app", ClientIP: netip.MustParseAddr("203.0.113.9"), /* ignored */
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Observe(ctx, denyEvent(fixRid1, ip, d1)); err != nil {
		t.Fatal(err)
	}
	authKey := "fix16:auth:sample_app:" + fixRid1
	if got := mr.HGet(authKey, "client_ip"); got != ip.String() {
		t.Fatalf("auth ip %q must come from admission %q", got, ip.String())
	}
	if got := mr.HGet(authKey, "generation"); got != d1.Admission.Generation {
		t.Fatalf("auth generation %q want %q", got, d1.Admission.Generation)
	}

	// Verdict arrives before auth, with a wrong source/IP rejected.
	d2 := admit(t, store, fixRid2, ip)
	if err := store.Observe(ctx, denyEvent(fixRid2, ip, d2)); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAuth(ctx, policy.AuthReceipt{
		Application: "sample_app", RequestID: fixRid2, Outcome: policy.AuthFailure,
		SourceID: "other-app", ClientIP: ip,
	}); err == nil {
		t.Fatal("untrusted source must be rejected")
	}
	if err := store.RecordAuth(ctx, policy.AuthReceipt{
		Application: "sample_app", RequestID: fixRid2, Outcome: policy.AuthFailure,
		SourceID: "login-app", ClientIP: ip,
	}); err != nil {
		t.Fatal(err)
	}
	if mr.HGet("fix16:auth:sample_app:"+fixRid2, "joined") != "1" {
		t.Fatal("verdict-then-auth must mark joined")
	}

	// Duplicate auth and duplicate observation never count twice.
	_ = store.RecordAuth(ctx, policy.AuthReceipt{
		Application: "sample_app", RequestID: fixRid2, Outcome: policy.AuthSuccess,
		SourceID: "login-app", ClientIP: ip,
	})
	response := denyEvent(fixRid2, ip, d2)
	response.ID = event.EventID("sample_app", fixRid2, event.KindObserveResponse)
	response.Kind = event.KindObserveResponse
	_ = store.Observe(ctx, response)
	if n := zcard(t, mr, "fix16:brute:sample_app:"+ip.String()); n != 2 {
		t.Fatalf("brute members %d want 2 (one per real request)", n)
	}
	if mrGet(t, mr, "fix16:ban:sample_app:"+ip.String()) == "" {
		t.Fatal("two distinct failed auths must ban at threshold 2")
	}
}

// Finding 14: response observation records status without reusing the request
// verdict to double-count the same WAF denial.
func TestResponseObservationNoDoubleCount(t *testing.T) {
	mr := miniredis.RunT(t)
	store := newFixStore(t, mr, "fix14")
	ctx := context.Background()
	ip := netip.MustParseAddr("198.51.100.17")
	d := admit(t, store, fixRid1, ip)
	status := 502
	ev := denyEvent(fixRid1, ip, d)
	ev.ID = event.EventID("sample_app", fixRid1, event.KindObserveResponse)
	ev.Kind = event.KindObserveResponse
	ev.OriginStatus = &status
	if err := store.Observe(ctx, ev); err != nil {
		t.Fatal(err)
	}
	metaKey := "fix14:meta:sample_app:" + ip.String()
	if mr.HGet(metaKey, "origin_status") != "502" || mr.HGet(metaKey, "response_seen") != "1" {
		t.Fatalf("response status not consumed: %v", hgetall(t, mr, metaKey))
	}
	if n := zcard(t, mr, "fix14:contrib:sample_app:"+ip.String()); n != 0 {
		t.Fatalf("response observation must not re-count WAF denial, got %d", n)
	}
}

func mrGet(t *testing.T, mr *miniredis.Miniredis, key string) string {
	t.Helper()
	v, err := mr.Get(key)
	if err != nil {
		return ""
	}
	return v
}

func zcard(t *testing.T, mr *miniredis.Miniredis, key string) int64 {
	t.Helper()
	c := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer c.Close()
	n, err := c.ZCard(context.Background(), key).Result()
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func hgetall(t *testing.T, mr *miniredis.Miniredis, key string) map[string]string {
	t.Helper()
	c := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer c.Close()
	m, err := c.HGetAll(context.Background(), key).Result()
	if err != nil {
		t.Fatal(err)
	}
	return m
}
