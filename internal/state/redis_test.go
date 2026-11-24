package state_test

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net/netip"
	"strings"
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
	rid := "550e8400-e29b-41d4-a716-446655440088"
	d1, _ := store.Check(ctx, event.Request{Application: "sample_app", ClientIP: ip, RequestID: rid})
	if _, err := store.Unban(ctx, state.UnbanRequest{Application: "sample_app", ClientIP: ip, OperationID: "op-lost"}); err != nil {
		t.Fatal(err)
	}
	d2, _ := store.Check(ctx, event.Request{Application: "sample_app", ClientIP: ip})
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

func TestObserveLogsBanReason(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	store, err := state.New(client, state.Config{
		Namespace:   "banlog",
		DefaultMode: event.ModeEnforce,
		Apps:        map[string]policy.Config{"sample_app": {WAFDenyWindowSec: 30, WAFDenyThreshold: 1, WAFDenyBanSec: 900}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	rid := "550e8400-e29b-41d4-a716-446655440099"
	req := event.Request{Application: "sample_app", ClientIP: netip.MustParseAddr("192.0.2.9"), RequestID: rid}
	admission, err := store.Check(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	ev := event.Event{
		Request:    req,
		ID:         event.EventID("sample_app", rid, event.KindWafVerdict),
		Kind:       event.KindWafVerdict,
		Phase:      event.PhaseRequest,
		Admission:  admission.Admission,
		RequestWAF: event.Verdict{Action: "deny", Source: "enforced"},
	}
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	if err := store.Observe(ctx, ev); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"ban issued", "request_id=" + rid, "client_ip=192.0.2.9", "reason=waf_deny"} {
		if !strings.Contains(out, want) {
			t.Errorf("ban log missing %q; got %q", want, out)
		}
	}
}

func TestObserveLogsShadowBanCandidate(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	store, err := state.New(client, state.Config{
		Namespace:   "shadowlog",
		DefaultMode: event.ModeObserve,
		Apps:        map[string]policy.Config{"sample_app": {WAFDenyWindowSec: 30, WAFDenyThreshold: 1, WAFDenyBanSec: 900}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	rid := "550e8400-e29b-41d4-a716-446655440098"
	req := event.Request{Application: "sample_app", ClientIP: netip.MustParseAddr("192.0.2.7"), RequestID: rid}
	admission, err := store.Check(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	ev := event.Event{
		Request:    req,
		ID:         event.EventID("sample_app", rid, event.KindWafVerdict),
		Kind:       event.KindWafVerdict,
		Phase:      event.PhaseRequest,
		Admission:  admission.Admission,
		RequestWAF: event.Verdict{Action: "deny", Source: "enforced"},
	}
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	if err := store.Observe(ctx, ev); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"ban would fire", "request_id=" + rid, "client_ip=192.0.2.7", "reason=waf_deny", "threshold=1"} {
		if !strings.Contains(out, want) {
			t.Errorf("shadow log missing %q; got %q", want, out)
		}
	}
}

func TestCheckSetsInspectionFlagsFromConfig(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	store, err := state.New(client, state.Config{
		Namespace:   "pathflags",
		DefaultMode: event.ModeEnforce,
		Apps: map[string]policy.Config{"sample_app": {
			ReqInspectPaths:      []string{"/upload"},
			ResInspectPaths:      []string{"/api/"},
			ObserveResponsePaths: []string{"/"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	d, err := store.Check(context.Background(), event.Request{
		Application: "sample_app",
		ClientIP:    netip.MustParseAddr("192.0.2.40"),
		RequestID:   "550e8400-e29b-41d4-a716-446655440080",
		Path:        "/api/v1/items",
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.ReqInspect {
		t.Fatal("/api/v1/items must not match req_inspect_paths")
	}
	if !d.ResInspect {
		t.Fatal("/api/v1/items must match res_inspect_paths")
	}
	if !d.ObserveResponse {
		t.Fatal("observe_response_paths=/ must match every path")
	}
}

func TestObserveLogsBackendStatusSignals(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	store, err := state.New(client, state.Config{
		Namespace:   "statuslog",
		DefaultMode: event.ModeEnforce,
		Apps: map[string]policy.Config{"sample_app": {
			WAFDenyWindowSec: 30, WAFDenyThreshold: 3, WAFDenyBanSec: 900,
			BruteWindowSec: 60, BruteFailures: 2, ScannerWindowSec: 60, ScannerResponses: 2,
			MaxEventAgeSec: 120, AdmissionTTL: 120,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ip := netip.MustParseAddr("192.0.2.30")
	feed := func(rid string, status int) {
		t.Helper()
		r := event.Request{Application: "sample_app", ClientIP: ip, RequestID: rid}
		admission, err := store.Check(ctx, r)
		if err != nil {
			t.Fatal(err)
		}
		st := status
		ev := event.Event{
			Request:    r,
			ID:         event.EventID("sample_app", rid, event.KindWafVerdict),
			Kind:       event.KindWafVerdict,
			Phase:      event.PhaseRequest,
			Admission:  admission.Admission,
			RequestWAF: event.Verdict{Action: "allow"},
			OriginStatus: &st,
		}
		if err := store.Observe(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	feed("550e8400-e29b-41d4-a716-446655440071", 401)
	feed("550e8400-e29b-41d4-a716-446655440072", 404)
	feed("550e8400-e29b-41d4-a716-446655440073", 500)
	out := buf.String()
	for _, want := range []string{
		"counter +1", "reason=brute_401", "reason=scanner_404", "backend_5xx", "status=500",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("backend signal log missing %q; got %q", want, out)
		}
	}
	if strings.Contains(out, "ban issued") {
		t.Fatalf("500 (and below-threshold 401/404) must not ban; got %q", out)
	}
}

func TestSharedBan(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	ip := netip.MustParseAddr("192.0.2.8")
	req := event.Request{Application: "sample_app", ClientIP: ip}
	ids := []string{
		"550e8400-e29b-41d4-a716-446655440001",
		"550e8400-e29b-41d4-a716-446655440002",
		"550e8400-e29b-41d4-a716-446655440003",
	}
	for _, rid := range ids {
		r := req
		r.RequestID = rid
		admission, err := store.Check(ctx, r)
		if err != nil {
			t.Fatal(err)
		}
		ev := event.Event{
			Request:    r,
			ID:         event.EventID("sample_app", rid, event.KindWafVerdict),
			Kind:       event.KindWafVerdict,
			Phase:      event.PhaseRequest,
			Admission:  admission.Admission,
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

func TestAuthReceiptJoinBothOrders(t *testing.T) {
	store, mr := testStore(t)
	ctx := context.Background()

	rid := "550e8400-e29b-41d4-a716-446655440020"
	key := "test:auth:sample_app:" + rid
	admit1, _ := store.Check(ctx, event.Request{Application: "sample_app", RequestID: rid, ClientIP: netip.MustParseAddr("192.0.2.1")})
	if err := store.RecordAuth(ctx, policy.AuthReceipt{
		Application: "sample_app",
		RequestID:   rid,
		Outcome:     policy.AuthFailure,
		SourceID:    "login-app",
		ClientIP:    netip.MustParseAddr("192.0.2.1"),
	}); err != nil {
		t.Fatal(err)
	}
	ev := event.Event{
		Request:    event.Request{Application: "sample_app", RequestID: rid, ClientIP: netip.MustParseAddr("192.0.2.1")},
		ID:         event.EventID("sample_app", rid, event.KindWafVerdict),
		Kind:       event.KindWafVerdict,
		RequestWAF: event.Verdict{Action: "allow", Source: "enforced"},
	}
	ev.Admission = admit1.Admission
	if err := store.Observe(ctx, ev); err != nil {
		t.Fatal(err)
	}
	if o := mr.HGet(key, "outcome"); o != "failure" {
		t.Fatalf("auth before observe join outcome %q", o)
	}
	if j := mr.HGet(key, "joined"); j != "1" {
		t.Fatalf("auth before observe joined %q", j)
	}

	rid2 := "550e8400-e29b-41d4-a716-446655440021"
	key2 := "test:auth:sample_app:" + rid2
	ev2 := event.Event{
		Request:    event.Request{Application: "sample_app", RequestID: rid2, ClientIP: netip.MustParseAddr("192.0.2.2")},
		ID:         event.EventID("sample_app", rid2, event.KindWafVerdict),
		Kind:       event.KindWafVerdict,
		RequestWAF: event.Verdict{Action: "allow", Source: "enforced"},
	}
	d2, _ := store.Check(ctx, ev2.Request)
	ev2.Admission = d2.Admission
	if err := store.Observe(ctx, ev2); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAuth(ctx, policy.AuthReceipt{
		Application: "sample_app",
		RequestID:   rid2,
		Outcome:     policy.AuthSuccess,
		SourceID:    "login-app",
		ClientIP:    netip.MustParseAddr("192.0.2.2"),
	}); err != nil {
		t.Fatal(err)
	}
	if o := mr.HGet(key2, "outcome"); o != "success" {
		t.Fatalf("observe before auth join outcome %q", o)
	}
	if j := mr.HGet(key2, "joined"); j != "1" {
		t.Fatalf("observe before auth joined %q", j)
	}
}

func TestAuthReceiptDuplicateRejected(t *testing.T) {
	store, mr := testStore(t)
	ctx := context.Background()
	rid := "550e8400-e29b-41d4-a716-446655440012"
	key := "test:auth:sample_app:" + rid
	_, _ = store.Check(ctx, event.Request{Application: "sample_app", RequestID: rid, ClientIP: netip.MustParseAddr("192.0.2.3")})
	if err := store.RecordAuth(ctx, policy.AuthReceipt{
		Application: "sample_app", RequestID: rid, Outcome: policy.AuthFailure, SourceID: "login-app", ClientIP: netip.MustParseAddr("192.0.2.3"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAuth(ctx, policy.AuthReceipt{
		Application: "sample_app", RequestID: rid, Outcome: policy.AuthSuccess, SourceID: "login-app", ClientIP: netip.MustParseAddr("192.0.2.3"),
	}); err != nil {
		t.Fatal(err)
	}
	if o := mr.HGet(key, "outcome"); o != "failure" {
		t.Fatalf("duplicate must keep first outcome %q", o)
	}
}

func TestAuthReceiptStoredOnce(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	rid := "550e8400-e29b-41d4-a716-446655440010"
	rid2 := "550e8400-e29b-41d4-a716-446655440011"
	ip := netip.MustParseAddr("192.0.2.4")
	_, _ = store.Check(ctx, event.Request{Application: "sample_app", RequestID: rid, ClientIP: ip})
	_, _ = store.Check(ctx, event.Request{Application: "sample_app", RequestID: rid2, ClientIP: ip})
	for i := 0; i < 2; i++ {
		if err := store.RecordAuth(ctx, policy.AuthReceipt{
			Application: "sample_app", RequestID: rid, Outcome: policy.AuthFailure,
			SourceID: "login-app", ClientIP: ip,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.RecordAuth(ctx, policy.AuthReceipt{
		Application: "sample_app", RequestID: rid2, Outcome: policy.AuthSuccess,
		SourceID: "login-app", ClientIP: ip,
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
	for i := 0; i < 3; i++ {
		rid := fmt.Sprintf("650e8400-e29b-41d4-a716-44665544000%d", i+1)
		d, _ := store.Check(ctx, event.Request{Application: "sample_app", ClientIP: ip, RequestID: rid})
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
