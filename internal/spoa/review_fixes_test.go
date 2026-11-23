package spoa

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ba0f3/haproxy-waf-spoe/internal/event"
	"github.com/dropmorepackets/haproxy-go/pkg/encoding"
)

// Finding 5: admission/check-ban must not depend on path length or parsing,
// including callers that send a raw (unstripped) long path.
func TestCheckBanIndependentOfPath(t *testing.T) {
	longPath := "/" + strings.Repeat("benign-segment/", 300)
	limits := event.Limits{MaxPathLen: 64, MaxRuleIDs: 64, MaxCategoryLen: 64,
		AllowedApps: map[string]struct{}{"sample_app": {}}}
	kvs := map[string]string{
		"schema_version": "1",
		"request_id":     "550e8400-e29b-41d4-a716-446655440001",
		"app":            "sample_app",
		"client_ip":      "192.0.2.8",
		"path":           longPath + "?query=benign",
	}
	if ev, reason, err := decodeMessage("check-ban", mustMessage(t, "check-ban", kvs), limits); err != nil {
		t.Fatalf("check-ban must accept long path: %s %v (%+v)", reason, err, ev)
	}
	if _, _, err := decodeMessage("waf-verdict", mustMessage(t, "waf-verdict", kvs), limits); err == nil {
		t.Fatal("other phases must still enforce path bounds")
	}
	backend := &fakeBackend{}
	h := NewHandler(backend, limits)
	h.HandleSPOE(context.Background(), &encoding.ActionWriter{}, mustMessage(t, "check-ban", kvs))
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.checkCalls != 1 {
		t.Fatalf("check-ban calls %d want 1", backend.checkCalls)
	}
}

// Finding 13: native typed SPOE integers/bools decode as well as strings.
func TestTypedSPOEFields(t *testing.T) {
	limits := event.Limits{MaxPathLen: 1024, MaxRuleIDs: 64, MaxCategoryLen: 64}
	m := mustMessage(t, "observe-response", map[string]string{
		"request_id": "550e8400-e29b-41d4-a716-446655440002",
		"app":        "sample_app",
		"client_ip":  "192.0.2.9",
		"path":       "/ok",
	},
		func(w *encoding.KVWriter) error { return w.SetInt32("schema_version", 1) },
		func(w *encoding.KVWriter) error { return w.SetString("admission_generation", "gen-typed") },
		func(w *encoding.KVWriter) error {
			return w.SetInt64("admission_at_ms", time.Unix(1_700_000_000, 0).UnixMilli())
		},
		func(w *encoding.KVWriter) error { return w.SetUInt64("policy_revision", 42) },
		func(w *encoding.KVWriter) error { return w.SetInt32("origin_status", 502) },
		func(w *encoding.KVWriter) error { return w.SetInt32("final_client_status", 200) },
		func(w *encoding.KVWriter) error { return w.SetBool("own_rejection", false) },
		func(w *encoding.KVWriter) error { return w.SetInt64("request_waf_rule_id", 123) },
		func(w *encoding.KVWriter) error { return w.SetBool("request_waf_inspection_error", true) },
	)
	ev, reason, err := decodeMessage("observe-response", m, limits)
	if err != nil {
		t.Fatalf("typed decode failed: %s %v", reason, err)
	}
	if ev.Request.SchemaVersion != event.SchemaVersion {
		t.Fatalf("schema %d", ev.Request.SchemaVersion)
	}
	if ev.Admission == nil || ev.Admission.Generation != "gen-typed" ||
		ev.Admission.Revision != 42 || ev.Admission.At.UnixMilli() != time.Unix(1_700_000_000, 0).UnixMilli() {
		t.Fatalf("typed admission %+v", ev.Admission)
	}
	if ev.OriginStatus == nil || *ev.OriginStatus != 502 ||
		ev.FinalClientStatus == nil || *ev.FinalClientStatus != 200 {
		t.Fatalf("typed statuses %v %v", ev.OriginStatus, ev.FinalClientStatus)
	}
	if ev.RequestWAF.RuleID == nil || *ev.RequestWAF.RuleID != 123 || !ev.RequestWAF.InspectionError {
		t.Fatalf("typed verdict %+v", ev.RequestWAF)
	}
}

// Finding 13: a delayed observation with no real admission token is dropped;
// the handler must not mint a replacement via Check.
func TestDelayedObservationRequiresRealAdmission(t *testing.T) {
	backend := &fakeBackend{}
	h := NewHandler(backend, event.Limits{MaxPathLen: 1024, MaxCategoryLen: 64})
	m := mustMessage(t, "waf-verdict", map[string]string{
		"schema_version":     "1",
		"request_id":         "550e8400-e29b-41d4-a716-446655440003",
		"app":                "sample_app",
		"client_ip":          "192.0.2.10",
		"path":               "/ok",
		"request_waf_action": "deny",
	})
	h.HandleSPOE(context.Background(), &encoding.ActionWriter{}, m)
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.checkCalls != 0 || backend.observeCalls != 0 {
		t.Fatalf("synthesized admission: checks=%d observes=%d", backend.checkCalls, backend.observeCalls)
	}
}
