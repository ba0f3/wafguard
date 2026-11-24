package spoa

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ba0f3/haproxy-waf-spoe/internal/event"
	"github.com/ba0f3/haproxy-waf-spoe/internal/logging"
	"github.com/dropmorepackets/haproxy-go/pkg/encoding"
)

func enableDebugLogs(t *testing.T) {
	t.Helper()
	logging.SetLevel(logging.LevelDebug)
	t.Cleanup(func() { logging.SetLevel(logging.LevelInfo) })
}

func TestHandleSPOELogsRequest(t *testing.T) {
	enableDebugLogs(t)
	h := NewHandler(&fakeBackend{}, event.Limits{AllowedApps: map[string]struct{}{"sample_app": {}}})
	m := mustMessage(t, "check-ban", map[string]string{
		"schema_version": "1",
		"request_id":     "550e8400-e29b-41d4-a716-446655440000",
		"app":            "sample_app",
		"client_ip":      "192.0.2.8",
		"peer_ip":        "192.0.2.1",
		"path":           "/ok",
	})
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	h.HandleSPOE(context.Background(), &encoding.ActionWriter{}, m)
	out := buf.String()
	for _, want := range []string{"spoe", "check-ban", "result=ok", "request_id=550e8400-e29b-41d4-a716-446655440000", "client_ip=192.0.2.8", "app=sample_app", "action=allow"} {
		if !strings.Contains(out, want) {
			t.Errorf("request log missing %q; got %q", want, out)
		}
	}
}

type fakeBackend struct {
	mu           sync.Mutex
	checkCalls   int
	observeCalls int
	checkAction  event.Action
	checkSlow    time.Duration
	observeErr   error
}

func (f *fakeBackend) Check(ctx context.Context, req event.Request) (event.Decision, error) {
	f.mu.Lock()
	f.checkCalls++
	f.mu.Unlock()
	if f.checkSlow > 0 {
		select {
		case <-time.After(f.checkSlow):
		case <-ctx.Done():
			return event.UnknownDecision(true), ctx.Err()
		}
	}
	action := f.checkAction
	if action == "" {
		action = event.ActionAllow
	}
	return event.Decision{
		Action: action,
		Admission: &event.Admission{
			Generation: "gen1",
			At:         time.Now(),
			Mode:       event.ModeObserve,
		},
	}, nil
}

func (f *fakeBackend) Observe(ctx context.Context, ev event.Event) error {
	f.mu.Lock()
	f.observeCalls++
	f.mu.Unlock()
	return f.observeErr
}

func TestHandleSPOELogsObserveErrorDetail(t *testing.T) {
	enableDebugLogs(t)
	h := NewHandler(&fakeBackend{observeErr: errors.New("policy config missing for revision 3")}, event.Limits{
		AllowedApps:    map[string]struct{}{"sample_app": {}},
		MaxPathLen:     1024,
		MaxRuleIDs:     64,
		MaxCategoryLen: 64,
	})
	m := mustMessage(t, "waf-verdict", map[string]string{
		"schema_version":       "1",
		"request_id":           "550e8400-e29b-41d4-a716-446655440000",
		"app":                  "sample_app",
		"method":               "GET",
		"client_ip":            "192.0.2.8",
		"admission_generation": "g1",
		"admission_at_ms":      "1700000000000",
		"behavior_mode":        "enforce",
		"path":                 "/ok",
	}, func(w *encoding.KVWriter) error { return w.SetAddr("peer_ip", netip.MustParseAddr("32.0.2.32")) })
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	h.HandleSPOE(context.Background(), &encoding.ActionWriter{}, m)
	out := buf.String()
	for _, want := range []string{"result=observe_error", "reason=policy config missing for revision 3"} {
		if !strings.Contains(out, want) {
			t.Errorf("observe error log missing %q; got %q", want, out)
		}
	}
}

func TestWriteAdmissionACKSetsInspectionVars(t *testing.T) {
	w := encoding.NewActionWriter(nil, 0)
	err := writeAdmissionACK(w, event.Decision{
		Action:          event.ActionAllow,
		ReqInspect:      true,
		ResInspect:      true,
		ObserveResponse: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	out := string(w.Bytes())
	for _, want := range []string{"req_insp", "res_insp", "observe_response"} {
		if !strings.Contains(out, want) {
			t.Errorf("ACK missing var %q; got %q", want, out)
		}
	}
}

func TestHandleSPOELogsFailureAtInfo(t *testing.T) {
	logging.SetLevel(logging.LevelInfo)
	t.Cleanup(func() { logging.SetLevel(logging.LevelInfo) })
	h := NewHandler(&fakeBackend{}, event.Limits{AllowedApps: map[string]struct{}{"sample_app": {}}}).WithMaxInflight(1)
	h.sem <- struct{}{}
	m := mustMessage(t, "check-ban", map[string]string{
		"schema_version": "1",
		"request_id":     "550e8400-e29b-41d4-a716-446655440099",
		"app":            "sample_app",
		"client_ip":      "192.0.2.8",
		"peer_ip":        "192.0.2.1",
		"path":           "/ok",
	})
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	h.HandleSPOE(context.Background(), &encoding.ActionWriter{}, m)
	if out := buf.String(); !strings.Contains(out, "result=overload") {
		t.Fatalf("non-ok SPOE result must be logged at info; got %q", out)
	}
}

func TestMissingAdmission(t *testing.T) {
	backend := &fakeBackend{}
	limits := event.Limits{
		AllowedApps:    map[string]struct{}{"sample_app": {}},
		MaxPathLen:     1024,
		MaxRuleIDs:     64,
		MaxCategoryLen: 64,
	}
	h := NewHandler(backend, limits)
	w := &encoding.ActionWriter{}
	m := mustMessage(t, "waf-verdict", map[string]string{
		"schema_version": "1",
		"request_id":     "550e8400-e29b-41d4-a716-446655440000",
		"app":            "sample_app",
		"client_ip":      "192.0.2.8",
		"peer_ip":        "192.0.2.1",
		"path":           "/ok",
	})
	h.HandleSPOE(context.Background(), w, m)
	backend.mu.Lock()
	calls := backend.observeCalls
	backend.mu.Unlock()
	if calls != 0 {
		t.Fatalf("observeCalls = %d, want 0", calls)
	}
}

func TestOverload(t *testing.T) {
	backend := &fakeBackend{}
	limits := event.Limits{AllowedApps: map[string]struct{}{"sample_app": {}}}
	h := NewHandler(backend, limits).WithMaxInflight(2)
	h.sem <- struct{}{}
	h.sem <- struct{}{}
	w := &encoding.ActionWriter{}
	m := mustMessage(t, "check-ban", map[string]string{
		"schema_version": "1",
		"request_id":     "550e8400-e29b-41d4-a716-446655440001",
		"app":            "sample_app",
		"client_ip":      "192.0.2.8",
		"peer_ip":        "192.0.2.1",
		"path":           "/ok",
	})
	h.HandleSPOE(context.Background(), w, m)
}

func TestSlowResponseAdmission(t *testing.T) {
	backend := &fakeBackend{checkSlow: 200 * time.Millisecond}
	limits := event.Limits{AllowedApps: map[string]struct{}{"sample_app": {}}}
	h := NewHandler(backend, limits)
	h.Timeout = 50 * time.Millisecond
	w := &encoding.ActionWriter{}
	m := mustMessage(t, "check-ban", map[string]string{
		"schema_version": "1",
		"request_id":     "550e8400-e29b-41d4-a716-446655440002",
		"app":            "sample_app",
		"client_ip":      "192.0.2.8",
		"peer_ip":        "192.0.2.1",
		"path":           "/ok",
	})
	h.HandleSPOE(context.Background(), w, m)
}

func TestWireV1Decode(t *testing.T) {
	limits := event.Limits{
		AllowedApps:    map[string]struct{}{"sample_app": {}},
		MaxPathLen:     1024,
		MaxRuleIDs:     64,
		MaxCategoryLen: 64,
	}
	m := mustMessage(t, "waf-verdict", map[string]string{
		"schema_version":       "1",
		"node_id":              "n1",
		"request_id":           "550e8400-e29b-41d4-a716-446655440000",
		"app":                  "sample_app",
		"backend":              "origin",
		"method":               "GET",
		"client_ip":            "192.0.2.8",
		"admission_generation": "g1",
		"admission_at_ms":      "1700000000000",
		"behavior_mode":        "observe",
		"path":                 "/ok",
	}, func(w *encoding.KVWriter) error { return w.SetAddr("peer_ip", netip.MustParseAddr("32.0.2.32")) })
	defer encoding.ReleaseMessage(m)
	ev, _, err := decodeMessage("waf-verdict", m, limits)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Request.ClientIP.String() != "192.0.2.8" {
		t.Fatal(ev.Request.ClientIP)
	}
	if ev.Request.PeerIP.String() != "32.0.2.32" {
		t.Fatal(ev.Request.PeerIP)
	}
}
