package spoa

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ba0f3/haproxy-waf-spoe/internal/event"
	"github.com/dropmorepackets/haproxy-go/pkg/encoding"
)

type fakeBackend struct {
	mu           sync.Mutex
	observeCalls int
	checkAction  event.Action
	checkSlow    time.Duration
}

func (f *fakeBackend) Check(ctx context.Context, req event.Request) (event.Decision, error) {
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
	return nil
}

func TestMissingAdmission(t *testing.T) {
	backend := &fakeBackend{}
	limits := event.Limits{
		AllowedApps: map[string]struct{}{"sample_app": {}},
		MaxPathLen:  1024,
		MaxRuleIDs:  64,
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
		AllowedApps: map[string]struct{}{"sample_app": {}},
		MaxPathLen:  1024,
		MaxRuleIDs:  64,
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
		"peer_ip":              "192.0.2.1",
		"admission_generation": "g1",
		"admission_at_ms":      "1700000000000",
		"behavior_mode":        "observe",
		"path":                 "/ok",
	})
	ev, _, err := decodeMessage("waf-verdict", m, limits)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Request.ClientIP.String() != "192.0.2.8" {
		t.Fatal(ev.Request.ClientIP)
	}
}

