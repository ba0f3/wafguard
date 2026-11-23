package event_test

import (
	"net/netip"
	"testing"

	"github.com/ba0f3/haproxy-waf-spoe/internal/event"
)

func TestWireV1Validation(t *testing.T) {
	limits := event.Limits{
		AllowedApps: map[string]struct{}{"sample_app": {}},
		MaxPathLen:  1024,
		MaxRuleIDs:  64,
		MaxCategoryLen: 64,
	}
	ev := event.Event{
		Kind:  event.KindCheckBan,
		Phase: event.PhaseAdmission,
		Request: event.Request{
			SchemaVersion: 1,
			RequestID:     "550e8400-e29b-41d4-a716-446655440000",
			Application:   "sample_app",
			Path:          "/ok",
			ClientIP:      netip.MustParseAddr("192.0.2.8"),
		},
	}
	if _, ok := event.Validate(limits, ev); !ok {
		t.Fatal("expected valid")
	}
	ev.Request.SchemaVersion = 2
	if r, ok := event.Validate(limits, ev); ok || r != event.InvalidSchemaVersion {
		t.Fatalf("got ok=%v reason=%v", ok, r)
	}
}

func TestStripQueryPath(t *testing.T) {
	if event.StripQueryPath("/ok?secret=fixture") != "/ok" {
		t.Fatal("query not stripped")
	}
}

