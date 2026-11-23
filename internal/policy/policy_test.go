package policy_test

import (
	"testing"

	"github.com/ba0f3/haproxy-waf-spoe/internal/event"
	"github.com/ba0f3/haproxy-waf-spoe/internal/policy"
)

func TestClassify(t *testing.T) {
	cfg := policy.DefaultConfig()
	ev := event.Event{
		OwnRejection: true,
		RequestWAF:   event.Verdict{Action: "deny"},
	}
	e := policy.Classify(ev, cfg)
	if e.WAFDeny {
		t.Fatal("own rejection must not waf deny")
	}
	ev = event.Event{
		RequestWAF: event.Verdict{InspectionError: true, Action: "deny"},
	}
	e = policy.Classify(ev, cfg)
	if e.WAFDeny {
		t.Fatal("inspection error")
	}
	ev = event.Event{
		RequestWAF: event.Verdict{Source: "hypothetical", Action: "deny"},
	}
	e = policy.Classify(ev, cfg)
	if e.WAFDeny || !e.DetectionMatch {
		t.Fatalf("detection only: %+v", e)
	}
}

func TestClassifyProbeAnd4xx(t *testing.T) {
	cfg := policy.DefaultConfig()
	ev := event.Event{
		Request: event.Request{Path: "/.env"},
		OriginStatus: func() *int { v := 404; return &v }(),
		RequestWAF:   event.Verdict{Action: "allow", Source: "enforced"},
	}
	e := policy.Classify(ev, cfg)
	if !e.ProbePath || !e.Eligible4xx || !e.ResponseSeen {
		t.Fatalf("scanner evidence %+v", e)
	}
}

func TestRecordAuthReceiptShape(t *testing.T) {
	r := policy.AuthReceipt{
		Application: "sample_app",
		RequestID:   "550e8400-e29b-41d4-a716-446655440000",
		Outcome:     policy.AuthFailure,
	}
	if r.Outcome != policy.AuthFailure {
		t.Fatal(r.Outcome)
	}
}

func TestPolicyBoundaries(t *testing.T) {
	if err := policy.Validate(policy.Config{WAFDenyThreshold: 0, MaxEventAgeSec: 1, AdmissionTTL: 2}); err == nil {
		t.Fatal("expected validate error")
	}
}

