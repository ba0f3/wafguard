package policy_test

import (
	"net/netip"
	"testing"

	"github.com/ba0f3/haproxy-waf-spoe/internal/event"
	"github.com/ba0f3/haproxy-waf-spoe/internal/policy"
)

func TestIPInList(t *testing.T) {
	entries := []string{"192.0.2.0/24", "2001:db8::1", "not-an-ip"}
	if !policy.IPInList(netip.MustParseAddr("192.0.2.5"), entries) {
		t.Fatal("IPv4 CIDR must match")
	}
	if policy.IPInList(netip.MustParseAddr("192.0.3.5"), entries) {
		t.Fatal("outside CIDR must not match")
	}
	if !policy.IPInList(netip.MustParseAddr("2001:db8::1"), entries) {
		t.Fatal("exact IPv6 must match")
	}
	if policy.IPInList(netip.MustParseAddr("2001:db8::2"), entries) {
		t.Fatal("other IPv6 must not match")
	}
	if policy.IPInList(netip.MustParseAddr("192.0.2.5"), nil) {
		t.Fatal("empty list must not match")
	}
}

func TestRepeatBanDefaults(t *testing.T) {
	cfg := policy.WithDefaults(policy.Config{})
	if cfg.RepeatBanThreshold != 2 {
		t.Fatalf("threshold = %d, want 2", cfg.RepeatBanThreshold)
	}
	if cfg.RepeatBanWindowSec != 604800 {
		t.Fatalf("window = %d, want 604800", cfg.RepeatBanWindowSec)
	}
	if cfg.RepeatBanTTLSec != 2592000 {
		t.Fatalf("ttl = %d, want 2592000", cfg.RepeatBanTTLSec)
	}
}

func TestPathMatchesPrefixes(t *testing.T) {
	if !policy.PathMatches("/api/v1/users", []string{"/api/"}) {
		t.Fatal("prefix match failed")
	}
	if policy.PathMatches("/other", []string{"/api/"}) {
		t.Fatal("unrelated path matched")
	}
	if policy.PathMatches("/api/v1", nil) {
		t.Fatal("empty prefix list must not match")
	}
	if !policy.PathMatches("/api", []string{"/api"}) {
		t.Fatal("exact prefix must match")
	}
}

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

func TestClassifyEnforcementRequiresSource(t *testing.T) {
	cfg := policy.DefaultConfig()
	ev := event.Event{
		RequestWAF: event.Verdict{Action: "deny", Source: ""},
	}
	e := policy.Classify(ev, cfg)
	if e.WAFDeny {
		t.Fatal("deny without enforced source must not count")
	}
}

func TestClassifyProbeAnd4xx(t *testing.T) {
	cfg := policy.DefaultConfig()
	ev := event.Event{
		Request:      event.Request{Path: "/.env"},
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

func TestWithDefaultsPartialOperatorConfig(t *testing.T) {
	cfg := policy.WithDefaults(policy.Config{
		WAFDenyWindowSec: 30,
		WAFDenyThreshold: 3,
		WAFDenyBanSec:    900,
		MaxEventAgeSec:   120,
		AdmissionTTL:     120,
	})
	if cfg.BruteFailures != policy.DefaultConfig().BruteFailures || cfg.BruteWindowSec != policy.DefaultConfig().BruteWindowSec {
		t.Fatalf("unconfigured brute force must get safe defaults: %+v", cfg)
	}
	if err := policy.Validate(cfg); err != nil {
		t.Fatalf("normalized config invalid: %v", err)
	}
	if err := policy.Validate(policy.Config{}); err == nil {
		t.Fatal("zero config must be rejected explicitly")
	}
}
