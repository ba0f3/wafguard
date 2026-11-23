package spoa

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ba0f3/haproxy-waf-spoe/internal/event"
	"github.com/dropmorepackets/haproxy-go/pkg/encoding"
)

func FuzzDecodeSPOE(f *testing.F) {
	fields := []struct{ name, seed string }{
		{"path", "/api/items?query=fixture"},
		{"client_ip", "::ffff:192.0.2.8"},
		{"peer_ip", "2001:db8::1%eth0"},
		{"origin_status", "200"},
		{"final_client_status", "599"},
		{"request_waf_rule_ids", "1,2"},
		{"response_waf_rule_ids", "3,4"},
		{"app", "sample_app"},
		{"request_id", "550e8400-e29b-41d4-a716-446655440000"},
		{"schema_version", "1"},
		{"admission_at_ms", "1700000000000"},
		{"policy_revision", "1"},
		{"method", "GET"},
	}
	for i, field := range fields {
		f.Add(uint8(i), field.seed)
	}
	f.Add(uint8(0), "/api/\x00items")
	f.Add(uint8(0), strings.Repeat("p", 1025))
	f.Add(uint8(5), strings.Repeat("1,", 64)+"2")

	limits := event.Limits{
		AllowedApps:    map[string]struct{}{"sample_app": {}},
		MaxPathLen:     1024,
		MaxRuleIDs:     64,
		MaxCategoryLen: 64,
	}
	f.Fuzz(func(t *testing.T, field uint8, value string) {
		if len(value) > 4096 {
			t.Skip()
		}
		args := map[string]string{
			"schema_version": "1",
			"request_id":     "550e8400-e29b-41d4-a716-446655440000",
			"app":            "sample_app",
			"method":         "GET",
			"path":           "/api/items",
			"client_ip":      "192.0.2.8",
		}
		key := fields[int(field)%len(fields)].name
		args[key] = value
		var extra []func(*encoding.KVWriter) error
		peerIP := netip.MustParseAddr("32.0.2.32")
		if key != "peer_ip" {
			extra = append(extra, func(w *encoding.KVWriter) error { return w.SetAddr("peer_ip", peerIP) })
		}
		name := string(event.KindObserveResponse)
		msg := mustMessage(t, name, args, extra...)
		defer encoding.ReleaseMessage(msg)
		decoded, reason, err := decodeMessage(name, msg, limits)
		if err != nil {
			if reason == "" {
				t.Fatal("rejected event has no drop reason")
			}
			return
		}
		if decoded.Request.Application != "sample_app" || decoded.Phase != event.PhaseResponse {
			t.Fatal("accepted event escaped its application or phase")
		}
		path := decoded.Request.Path
		if strings.ContainsRune(path, '?') || len(path) > limits.MaxPathLen || strings.ContainsAny(path, "\x00\r\n") {
			t.Fatal("accepted path contains a query or invalid bytes, or exceeds the limit")
		}
		for _, field := range []struct {
			name string
			ip   netip.Addr
		}{{"client_ip", decoded.Request.ClientIP}, {"peer_ip", decoded.Request.PeerIP}} {
			if _, exists := args[field.name]; !exists {
				if field.ip != peerIP {
					t.Fatal("accepted native IP differs from input")
				}
				continue
			}
			expected, parseErr := netip.ParseAddr(strings.TrimSpace(args[field.name]))
			if parseErr != nil || expected.Zone() != "" || field.ip != expected.Unmap() {
				t.Fatal("accepted text IP is invalid or differs from input")
			}
		}
	})
}

type operationRecorder struct {
	noopTelemetry
	operation string
}

func (r *operationRecorder) RecordOperation(operation, _ string, _ time.Duration) {
	r.operation = operation
}

func FuzzSPOEOperationLabel(f *testing.F) {
	f.Add("unknown-fixture")
	f.Add(string(event.KindCheckBan))
	f.Add(string(event.KindWafVerdict))
	f.Add(string(event.KindObserveResponse))
	f.Fuzz(func(t *testing.T, name string) {
		if len(name) > 256 {
			t.Skip()
		}
		msg := mustMessage(t, name, nil)
		defer encoding.ReleaseMessage(msg)
		// The absent request ID must keep the handler from reaching the backend.
		h := NewHandler(nil, event.Limits{})
		rec := &operationRecorder{}
		h.Telemetry = rec
		h.HandleSPOE(context.Background(), &encoding.ActionWriter{}, msg)
		want := "unknown"
		if _, known := event.PhaseForKind(event.Kind(name)); known {
			want = name
		}
		if rec.operation != want {
			t.Fatalf("operation label = %q, want %q", rec.operation, want)
		}
	})
}
