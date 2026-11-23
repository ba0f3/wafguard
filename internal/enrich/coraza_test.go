package enrich_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ba0f3/haproxy-waf-spoe/internal/enrich"
)

func TestEnrichmentRedaction(t *testing.T) {
	long := strings.Repeat("x", 200)
	line := []byte(`{"unique_id":"550e8400-e29b-41d4-a716-446655440001","ruleid":1001,"tags":["` + long + `"],"severity":5,"phase":1}`)
	m, err := enrich.Parse(bytes.NewReader(line), enrich.Source{Application: "sample_app"}, enrich.Limits{MaxTagLen: 16})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Tags[0]) > 16 {
		t.Fatalf("tag len %d", len(m.Tags[0]))
	}
}

func TestEnrichmentZerologStockMatch(t *testing.T) {
	line := []byte(`{"level":"error","match":{"unique_id":"550e8400-e29b-41d4-a716-446655440099","rule_id":1001,"tags":["marker-benign"],"severity_id":5,"phase_id":1}}`)
	m, err := enrich.Parse(bytes.NewReader(line), enrich.Source{Application: "sample_app"}, enrich.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if m.RequestID != "550e8400-e29b-41d4-a716-446655440099" || m.RuleID != 1001 {
		t.Fatalf("%+v", m)
	}
}

func TestEnrichmentJoin(t *testing.T) {
	line := []byte(`{"unique_id":"550e8400-e29b-41d4-a716-446655440000","ruleid":1001,"tags":["marker"],"severity":5,"phase":1}`)
	m, err := enrich.Parse(bytes.NewReader(line), enrich.Source{Application: "sample_app"}, enrich.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if m.RequestID == "" || m.RuleID != 1001 {
		t.Fatalf("%+v", m)
	}
}
