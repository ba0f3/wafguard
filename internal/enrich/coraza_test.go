package enrich_test

import (
	"bytes"
	"testing"

	"github.com/ba0f3/haproxy-waf-spoe/internal/enrich"
)

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
