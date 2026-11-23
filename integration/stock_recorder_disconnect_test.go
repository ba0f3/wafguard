//go:build integration

package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"
)

func requireRecorderDisconnect(t *testing.T) {
	t.Helper()
	if os.Getenv("WAF_RECORDER_BODY") == "" {
		t.Skip("set WAF_RECORDER_BODY=1 with recorder-body matrix up")
	}
	requireCompose(t)
}

func TestStockRecorderDisconnectPrecheckCorazaStillDenies(t *testing.T) {
	requireRecorderDisconnect(t)
	before := originHits(t)
	resp, err := http.Get(haproxyURL() + "/fixture-disconnect-precheck")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("client %d want 403 from Coraza when recorder drops check-ban ack", resp.StatusCode)
	}
	if originHits(t) != before {
		t.Fatal("coraza deny must not reach origin")
	}
	last, _ := http.Get(recorderBase() + "/v1/last")
	var id struct {
		RequestID string `json:"request_id"`
	}
	_ = json.NewDecoder(last.Body).Decode(&id)
	last.Body.Close()
	rec, _ := http.Get(recorderBase() + "/v1/requests/" + id.RequestID)
	body, _ := io.ReadAll(rec.Body)
	rec.Body.Close()
	var e struct{ Calls []string `json:"calls"` }
	_ = json.Unmarshal(body, &e)
	for _, c := range e.Calls {
		if c == "check-ban" {
			t.Fatalf("calls %v must not include check-ban when recorder drops ack", e.Calls)
		}
	}
}

func TestStockRecorderDisconnectVerdictCorazaStillDenies(t *testing.T) {
	requireRecorderDisconnect(t)
	before := originHits(t)
	resp, err := http.Get(haproxyURL() + "/fixture-disconnect-verdict")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("client %d want 403 from Coraza snapshot when recorder drops waf-verdict ack", resp.StatusCode)
	}
	if originHits(t) != before {
		t.Fatal("coraza deny must not reach origin")
	}
}
