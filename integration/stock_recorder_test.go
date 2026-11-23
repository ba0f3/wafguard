//go:build integration

package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"
)

func recorderBase() string {
	if u := os.Getenv("RECORDER_URL"); u != "" {
		return u
	}
	return "http://127.0.0.1:18090"
}

func requireRecorder(t *testing.T) {
	t.Helper()
	if os.Getenv("WAF_RECORDER") == "" {
		t.Skip("set WAF_RECORDER=1 with compose.recorder.yaml")
	}
	requireCompose(t)
}

func TestStockRecorderCalls(t *testing.T) {
	requireRecorder(t)
	req, _ := http.NewRequest(http.MethodGet, haproxyURL()+"/ok", nil)
	req.Header.Set("User-Agent", "fixture-deny-request")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("status %d", resp.StatusCode)
	}

	lastResp, err := http.Get(recorderBase() + "/v1/last")
	if err != nil {
		t.Fatal(err)
	}
	defer lastResp.Body.Close()
	var last struct {
		RequestID string `json:"request_id"`
	}
	if err := json.NewDecoder(lastResp.Body).Decode(&last); err != nil || last.RequestID == "" {
		t.Fatal("no last request id")
	}
	recResp, err := http.Get(recorderBase() + "/v1/requests/" + last.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	defer recResp.Body.Close()
	body, _ := io.ReadAll(recResp.Body)
	var rec struct {
		Calls []string `json:"calls"`
	}
	if err := json.Unmarshal(body, &rec); err != nil {
		t.Fatal(err)
	}
	want := []string{"check-ban", "waf-verdict"}
	if len(rec.Calls) < len(want) {
		t.Fatalf("calls %v", rec.Calls)
	}
	for i, name := range want {
		if rec.Calls[i] != name {
			t.Fatalf("calls %v want %v", rec.Calls, want)
		}
	}
}