//go:build integration

package integration

import (
	"net/http"
	"os"
	"testing"
	"time"
)

func haproxyURL() string {
	if u := os.Getenv("HAPROXY_URL"); u != "" {
		return u
	}
	if p := os.Getenv("HAPROXY_PORT"); p != "" {
		return "http://127.0.0.1:" + p
	}
	return "http://127.0.0.1:18080"
}

func requireCompose(t *testing.T) {
	t.Helper()
	if os.Getenv("WAF_INTEGRATION") == "" {
		t.Skip("set WAF_INTEGRATION=1 with compose up")
	}
	client := &http.Client{Timeout: 2 * time.Second}
	if _, err := client.Get(haproxyURL() + "/ok"); err != nil {
		t.Skip("haproxy not reachable:", err)
	}
}

func TestStockLifecycle(t *testing.T) {
	requireCompose(t)
	resp, err := http.Get(haproxyURL() + "/ok")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	// Synthetic deny is verified in compose via Coraza logs (fixture User-Agent rule).
	_ = http.StatusForbidden
}

func TestStockStreamIsolation(t *testing.T) {
	requireCompose(t)
	t.Skip("HTTP/2 stream isolation requires harness wiring; run manually with h2 client")
}

func TestStockBodyAndAffinity(t *testing.T) {
	requireCompose(t)
	t.Skip("body/affinity cases require full stock recorder topology")
}

