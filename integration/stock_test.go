//go:build integration

package integration

import (
	"io"
	"net/http"
	"os"
	"strconv"
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

func originHitsURL() string {
	if u := os.Getenv("TESTORIGIN_HITS_URL"); u != "" {
		return u
	}
	return "http://127.0.0.1:8081/internal/hits"
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

func originHits(t *testing.T) uint64 {
	t.Helper()
	resp, err := http.Get(originHitsURL())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.ParseUint(string(b), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestStockLifecycle(t *testing.T) {
	requireCompose(t)
	before := originHits(t)

	resp, err := http.Get(haproxyURL() + "/ok")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("clean status %d", resp.StatusCode)
	}
	afterAllow := originHits(t)
	if afterAllow != before+1 {
		t.Fatalf("origin hits after allow: before=%d after=%d", before, afterAllow)
	}

	req, err := http.NewRequest(http.MethodGet, haproxyURL()+"/ok", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("User-Agent", "fixture-deny-request")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("deny status %d want 403", resp.StatusCode)
	}
	if h := resp.Header.Get("waf-block"); h != "request" {
		t.Fatalf("waf-block header %q", h)
	}

	resp, err = http.Get(haproxyURL() + "/marker-deny")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("path marker status %d", resp.StatusCode)
	}

	afterDeny := originHits(t)
	if afterDeny != afterAllow {
		t.Fatalf("origin hits increased on deny: allow=%d deny-phase=%d", afterAllow, afterDeny)
	}
}

func TestStockStreamIsolation(t *testing.T) {
	requireCompose(t)
	// HTTP/2 via TLS listener when HAPROXY_H2_URL is set.
	if os.Getenv("HAPROXY_H2_URL") == "" {
		t.Skip("set HAPROXY_H2_URL for HTTP/2 gate")
	}
	t.Skip("h2 client harness pending")
}

func TestStockBodyAndAffinity(t *testing.T) {
	requireCompose(t)
	t.Skip("body/affinity cases require recorder SPOA swap in compose overlay")
}
