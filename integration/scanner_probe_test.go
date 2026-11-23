//go:build integration

package integration

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func TestScannerProbeObserveIntegration(t *testing.T) {
	requireCompose(t)
	probes := []string{"/.env", "/wp-admin", "/.git/config"}
	for _, p := range probes {
		resp, err := http.Get(haproxyURL() + p)
		if err != nil {
			t.Fatal(p, err)
		}
		resp.Body.Close()
		if resp.StatusCode != 404 {
			t.Fatalf("%s status %d want 404", p, resp.StatusCode)
		}
	}
	ctx := context.Background()
	cli := redis.NewClient(&redis.Options{Addr: redisAddr()})
	deadline := time.Now().Add(15 * time.Second)
	var n int
	for time.Now().Before(deadline) {
		keys, err := cli.Keys(ctx, "wg:dedupe:sample_app*observe-response*").Result()
		if err == nil {
			n = len(keys)
			if n >= len(probes) {
				break
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	if n < len(probes) {
		t.Fatalf("observe-response dedupe keys %d want >= %d", n, len(probes))
	}
	// benign: clean path should not add scanner-only markers
	resp, err := http.Get(haproxyURL() + "/ok")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || strings.Contains(resp.Header.Get("waf-block"), "request") {
		t.Fatalf("clean /ok status %d", resp.StatusCode)
	}
}
