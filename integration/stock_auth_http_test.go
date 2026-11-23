//go:build integration

package integration

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func authHTTPURL() string {
	if u := os.Getenv("WAF_AUTH_HTTP_URL"); u != "" {
		return u
	}
	return "http://127.0.0.1:19201"
}

func requireAuthHTTP(t *testing.T) {
	t.Helper()
	if os.Getenv("WAF_AUTH_HTTP") == "" {
		t.Skip("set WAF_AUTH_HTTP=1 with wafguard admin_http_auth exposed")
	}
	requireCompose(t)
}

func postAuth(t *testing.T, body string, token, proxyID string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, authHTTPURL()+"/v1/apps/sample_app/auth-outcomes", bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-Wafguard-Auth-Token", token)
	}
	if proxyID != "" {
		req.Header.Set("X-Wafguard-Request-Id", proxyID)
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func TestStockHTTPAuthOutcomes(t *testing.T) {
	requireAuthHTTP(t)
	token := os.Getenv("WAF_AUTH_TOKEN")
	if token == "" {
		token = "operator-lab-only"
	}

	// Mint a real admission with a benign request, then read the proxy id
	// that check-ban stored in Redis.
	resp, err := http.Get(haproxyURL() + "/ok")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		addr = "127.0.0.1:6379"
	}
	client := redis.NewClient(&redis.Options{Addr: addr})
	defer client.Close()
	ctx := context.Background()
	keys, err := client.Keys(ctx, "wg:admission:sample_app:*").Result()
	if err != nil || len(keys) == 0 {
		t.Fatalf("no admission tokens in Redis: keys=%v err=%v", keys, err)
	}
	rid := strings.TrimPrefix(keys[0], "wg:admission:sample_app:")
	if rid == keys[0] {
		t.Fatalf("unexpected admission key %q", keys[0])
	}

	// A client-forged body value must be replaced by the proxy id header.
	body := fmt.Sprintf(`{"request_id":"client-forged-value","outcome":"failure"}`)
	if code := postAuth(t, body, token, rid); code != http.StatusNoContent {
		t.Fatalf("auth POST %d want 204", code)
	}
	key := "wg:auth:sample_app:" + rid
	out, err := client.HGet(ctx, key, "outcome").Result()
	if err != nil || out != "failure" {
		t.Fatalf("redis outcome %q err %v", out, err)
	}
	src, _ := client.HGet(ctx, key, "source").Result()
	expectedSource := os.Getenv("WAF_AUTH_SOURCE")
	if expectedSource == "" {
		expectedSource = "login-app"
	}
	if src != expectedSource {
		t.Fatalf("source %q want %q", src, expectedSource)
	}
	storedRID, _ := client.HGet(ctx, key, "request_id").Result()
	if storedRID != rid {
		t.Fatalf("stored request id %q want proxy id %q", storedRID, rid)
	}
	if gen := client.HGet(ctx, key, "generation").Val(); gen == "" {
		t.Fatal("auth was not bound to an admission generation")
	}

	if code := postAuth(t, body, token, ""); code != http.StatusBadRequest {
		t.Fatalf("auth without proxy id %d want 400", code)
	}
	if code := postAuth(t, body, "", rid); code != http.StatusForbidden {
		t.Fatalf("auth without token %d want 403", code)
	}
}
