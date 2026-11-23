//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
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

func TestStockHTTPAuthOutcomes(t *testing.T) {
	requireAuthHTTP(t)
	rid := fmt.Sprintf("auth-http-%d", time.Now().UnixNano())
	body, _ := json.Marshal(map[string]string{
		"request_id": rid,
		"outcome":    "failure",
	})
	req, _ := http.NewRequest(http.MethodPost, authHTTPURL()+"/v1/apps/sample_app/auth-outcomes", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("auth POST %d want 204", resp.StatusCode)
	}

	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		addr = "127.0.0.1:6379"
	}
	client := redis.NewClient(&redis.Options{Addr: addr})
	defer client.Close()
	ctx := context.Background()
	key := "wg:auth:sample_app:" + rid
	out, err := client.HGet(ctx, key, "outcome").Result()
	if err != nil || out != "failure" {
		t.Fatalf("redis outcome %q err %v", out, err)
	}
	src, _ := client.HGet(ctx, key, "source").Result()
	if src != "login-app" {
		t.Fatalf("source %q want login-app", src)
	}
}
