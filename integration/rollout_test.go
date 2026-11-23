//go:build integration

package integration

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func haproxyBURL() string {
	if u := os.Getenv("HAPROXY_B_URL"); u != "" {
		return u
	}
	return "http://127.0.0.1:18081"
}

func labClientIP(t *testing.T) string {
	t.Helper()
	if v := os.Getenv("LAB_CLIENT_IP"); v != "" {
		return v
	}
	out, err := exec.Command("docker", "network", "inspect", "integration_default", "-f", "{{(index .IPAM.Config 0).Gateway}}").Output()
	if err == nil {
		if ip := strings.TrimSpace(string(out)); ip != "" {
			return ip
		}
	}
	return "172.17.0.1"
}

func redisAddr() string {
	if a := os.Getenv("REDIS_ADDR"); a != "" {
		return a
	}
	return "127.0.0.1:6379"
}

func clearLabBan(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	c := redis.NewClient(&redis.Options{Addr: redisAddr()})
	ip := labClientIP(t)
	_ = c.Del(ctx, "wg:ban:sample_app:"+ip, "wg:contrib:sample_app:"+ip).Err()
}

func requireRollout(t *testing.T) {
	t.Helper()
	requireCompose(t)
	if os.Getenv("WAF_ROLLOUT") == "" {
		t.Skip("set WAF_ROLLOUT=1 with compose.rollout.yaml up")
	}
	clearLabBan(t)
	client := &http.Client{Timeout: 2 * time.Second}
	if _, err := client.Get(haproxyBURL() + "/ok"); err != nil {
		t.Skip("haproxy-b not reachable:", err)
	}
}

func corazaDeny(t *testing.T, base string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, base+"/ok", nil)
	req.Header.Set("User-Agent", "fixture-deny-request")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("deny status %d", resp.StatusCode)
	}
}

func TestRolloutSharedState(t *testing.T) {
	requireRollout(t)
	ctx := context.Background()
	c := redis.NewClient(&redis.Options{Addr: redisAddr()})
	if err := c.Ping(ctx).Err(); err != nil {
		t.Fatal(err)
	}
	info, err := c.Info(ctx, "replication").Result()
	if err != nil || !strings.Contains(info, "role:master") {
		t.Fatalf("redis primary: %v", err)
	}
	ip := labClientIP(t)
	_ = c.Del(ctx, "wg:ban:sample_app:"+ip, "wg:contrib:sample_app:"+ip)
	if err := c.Set(ctx, "wg:mode:sample_app", "enforce", 0).Err(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		corazaDeny(t, haproxyURL())
	}
	ban, err := c.Get(ctx, "wg:ban:sample_app:"+ip).Result()
	if err != nil || ban == "" {
		t.Fatalf("want ban key in redis, got %q %v", ban, err)
	}
	resp, err := http.Get(haproxyBURL() + "/ok")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("want behavioral ban on HAProxy B, got %d", resp.StatusCode)
	}
}

func TestRolloutBackendSignals(t *testing.T) {
	requireRollout(t)
	resp, err := http.Get(haproxyURL() + "/status/503")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 503 {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestRolloutOutages(t *testing.T) {
	requireRollout(t)
	corazaDeny(t, haproxyURL())
}

func TestLoadReport(t *testing.T) {
	requireCompose(t)
	start := time.Now()
	n := 50
	ok := 0
	for i := 0; i < n; i++ {
		resp, err := http.Get(haproxyURL() + "/ok")
		if err != nil {
			continue
		}
		if resp.StatusCode == 200 {
			ok++
		}
		resp.Body.Close()
	}
	elapsed := time.Since(start)
	if ok < n-5 {
		t.Fatalf("load ok=%d/%d elapsed=%s", ok, n, elapsed)
	}
	t.Logf("load_report version=haproxy3.2 requests=%d ok=%d elapsed=%s", n, ok, elapsed)
}
