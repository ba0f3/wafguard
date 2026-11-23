//go:build integration

package integration

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func sentinelAddr() string {
	if a := os.Getenv("SENTINEL_ADDR"); a != "" {
		return a
	}
	return "127.0.0.1:26379"
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, _ := os.Getwd()
	for d := wd; d != "/"; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d
		}
	}
	t.Fatal("go.mod not found")
	return ""
}

func composeFailover(t *testing.T, args ...string) {
	t.Helper()
	root := repoRoot(t)
	files := os.Getenv("WAF_COMPOSE_FILES")
	if files == "" {
		files = "integration/compose.yaml integration/compose.failover.yaml"
	}
	base := []string{"compose"}
	for _, f := range strings.Fields(files) {
		base = append(base, "-f", f)
	}
	cmd := exec.Command("docker", append(base, args...)...)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker %v: %v %s", args, err, out)
	}
}

func waitReplicaPromoted(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	sent := redis.NewSentinelClient(&redis.Options{Addr: sentinelAddr()})
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		addr, err := sent.GetMasterAddrByName(ctx, "mymaster").Result()
		if err == nil && len(addr) >= 2 && addr[0] != "redis" {
			replicaAddr := os.Getenv("REDIS_REPLICA_ADDR")
			if replicaAddr == "" {
				replicaAddr = "127.0.0.1:6380"
			}
			prim := redis.NewClient(&redis.Options{Addr: replicaAddr})
			info, err := prim.Info(ctx, "replication").Result()
			prim.Close()
			if err == nil && strings.Contains(info, "role:master") {
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatal("replica not promoted as master")
}

func TestSentinelMasterDiscoverable(t *testing.T) {
	if os.Getenv("WAF_SENTINEL") == "" {
		t.Skip("set WAF_SENTINEL=1 with compose.sentinel.yaml up")
	}
	ctx := context.Background()
	c := redis.NewSentinelClient(&redis.Options{Addr: sentinelAddr()})
	addr, err := c.GetMasterAddrByName(ctx, "mymaster").Result()
	if err != nil || len(addr) < 2 {
		t.Fatalf("sentinel master: %v %v", addr, err)
	}
	port, _ := strconv.Atoi(addr[1])
	if port == 0 {
		t.Fatalf("bad master port %v", addr)
	}
	prim := redis.NewClient(&redis.Options{Addr: addr[0] + ":" + addr[1]})
	if err := prim.Ping(ctx).Err(); err != nil {
		t.Fatal(err)
	}
	info, err := prim.Info(ctx, "replication").Result()
	if err != nil || !strings.Contains(info, "role:master") {
		t.Fatalf("primary role: %v", err)
	}
}

func TestSentinelFailoverWafDecision(t *testing.T) {
	if os.Getenv("WAF_FAILOVER") == "" {
		t.Skip("set WAF_FAILOVER=1 with compose.failover.yaml up")
	}
	requireCompose(t)
	client := &http.Client{Timeout: 5 * time.Second}
	if _, err := client.Get(haproxyURL() + "/ok"); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, haproxyURL()+"/ok", nil)
	req.Header.Set("User-Agent", "fixture-deny-request")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("pre-failover deny %d", resp.StatusCode)
	}

	composeFailover(t, "stop", "redis")
	t.Cleanup(func() { composeFailover(t, "up", "-d", "redis") })

	waitReplicaPromoted(t)
	time.Sleep(3 * time.Second)

	var lastCode int
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		resp2, err := client.Get(haproxyURL() + "/ok")
		if err == nil {
			resp2.Body.Close()
			lastCode = resp2.StatusCode
			if resp2.StatusCode == 200 {
				break
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	if lastCode != 200 {
		t.Fatalf("post-failover allow %d", lastCode)
	}
	req2, _ := http.NewRequest(http.MethodGet, haproxyURL()+"/ok", nil)
	req2.Header.Set("User-Agent", "fixture-deny-request")
	resp3, err := client.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != 403 {
		t.Fatalf("post-failover deny %d", resp3.StatusCode)
	}
}
