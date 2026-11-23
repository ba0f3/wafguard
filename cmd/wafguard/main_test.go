package main

import (
	"bytes"
	"context"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestRedisAuthOptions(t *testing.T) {
	opt := newRedisOptions(redisOptions{Addr: "redis:6379", Username: "wg", Password: "master-secret", DB: 3})
	if opt.Username != "wg" || opt.Password != "master-secret" {
		t.Fatalf("master credentials not applied: user=%q pass=%q", opt.Username, opt.Password)
	}
	if opt.DB != 3 {
		t.Fatalf("standalone DB = %d, want 3", opt.DB)
	}
	if opt.DialTimeout == 0 {
		t.Fatal("existing timeouts were dropped")
	}
}

func TestFailoverAuthOptions(t *testing.T) {
	opt := newFailoverOptions(redisOptions{
		Username: "wg", Password: "master-secret", DB: 4,
		Sentinel: &sentinelOptions{
			MasterName: "mymaster",
			Addrs:      []string{"sentinel:26379"},
			Username:   "sentinel-user",
			Password:   "sentinel-secret",
		},
	})
	if opt.Username != "wg" || opt.Password != "master-secret" {
		t.Fatalf("master credentials not applied on failover: user=%q pass=%q", opt.Username, opt.Password)
	}
	if opt.SentinelUsername != "sentinel-user" || opt.SentinelPassword != "sentinel-secret" {
		t.Fatalf("sentinel credentials not applied: user=%q pass=%q", opt.SentinelUsername, opt.SentinelPassword)
	}
	if opt.DB != 4 {
		t.Fatalf("failover DB = %d, want 4", opt.DB)
	}
}

func TestRunLogsStartupListenersAndRedis(t *testing.T) {
	mr := miniredis.RunT(t)
	cfg, err := loadConfig(strings.NewReader(`{"version":1,"spop_listen":"127.0.0.1:0","metrics_listen":"127.0.0.1:0","redis":{"addr":"` + mr.Addr() + `"},"limits":{"allowed_apps":["sample_app"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := run(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"wafguard starting", "redis", "spoe listening", "metrics listening"} {
		if !strings.Contains(out, want) {
			t.Errorf("startup log missing %q; got:\n%s", want, out)
		}
	}
}

func TestSentinelConfigValidation(t *testing.T) {
	_, err := loadConfig(strings.NewReader(`{"version":1,"spop_listen":":0","redis":{"sentinel":{"addrs":["127.0.0.1:26379"]}}}`))
	if err == nil {
		t.Fatal("expected sentinel master_name error")
	}
	_, err = loadConfig(strings.NewReader(`{"version":1,"spop_listen":":0","redis":{"sentinel":{"master_name":"mymaster","addrs":["127.0.0.1:26379"]}},"admission_ttl_seconds":120}`))
	if err != nil {
		t.Fatal(err)
	}
}

func TestConfigValidation(t *testing.T) {
	_, err := loadConfig(strings.NewReader(`{"version":1,"spop_listen":":0","redis":{"addr":"127.0.0.1:6379"},"admission_ttl_seconds":5}`))
	if err == nil {
		t.Fatal("expected admission ttl error")
	}
	_, err = loadConfig(strings.NewReader(`{"version":1,"spop_listen":":0","redis":{"addr":"127.0.0.1:6379"},"admin_read_socket":"/tmp/x","admin_write_socket":"/tmp/x"}`))
	if err == nil {
		t.Fatal("expected socket collision")
	}
}

// Finding 2: an HTTP admin write listener is rejected at startup without an
// explicit token; the auth-outcomes listener requires one too.
func TestAdminHTTPWriteRequiresTokenAtStartup(t *testing.T) {
	base := `{"version":1,"spop_listen":":0","redis":{"addr":"127.0.0.1:6379"},`
	if _, err := loadConfig(strings.NewReader(base + `"admin_http_write":"127.0.0.1:19200"}`)); err == nil {
		t.Fatal("admin_http_write without token must fail startup validation")
	}
	if _, err := loadConfig(strings.NewReader(base + `"admin_http_write":"127.0.0.1:19200","admin_http_write_token":"t"}`)); err != nil {
		t.Fatalf("token-protected write listener: %v", err)
	}
	if _, err := loadConfig(strings.NewReader(base + `"admin_http_auth":"127.0.0.1:19201"}`)); err == nil {
		t.Fatal("admin_http_auth without token must fail startup validation")
	}
}

func TestWithAuthToken(t *testing.T) {
	h := withAuthToken("lab-token", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPut, "/v1/apps/sample_app/policy", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("unauthorized write %d want 403", w.Code)
	}
	req = httptest.NewRequest(http.MethodPut, "/v1/apps/sample_app/policy", nil)
	req.Header.Set("X-Wafguard-Auth-Token", "lab-token")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("authenticated write %d want 204", w.Code)
	}
}

// Finding 8: socket I/O against a stalled Redis endpoint is bounded by the
// client's dial/read/write settings and the request context.
func TestRedisStalledEndpointIsBounded(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Accept but never answer: simulate a stalled Redis socket.
			_ = conn
		}
	}()
	client := newRedisClient(redisOptions{Addr: ln.Addr().String()})
	defer func() { _ = client.Close() }()
	opt := client.(*redis.Client).Options()
	if opt.ContextTimeoutEnabled != true || opt.DialTimeout > time.Second ||
		opt.ReadTimeout > time.Second || opt.WriteTimeout > time.Second ||
		opt.PoolTimeout > time.Second || opt.MaxRetries > 3 {
		t.Fatalf("redis options not handler-bounded: %+v", opt)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	start := time.Now()
	_ = client.Ping(ctx).Err()
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("stalled endpoint took %v, want bounded", elapsed)
	}
}
