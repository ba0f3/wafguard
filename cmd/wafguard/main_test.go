package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

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
