package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func executeCmd(t *testing.T, h http.Handler, args ...string) (string, error) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	var buf bytes.Buffer
	root := newRootCmd(&buf, func(_, _, _, _ string) *client {
		return &client{
			base: srv.URL, metricsBase: srv.URL + "/metrics", token: "tok", app: "sample_app",
			http: &http.Client{Timeout: time.Second},
		}
	})
	root.SetArgs(args)
	err := root.Execute()
	return buf.String(), err
}

func TestStatusCommand(t *testing.T) {
	out, err := executeCmd(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/apps/sample_app/status" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"revision":2,"mode":"enforce","whitelist_count":1}`)
	}), "status")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"mode=enforce", "revision=2", "whitelist_count=1"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q: %s", want, out)
		}
	}
}

func TestConfigSetCommand(t *testing.T) {
	var put map[string]any
	out, err := executeCmd(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_, _ = io.WriteString(w, `{"revision":5,"mode":"enforce","config":{"waf_deny_threshold":3,"whitelist_ips":[]}}`)
		case http.MethodPut:
			if err := json.NewDecoder(r.Body).Decode(&put); err != nil {
				t.Error(err)
			}
			_, _ = io.WriteString(w, `{"revision":6}`)
		}
	}), "config", "set", "waf_deny_threshold", "7")
	if err != nil {
		t.Fatal(err)
	}
	if put["expected_revision"] != float64(5) {
		t.Fatalf("revision = %v", put["expected_revision"])
	}
	cfg, ok := put["config"].(map[string]any)
	if !ok || cfg["waf_deny_threshold"] != float64(7) {
		t.Fatalf("config = %v", put["config"])
	}
	if !strings.Contains(out, "6") {
		t.Fatalf("output = %s", out)
	}
}

func TestConfigAddRejectsScalar(t *testing.T) {
	_, err := executeCmd(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"revision":0,"config":{}}`)
	}), "config", "add", "waf_deny_threshold", "9")
	if err == nil || !strings.Contains(err.Error(), "list fields") {
		t.Fatalf("err = %v", err)
	}
}

func TestBanListCommand(t *testing.T) {
	out, err := executeCmd(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"bans":[{"client_ip":"192.0.2.9","expires_at":"2026-11-26T00:00:00Z","reason":"waf_deny","ban_count":2}]}`)
	}), "ban", "list")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"192.0.2.9", "waf_deny", "ban_count=2"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q: %s", want, out)
		}
	}
}
