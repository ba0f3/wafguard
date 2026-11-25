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

func testClient(t *testing.T, h http.Handler) (*client, *httptest.Server) {
	t.Helper()
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	return &client{
		base: s.URL, token: "tok", app: "sample_app",
		http: &http.Client{Timeout: time.Second},
	}, s
}

func TestStatusCommand(t *testing.T) {
	c, _ := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/apps/sample_app/status" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.Header.Get("X-Wafguard-Auth-Token") != "tok" {
			t.Errorf("missing token")
		}
		_, _ = io.WriteString(w, `{"revision":2,"mode":"enforce","whitelist_count":1}`)
	}))
	var out bytes.Buffer
	if err := run([]string{"status"}, c, &out, false); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"mode=enforce", "revision=2", "whitelist_count=1"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output missing %q: %s", want, out.String())
		}
	}
}

func TestWhitelistAddCommand(t *testing.T) {
	var got map[string]any
	c, _ := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/apps/sample_app/whitelist" {
			t.Errorf("got %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Error(err)
		}
		_, _ = io.WriteString(w, `{"revision":1,"ips":["192.0.2.1"]}`)
	}))
	var out bytes.Buffer
	if err := run([]string{"whitelist", "add", "192.0.2.1"}, c, &out, false); err != nil {
		t.Fatal(err)
	}
	ips, ok := got["ips"].([]any)
	if !ok || len(ips) != 1 || ips[0] != "192.0.2.1" {
		t.Fatalf("body ips = %v", got["ips"])
	}
	if !strings.Contains(out.String(), "192.0.2.1") {
		t.Fatalf("output = %s", out.String())
	}
}
