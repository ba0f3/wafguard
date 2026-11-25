package admin_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ba0f3/haproxy-waf-spoe/internal/admin"
)

func TestWhitelistEndpoints(t *testing.T) {
	store := testStore(t)
	h := admin.New(store, admin.Access{Role: admin.Write, Application: "sample_app"})

	post := func(method, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/v1/apps/sample_app/whitelist", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}

	if w := post(http.MethodGet, ""); w.Code != http.StatusOK {
		t.Fatalf("GET %d %s", w.Code, w.Body.String())
	}
	w := post(http.MethodPost, `{"ips":["192.0.2.1","10.0.0.0/8"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("POST %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "192.0.2.1") {
		t.Fatalf("POST response missing ip: %s", w.Body.String())
	}
	w = post(http.MethodGet, "")
	if !strings.Contains(w.Body.String(), "10.0.0.0/8") {
		t.Fatalf("GET missing cidr: %s", w.Body.String())
	}
	cfg, rev, _, err := store.Policy(t.Context(), "sample_app")
	if err != nil {
		t.Fatal(err)
	}
	if rev != 1 || len(cfg.WhitelistIPs) != 2 {
		t.Fatalf("policy rev=%d whitelist=%v", rev, cfg.WhitelistIPs)
	}
	w = post(http.MethodDelete, `{"ips":["192.0.2.1"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("DELETE %d %s", w.Code, w.Body.String())
	}
	cfg, _, _, err = store.Policy(t.Context(), "sample_app")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.WhitelistIPs) != 1 || cfg.WhitelistIPs[0] != "10.0.0.0/8" {
		t.Fatalf("after delete whitelist=%v", cfg.WhitelistIPs)
	}
}
