package admin_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/ba0f3/haproxy-waf-spoe/internal/admin"
	"github.com/ba0f3/haproxy-waf-spoe/internal/event"
	"github.com/ba0f3/haproxy-waf-spoe/internal/policy"
	"github.com/ba0f3/haproxy-waf-spoe/internal/state"
	"github.com/redis/go-redis/v9"
)

// Actual HTTP cross-app rejection with both apps having real admissions.
func TestAuthHTTPBoundToSingleApp(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer client.Close()
	store, err := state.New(client, state.Config{
		Namespace: "authscope", DefaultMode: event.ModeEnforce, AuthSource: "login-app",
		Apps: map[string]policy.Config{"sample_app": policy.DefaultConfig(), "other_app": policy.DefaultConfig()},
	})
	if err != nil {
		t.Fatal(err)
	}
	appFor := map[string]string{
		"550e8400-e29b-41d4-a716-446655440010": "sample_app",
		"550e8400-e29b-41d4-a716-446655440011": "other_app",
	}
	for rid, app := range appFor {
		if _, err := store.Check(context.Background(), event.Request{
			Application: app, RequestID: rid, ClientIP: netip.MustParseAddr("192.0.2.10"),
		}); err != nil {
			t.Fatal(err)
		}
	}
	h := admin.New(store, admin.Access{
		Role: admin.Auth, SourceID: "login-app", Application: store.AuthApplication(),
	})
	post := func(app, rid string) int {
		t.Helper()
		body := fmt.Sprintf(`{"request_id":"client-forged","outcome":"failure"}`)
		req := httptest.NewRequest(http.MethodPost, "/v1/apps/"+app+"/auth-outcomes", strings.NewReader(body))
		req.Header.Set(admin.RequestIDHeader, rid)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}
	if code := post("sample_app", "550e8400-e29b-41d4-a716-446655440010"); code != http.StatusNoContent {
		t.Fatalf("bound app POST %d want 204", code)
	}
	if code := post("other_app", "550e8400-e29b-41d4-a716-446655440011"); code != http.StatusForbidden {
		t.Fatalf("cross-app POST %d want 403", code)
	}
	if mr.Exists("authscope:auth:sample_app:550e8400-e29b-41d4-a716-446655440011") {
		t.Fatal("cross-app receipt persisted")
	}
}

// HTTP surface maps an operation-id payload conflict to 409.
func TestUnbanChangedReasonHTTP409(t *testing.T) {
	store := testStore(t)
	h := admin.New(store, admin.Access{Role: admin.Write, Application: "sample_app"})
	post := func(reason string) int {
		t.Helper()
		body := fmt.Sprintf(`{"client_ip":"192.0.2.8","operation_id":"op-http-reason","reason":%q}`, reason)
		req := httptest.NewRequest(http.MethodPost, "/v1/apps/sample_app/unban", strings.NewReader(body))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}
	if code := post("original"); code != http.StatusOK {
		t.Fatalf("first unban %d want 200", code)
	}
	if code := post("original"); code != http.StatusOK {
		t.Fatalf("exact retry %d want 200", code)
	}
	if code := post("changed"); code != http.StatusConflict {
		t.Fatalf("changed reason %d want 409", code)
	}
}
