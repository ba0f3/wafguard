package admin_test

import (
	"context"
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

func testStore(t testing.TB) *state.Store {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	store, err := state.New(client, state.Config{
		Namespace:   "adm",
		DefaultMode: event.ModeObserve,
		Apps:        map[string]policy.Config{"sample_app": policy.DefaultConfig()},
	})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestAdminPolicyDryRun409(t *testing.T) {
	store := testStore(t)
	h := admin.New(store, admin.Access{Role: admin.Write, Application: "sample_app"})
	cfg := `{"waf_deny_threshold":3,"max_event_age_sec":120,"admission_ttl":120}`
	body := `{"expected_revision":0,"mode":"observe","config":` + cfg + `}`
	req := httptest.NewRequest(http.MethodPut, "/v1/apps/sample_app/policy?dry_run=1", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("dry-run %d %s", w.Code, w.Body.String())
	}
	stale := httptest.NewRequest(http.MethodPut, "/v1/apps/sample_app/policy?dry_run=1", strings.NewReader(`{"expected_revision":99,"mode":"observe","config":`+cfg+`}`))
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, stale)
	if w2.Code != http.StatusConflict {
		t.Fatalf("stale dry-run %d", w2.Code)
	}
}

func TestAdminRoles(t *testing.T) {
	store := testStore(t)
	readH := admin.New(store, admin.Access{Role: admin.Read, Application: "sample_app"})
	writeH := admin.New(store, admin.Access{Role: admin.Write, Application: "sample_app"})

	req := httptest.NewRequest(http.MethodPost, "/v1/apps/sample_app/unban", strings.NewReader(`{"client_ip":"192.0.2.8","operation_id":"op-admin-test"}`))
	w := httptest.NewRecorder()
	readH.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("read socket unban: %d", w.Code)
	}

	w2 := httptest.NewRecorder()
	writeH.ServeHTTP(w2, req)
	if w2.Code != http.StatusOK && w2.Code != http.StatusNoContent {
		// JSON response ok
		if w2.Code >= 500 {
			t.Fatalf("write unban: %d %s", w2.Code, w2.Body.String())
		}
	}

	authH := admin.New(store, admin.Access{Role: admin.Auth, SourceID: "login-app"})
	rid := "550e8400-e29b-41d4-a716-446655440077"
	_, _ = store.Check(context.Background(), event.Request{Application: "sample_app", RequestID: rid, ClientIP: netip.MustParseAddr("192.0.2.70")})
	authBody := `{"request_id":"client-forged-value","outcome":"failure"}`
	authReq := httptest.NewRequest(http.MethodPost, "/v1/apps/sample_app/auth-outcomes", strings.NewReader(authBody))
	authReq.Header.Set(admin.RequestIDHeader, rid)
	authW := httptest.NewRecorder()
	authH.ServeHTTP(authW, authReq)
	if authW.Code != http.StatusNoContent {
		t.Fatalf("auth POST %d", authW.Code)
	}
	writeAuth := httptest.NewRequest(http.MethodPost, "/v1/apps/sample_app/auth-outcomes", strings.NewReader(authBody))
	writeAuthW := httptest.NewRecorder()
	writeH.ServeHTTP(writeAuthW, writeAuth)
	if writeAuthW.Code != http.StatusForbidden {
		t.Fatalf("write on auth-outcomes %d", writeAuthW.Code)
	}
}
