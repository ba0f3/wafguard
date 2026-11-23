package admin_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/ba0f3/haproxy-waf-spoe/internal/admin"
	"github.com/ba0f3/haproxy-waf-spoe/internal/event"
	"github.com/ba0f3/haproxy-waf-spoe/internal/policy"
	"github.com/ba0f3/haproxy-waf-spoe/internal/state"
	"github.com/redis/go-redis/v9"
)

func testStore(t *testing.T) *state.Store {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
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

func TestAdminRoles(t *testing.T) {
	store := testStore(t)
	readH := admin.New(store, admin.Access{Role: admin.Read, Application: "sample_app"})
	writeH := admin.New(store, admin.Access{Role: admin.Write, Application: "sample_app"})

	req := httptest.NewRequest(http.MethodPost, "/v1/apps/sample_app/unban", strings.NewReader(`{"client_ip":"192.0.2.8"}`))
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
}
