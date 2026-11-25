package admin_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/ba0f3/haproxy-waf-spoe/internal/admin"
	"github.com/ba0f3/haproxy-waf-spoe/internal/event"
	"github.com/ba0f3/haproxy-waf-spoe/internal/policy"
	"github.com/ba0f3/haproxy-waf-spoe/internal/state"
	"github.com/redis/go-redis/v9"
)

func TestBansEndpoint(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	store, err := state.New(client, state.Config{
		Namespace:   "adm",
		DefaultMode: event.ModeEnforce,
		Apps:        map[string]policy.Config{"sample_app": policy.DefaultConfig()},
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = mr.Set("adm:ban:sample_app:192.0.2.9", "1")
	mr.SetTTL("adm:ban:sample_app:192.0.2.9", 10*time.Minute)

	h := admin.New(store, admin.Access{Role: admin.Write, Application: "sample_app"})
	req := httptest.NewRequest(http.MethodGet, "/v1/apps/sample_app/bans", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET bans %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "192.0.2.9") {
		t.Fatalf("ban missing: %s", w.Body.String())
	}
}
