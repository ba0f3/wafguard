package admin_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ba0f3/haproxy-waf-spoe/internal/admin"
)

func FuzzAdminPolicyRequest(f *testing.F) {
	valid := `{"expected_revision":0,"mode":"observe","config":{"waf_deny_threshold":3,"max_event_age_sec":120,"admission_ttl":120}}`
	f.Add(valid, true, true)
	f.Add(valid+" {}", true, true)
	f.Add(valid+strings.Repeat(" ", 64<<10), true, true)
	f.Add(`{"config":`, true, true)
	f.Add(valid, false, true)
	f.Add(valid, true, false)

	allowed := admin.New(testStore(f), admin.Access{Role: admin.Write, Application: "sample_app"})
	readOnly := admin.New(nil, admin.Access{Role: admin.Read, Application: "sample_app"})
	f.Fuzz(func(t *testing.T, body string, writeRole, ownApp bool) {
		if len(body) > 128<<10 {
			t.Skip()
		}
		handler := readOnly
		if writeRole {
			handler = allowed
		}
		app := "other_app"
		if ownApp {
			app = "sample_app"
		}
		req := httptest.NewRequest(http.MethodPut, "/v1/apps/"+app+"/policy?dry_run=1", strings.NewReader(body))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		switch {
		case !writeRole || !ownApp:
			if w.Code != http.StatusForbidden {
				t.Fatalf("policy outside role or application scope returned %d", w.Code)
			}
		case len(body) > 64<<10:
			if w.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("oversized body returned %d", w.Code)
			}
		case !json.Valid([]byte(body)):
			if w.Code != http.StatusBadRequest {
				t.Fatalf("malformed JSON body returned %d", w.Code)
			}
		default:
			switch w.Code {
			case http.StatusOK, http.StatusBadRequest, http.StatusConflict:
			default:
				t.Fatalf("unexpected policy response %d", w.Code)
			}
		}
	})
}
