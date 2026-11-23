//go:build integration

package integration

import (
	"net/http"
	"os"
	"testing"
)

func requirePhase4Only(t *testing.T) {
	t.Helper()
	if os.Getenv("WAF_PHASE4_ONLY") == "" {
		t.Skip("set WAF_PHASE4_ONLY=1 with compose.phase4only.yaml")
	}
	requireCompose(t)
}

func TestStockResponseBodyPhase4OnlyIsolation(t *testing.T) {
	requirePhase4Only(t)
	before := originHits(t)

	ctrl, err := http.Get(haproxyURL() + "/phase4-body-control")
	if err != nil {
		t.Fatal(err)
	}
	ctrl.Body.Close()
	if ctrl.StatusCode != 200 {
		t.Fatalf("control client %d want 200", ctrl.StatusCode)
	}
	if h := ctrl.Header.Get("X-Phase4-Fixture"); h != "constant" {
		t.Fatalf("control header %q want constant", h)
	}

	marked, err := http.Get(haproxyURL() + "/phase4-body-marker")
	if err != nil {
		t.Fatal(err)
	}
	marked.Body.Close()
	if marked.StatusCode != 403 {
		t.Fatalf("marker client %d want 403", marked.StatusCode)
	}
	if h := marked.Header.Get("waf-block"); h != "response" {
		t.Fatalf("marker waf-block %q want response", h)
	}
	if originHits(t) != before+2 {
		t.Fatalf("origin hits want %d got %d", before+2, originHits(t))
	}

	// No phase-3 rules are present in this fixture: the deny can only come from
	// the phase-4 RESPONSE_BODY rule over the coraza-response-sync group.
	t.Log("phase4-only body deny: client=403 (no phase-3 rules)")
}

func TestStockResponseBodyPhase4Availability(t *testing.T) {
	requirePhase4Only(t)
	cases := []struct {
		path string
		want int
	}{
		{"/phase4-body-control", 200},
		{"/phase4-body-delayed", 403},
		{"/phase4-body-chunked", 403},
		{"/phase4-body-large-early", 403},
		// Known limit: only the HAProxy-buffered prefix reaches Coraza.
		{"/phase4-body-large-late", 200},
	}
	for _, tc := range cases {
		resp, err := http.Get(haproxyURL() + tc.path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Errorf("%s client %d want %d", tc.path, resp.StatusCode, tc.want)
		}
	}
}
