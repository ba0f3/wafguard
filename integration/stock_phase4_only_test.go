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
	if h := marked.Header.Get("X-Phase4-Fixture"); h != "constant" {
		t.Fatalf("marker header %q want constant", h)
	}
	if originHits(t) != before+2 {
		t.Fatalf("origin hits want %d got %d", before+2, originHits(t))
	}

	// Report observed marker outcome without phase-3 rules; do not claim deny pass if stack returns 200.
	if marked.StatusCode == 403 {
		if marked.Header.Get("waf-block") != "response" {
			t.Fatalf("marker waf-block %q want response when denied", marked.Header.Get("waf-block"))
		}
		t.Log("phase4-only body deny: client=403 (no phase-3 rules)")
		return
	}
	if marked.StatusCode != 200 {
		t.Fatalf("unexpected marker client %d", marked.StatusCode)
	}
	t.Log("phase4-only body deny: client=200 (SecResponseBodyAccess + explicit coraza-response-sync; phase-4 rule 4001 did not deny on coraza-spoa 0.9.1 in this lab)")
}
