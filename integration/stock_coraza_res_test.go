//go:build integration

package integration

import (
	"bytes"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func corazaResLogDelta(t *testing.T) int {
	t.Helper()
	root := repoRoot(t)
	cmd := exec.Command("docker", "compose", "-f", "integration/compose.yaml", "-f", "integration/compose.responseinspect.yaml", "logs", "--tail=80", "haproxy")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("logs: %v %s", err, out)
	}
	return bytes.Count(out, []byte("<GROUP:coraza-response-sync>"))
}

func TestStockCorazaResponseSyncDeny(t *testing.T) {
	if os.Getenv("WAF_CORAZA_RES") == "" {
		t.Skip("set WAF_CORAZA_RES=1 with compose.responseinspect.yaml up")
	}
	requireCompose(t)
	before := originHits(t)
	beforeSpoe := corazaResLogDelta(t)

	resp, err := http.Get(haproxyURL() + "/marker-response-body")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("client status %d want 403", resp.StatusCode)
	}
	if h := resp.Header.Get("waf-block"); h != "response" {
		t.Fatalf("waf-block %q want response", h)
	}
	after := originHits(t)
	if after != before+1 {
		t.Fatalf("origin hits %d want %d (origin 200 before response deny)", after, before+1)
	}
	if n := corazaResLogDelta(t) - beforeSpoe; n != 1 {
		t.Fatalf("coraza-response-sync calls %d want 1", n)
	}
}

func TestStockDropRequest(t *testing.T) {
	requireCompose(t)
	req, err := http.NewRequest(http.MethodGet, haproxyURL()+"/marker-drop", nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), "EOF") || strings.Contains(err.Error(), "reset") {
			return
		}
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == 200 {
		t.Fatal("drop must not return 200")
	}
}
