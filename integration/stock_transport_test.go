//go:build integration

package integration

import (
	"net/http"
	"os/exec"
	"testing"
	"time"
)

func TestStockCorazaTransportError(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	requireCompose(t)
	root := repoRoot(t)
	pause := exec.Command("docker", "compose", "-f", "integration/compose.yaml", "pause", "coraza-spoa")
	pause.Dir = root
	if out, err := pause.CombinedOutput(); err != nil {
		t.Fatalf("pause coraza: %v %s", err, out)
	}
	t.Cleanup(func() {
		un := exec.Command("docker", "compose", "-f", "integration/compose.yaml", "unpause", "coraza-spoa")
		un.Dir = root
		_, _ = un.CombinedOutput()
	})
	time.Sleep(500 * time.Millisecond)
	resp, err := http.Get(haproxyURL() + "/ok")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 500 {
		t.Fatalf("transport error status %d want 500", resp.StatusCode)
	}
}
