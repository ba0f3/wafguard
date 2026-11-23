//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/ba0f3/haproxy-waf-spoe/internal/enrich"
	"github.com/redis/go-redis/v9"
)

func enrichComposeExec(t *testing.T, args ...string) {
	t.Helper()
	root := repoRoot(t)
	base := []string{"compose", "-f", "integration/compose.yaml", "-f", "integration/compose.enrich.yaml"}
	if os.Getenv("WAF_RECORDER") != "" {
		base = append(base, "-f", "integration/compose.recorder.yaml")
	}
	cmd := exec.Command("docker", append(base, args...)...)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker %v: %v %s", args, err, out)
	}
}

// TestEnrichmentSyntheticTailIngest proves tail/dedupe on injected JSONL (not stock Coraza match records).
func TestEnrichmentSyntheticTailIngest(t *testing.T) {
	if os.Getenv("WAF_ENRICH_SYNTH") == "" {
		t.Skip("set WAF_ENRICH_SYNTH=1 with compose.enrich.yaml up")
	}
	if os.Getenv("WAF_RECORDER") == "" {
		t.Skip("set WAF_RECORDER=1 for request correlation id")
	}
	requireRecorder(t)
	req, _ := http.NewRequest(http.MethodGet, haproxyURL()+"/ok", nil)
	req.Header.Set("User-Agent", "fixture-deny-request")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("deny %d", resp.StatusCode)
	}

	lastResp, err := http.Get(recorderBase() + "/v1/last")
	if err != nil {
		t.Fatal(err)
	}
	var last struct {
		RequestID string `json:"request_id"`
	}
	if err := json.NewDecoder(lastResp.Body).Decode(&last); err != nil || last.RequestID == "" {
		lastResp.Body.Close()
		t.Fatal("no recorder request id")
	}
	lastResp.Body.Close()

	// shortcut: coraza-spoa 0.9.1 log_file is agent lifecycle JSON, not per-rule match audit — synthetic line only.
	line := fmt.Sprintf(`{"unique_id":%q,"ruleid":1001,"tags":["marker-lab"],"severity":5,"phase":1}`, last.RequestID)
	if _, err := enrich.Parse(bytes.NewReader([]byte(line)), enrich.Source{Application: "sample_app"}, enrich.Limits{}); err != nil {
		t.Fatal(err)
	}
	enrichComposeExec(t, "exec", "-T", "wafguard", "sh", "-c", fmt.Sprintf("printf '%%s\n' %q >> /shared/coraza.jsonl", line))

	addr := redisAddr()
	cli := redis.NewClient(&redis.Options{Addr: addr})
	ctx := context.Background()
	key := "wg:enrich:sample_app:" + last.RequestID
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		rid, err := cli.HGet(ctx, key, "rule_id").Result()
		if err == nil && rid == "1001" {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	rid, err := cli.HGet(ctx, key, "rule_id").Result()
	if err != nil || rid != "1001" {
		t.Fatalf("enrich key %s rule_id %q err %v", key, rid, err)
	}
	enrichComposeExec(t, "exec", "-T", "wafguard", "sh", "-c", fmt.Sprintf("printf '%%s\n' %q >> /shared/coraza.jsonl", line))
	time.Sleep(800 * time.Millisecond)
	n, err := cli.Exists(ctx, key).Result()
	if err != nil || n != 1 {
		t.Fatalf("dedupe want 1 key got %d", n)
	}
}
