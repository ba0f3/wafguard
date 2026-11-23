//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/redis/go-redis/v9"
)

func enforceLabMode(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	c := redis.NewClient(&redis.Options{Addr: redisAddr()})
	if err := c.Set(ctx, "wg:mode:sample_app", "enforce", 0).Err(); err != nil {
		t.Fatal(err)
	}
}

func contribCount(t *testing.T) int64 {
	t.Helper()
	ctx := context.Background()
	c := redis.NewClient(&redis.Options{Addr: redisAddr()})
	ip := labClientIP(t)
	n, err := c.ZCard(ctx, "wg:contrib:sample_app:"+ip).Result()
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func clearClientBanState(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	c := redis.NewClient(&redis.Options{Addr: redisAddr()})
	ip := labClientIP(t)
	_ = c.Del(ctx, "wg:ban:sample_app:"+ip, "wg:contrib:sample_app:"+ip).Err()
}

func lastRecorderVerdict(t *testing.T) (action, source string) {
	t.Helper()
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

	recResp, err := http.Get(recorderBase() + "/v1/requests/" + last.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	defer recResp.Body.Close()
	body, _ := io.ReadAll(recResp.Body)
	var rec struct {
		Snapshots []struct {
			Message string `json:"message"`
			Action  string `json:"action"`
			Source  string `json:"source"`
		} `json:"snapshots"`
	}
	if err := json.Unmarshal(body, &rec); err != nil {
		t.Fatal(err)
	}
	for _, s := range rec.Snapshots {
		if s.Message == "waf-verdict" {
			return s.Action, s.Source
		}
	}
	t.Fatal("no waf-verdict snapshot")
	return "", ""
}

func TestStockVerdictEnforcedPositive(t *testing.T) {
	requireRecorder(t)
	clearClientBanState(t)
	enforceLabMode(t)
	before := contribCount(t)

	req, _ := http.NewRequest(http.MethodGet, haproxyURL()+"/ok", nil)
	req.Header.Set("User-Agent", "fixture-deny-request")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("status %d want 403", resp.StatusCode)
	}
	action, source := lastRecorderVerdict(t)
	if action != "deny" || source != "enforced" {
		t.Fatalf("verdict action=%q source=%q", action, source)
	}
	after := contribCount(t)
	if after != before+1 {
		t.Fatalf("contrib %d want %d", after, before+1)
	}
}

func TestStockVerdictOrigin403NoContrib(t *testing.T) {
	requireCompose(t)
	clearClientBanState(t)
	before := contribCount(t)

	resp, err := http.Get(haproxyURL() + "/status/403")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if contribCount(t) != before {
		t.Fatalf("origin 403 must not add WAF deny contrib")
	}
}

func TestStockBehaviorModeObserveNoBan(t *testing.T) {
	if os.Getenv("WAF_OBSERVE_MODE") == "" {
		t.Skip("set WAF_OBSERVE_MODE=1 with default observe wafguard compose")
	}
	requireCompose(t)
	clearClientBanState(t)
	ctx := context.Background()
	c := redis.NewClient(&redis.Options{Addr: redisAddr()})
	ip := labClientIP(t)
	for i := 0; i < 3; i++ {
		req, _ := http.NewRequest(http.MethodGet, haproxyURL()+"/ok", nil)
		req.Header.Set("User-Agent", "fixture-deny-request")
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != 403 {
			t.Fatalf("deny status %d", r.StatusCode)
		}
	}
	if ban, _ := c.Get(ctx, "wg:ban:sample_app:"+ip).Result(); ban != "" {
		t.Fatalf("observe mode must not ban, got %q", ban)
	}
}

func TestStockVerdictDetectionOnly(t *testing.T) {
	if os.Getenv("WAF_DETECT_ONLY") == "" {
		t.Skip("set WAF_DETECT_ONLY=1 with compose.detectonly.yaml")
	}
	requireRecorder(t)
	clearClientBanState(t)
	before := contribCount(t)

	req, _ := http.NewRequest(http.MethodGet, haproxyURL()+"/ok", nil)
	req.Header.Set("User-Agent", "fixture-deny-request")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("detection-only client status %d want 200", resp.StatusCode)
	}
	action, source := lastRecorderVerdict(t)
	if action == "deny" && source == "enforced" {
		t.Fatalf("detection-only must not send enforced deny snapshot, got %q/%q", action, source)
	}
	if contribCount(t) != before {
		t.Fatalf("detection-only must not contrib")
	}
}

func TestStockVerdictMarkerRuleDisabled(t *testing.T) {
	if os.Getenv("WAF_NOMARKER_RULE") == "" {
		t.Skip("set WAF_NOMARKER_RULE=1 with compose.nomarker.yaml")
	}
	requireCompose(t)
	clearClientBanState(t)
	before := contribCount(t)

	resp, err := http.Get(haproxyURL() + "/marker-deny")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == 403 {
		t.Fatal("marker path must not be denied when rule 1002 is absent")
	}
	if contribCount(t) != before {
		t.Fatalf("disabled marker rule must not add contrib")
	}
}
