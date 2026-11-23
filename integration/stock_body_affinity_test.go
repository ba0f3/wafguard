//go:build integration

package integration

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

type recEntry struct {
	Calls     []string `json:"calls"`
	Snapshots []struct {
		Message         string `json:"message"`
		InspectionError bool   `json:"inspection_error"`
	} `json:"snapshots"`
}

func requireRecorderMatrix(t *testing.T) {
	t.Helper()
	if os.Getenv("WAF_RECORDER_BODY") == "" {
		t.Skip("set WAF_RECORDER_BODY=1 with compose.recorder-body.yaml")
	}
	requireCompose(t)
}

func lastRecorderEntry(t *testing.T) recEntry {
	t.Helper()
	lastResp, err := http.Get(recorderBase() + "/v1/last")
	if err != nil {
		t.Fatal(err)
	}
	defer lastResp.Body.Close()
	var last struct {
		RequestID string `json:"request_id"`
	}
	if err := json.NewDecoder(lastResp.Body).Decode(&last); err != nil || last.RequestID == "" {
		t.Fatal("no last request id")
	}
	recResp, err := http.Get(recorderBase() + "/v1/requests/" + last.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	defer recResp.Body.Close()
	body, _ := io.ReadAll(recResp.Body)
	var rec recEntry
	if err := json.Unmarshal(body, &rec); err != nil {
		t.Fatal(err)
	}
	return rec
}

func corazaGroupsAfterPath(t *testing.T, path string) (reqG, resG int) {
	t.Helper()
	root := repoRoot(t)
	cmd := exec.Command("docker", "compose", "-f", "integration/compose.yaml", "-f", "integration/compose.recorder.yaml", "-f", "integration/compose.recorder-body.yaml", "logs", "--tail=80", "haproxy")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(out, []byte("\n"))
	idx := -1
	for i := len(lines) - 1; i >= 0; i-- {
		if bytes.Contains(lines[i], []byte(path)) {
			idx = i
			break
		}
	}
	if idx < 0 {
		return
	}
	from := idx - 12
	if from < 0 {
		from = 0
	}
	for _, line := range lines[from : idx+1] {
		if bytes.Contains(line, []byte("<GROUP:coraza-req>")) {
			reqG++
		}
		if bytes.Contains(line, []byte("<GROUP:coraza-response-sync>")) {
			resG++
		}
	}
	return reqG, resG
}

func TestStockBannedExpectBeforeBody(t *testing.T) {
	requireRecorderMatrix(t)
	body := strings.Repeat("x", 64)
	req, _ := http.NewRequest(http.MethodPost, haproxyURL()+"/fixture-precheck-ban", strings.NewReader(body))
	req.Header.Set("Expect", "100-continue")
	req.ContentLength = int64(len(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("status %d want 403", resp.StatusCode)
	}
	rec := lastRecorderEntry(t)
	if len(rec.Calls) != 1 || rec.Calls[0] != "check-ban" {
		t.Fatalf("calls %v want [check-ban] only (no coraza)", rec.Calls)
	}
}

func TestStockAllowedPrecheckBodyMarker(t *testing.T) {
	requireRecorderMatrix(t)
	before := originHits(t)
	req, _ := http.NewRequest(http.MethodPost, haproxyURL()+"/echo", strings.NewReader("x"))
	req.Header.Set("User-Agent", "fixture-body-deny")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("status %d want 403", resp.StatusCode)
	}
	if originHits(t) != before {
		t.Fatal("deny must not reach origin")
	}
	rec := lastRecorderEntry(t)
	want := []string{"check-ban", "waf-verdict"}
	if len(rec.Calls) < len(want) {
		t.Fatalf("calls %v", rec.Calls)
	}
	for i, n := range want {
		if rec.Calls[i] != n {
			t.Fatalf("calls %v want prefix %v", rec.Calls, want)
		}
	}
}

func TestStockIncompleteBodyTimeout(t *testing.T) {
	requireRecorderMatrix(t)
	before := originHits(t)
	host := strings.TrimPrefix(haproxyURL(), "http://")
	conn, err := net.DialTimeout("tcp", host, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = fmt.Fprintf(conn, "POST /echo HTTP/1.1\r\nHost: %s\r\nContent-Length: 8192\r\n\r\n", host)
	status, readErr := readHTTPStatusOptional(conn)
	if readErr != nil {
		if originHits(t) != before {
			t.Fatal("origin reached during partial body")
		}
		return
	}
	if status != 408 {
		t.Fatalf("status %d want 408", status)
	}
	if originHits(t) != before {
		t.Fatal("incomplete body must not reach origin")
	}
}

func readHTTPStatusOptional(r io.Reader) (int, error) {
	br := bufio.NewReader(r)
	line, err := br.ReadString('\n')
	if err != nil {
		return 0, err
	}
	var code int
	if _, err := fmt.Sscanf(line, "HTTP/1.1 %d", &code); err != nil {
		return 0, fmt.Errorf("status line %q: %w", line, err)
	}
	return code, nil
}

func TestStockCorazaRequestResponseAffinity(t *testing.T) {
	requireRecorderMatrix(t)
	before := originHits(t)
	resp, err := http.Get(haproxyURL() + "/marker-response-body")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("status %d want 403", resp.StatusCode)
	}
	if originHits(t) != before+1 {
		t.Fatal("origin 200 before response deny")
	}
	reqG, resG := corazaGroupsAfterPath(t, "/marker-response-body")
	if reqG < 1 || resG < 1 {
		t.Fatalf("coraza req/res groups %d/%d want >=1 each (dual backend)", reqG, resG)
	}
}

func TestStockForcedAffinityMiss(t *testing.T) {
	requireRecorderMatrix(t)
	resp, err := http.Get(haproxyURL() + "/fixture-affinity-break")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	rec := lastRecorderEntry(t)
	var sawObs bool
	var inspErr bool
	for _, s := range rec.Snapshots {
		if s.Message == "observe-response" {
			sawObs = true
			inspErr = s.InspectionError
		}
	}
	if !sawObs {
		t.Fatal("no observe-response snapshot")
	}
	if !inspErr {
		t.Fatal("want inspection_error on forced affinity break")
	}
}

func TestStockBodyAndAffinity(t *testing.T) {
	t.Run("BannedExpectBeforeBody", TestStockBannedExpectBeforeBody)
	t.Run("AllowedPrecheckBodyMarker", TestStockAllowedPrecheckBodyMarker)
	t.Run("IncompleteBody", TestStockIncompleteBodyTimeout)
	t.Run("Affinity", TestStockCorazaRequestResponseAffinity)
	t.Run("ForcedAffinityMiss", TestStockForcedAffinityMiss)
}
