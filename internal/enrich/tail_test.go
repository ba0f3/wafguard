package enrich

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func logLine(id string) string {
	return fmt.Sprintf(`{"unique_id":%q,"ruleid":1,"tags":["marker"],"severity":2,"phase":1}`, id)
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

// Finding 17: only newline-terminated records are ingested; a partial line is
// replayed once the writer completes it.
func TestTailCompleteLinesOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	first := logLine("rid-1") + "\n"
	writeFile(t, path, first+logLine("rid-2"))

	src := Source{Application: "sample_app"}
	limits := Limits{}
	var got []string
	state := readFrom(context.Background(), path, tailState{}, src, limits, func(_ context.Context, m Match) error {
		got = append(got, m.RequestID)
		return nil
	})
	if len(got) != 1 || got[0] != "rid-1" {
		t.Fatalf("ingested %v want only first complete record", got)
	}
	if state.offset != int64(len(first)) {
		t.Fatalf("offset %d want %d", state.offset, len(first))
	}

	writeFile(t, path, first+logLine("rid-2")+"\n")
	state = readFrom(context.Background(), path, state, src, limits, func(_ context.Context, m Match) error {
		got = append(got, m.RequestID)
		return nil
	})
	if len(got) != 2 || got[1] != "rid-2" {
		t.Fatalf("after newline ingested %v", got)
	}
}

// Finding 17: a retryable ingest failure keeps the offset so the record is
// replayed rather than silently dropped.
func TestTailRetryRetainsOffset(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	line := logLine("rid-retry") + "\n"
	writeFile(t, path, line)

	src := Source{Application: "sample_app"}
	boom := errors.New("redis temporarily unavailable")
	state := readFrom(context.Background(), path, tailState{}, src, Limits{}, func(context.Context, Match) error {
		return boom
	})
	if state.offset != 0 {
		t.Fatalf("failed ingest advanced offset to %d", state.offset)
	}
	var count int
	state = readFrom(context.Background(), path, state, src, Limits{}, func(context.Context, Match) error {
		count++
		return nil
	})
	if count != 1 || state.offset != int64(len(line)) {
		t.Fatalf("retry ingested=%d offset=%d", count, state.offset)
	}
}

// Finding 17: rotation (new inode) and truncation (same inode, smaller file)
// both restart from the beginning of the current file.
func TestTailRotationAndTruncation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	writeFile(t, path, logLine("rid-old")+"\n")
	src := Source{Application: "sample_app"}
	ingest := func(_ context.Context, m Match) error { return nil }
	state := readFrom(context.Background(), path, tailState{}, src, Limits{}, ingest)
	if state.offset == 0 {
		t.Fatal("initial read did not advance offset")
	}

	// Rotation: replace the path with a brand-new file.
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	rotated := logLine("rid-rotated") + "\n"
	writeFile(t, path, rotated)
	var got []string
	state = readFrom(context.Background(), path, state, src, Limits{}, func(_ context.Context, m Match) error {
		got = append(got, m.RequestID)
		return nil
	})
	if len(got) != 1 || got[0] != "rid-rotated" {
		t.Fatalf("rotation ingested %v", got)
	}

	// Truncation and rewrite in place, leaving a large stale offset.
	state.offset = 1 << 20
	truncated := logLine("rid-truncated") + "\n"
	writeFile(t, path, truncated)
	got = nil
	state = readFrom(context.Background(), path, state, src, Limits{}, func(_ context.Context, m Match) error {
		got = append(got, m.RequestID)
		return nil
	})
	if len(got) != 1 || got[0] != "rid-truncated" {
		t.Fatalf("truncation ingested %v", got)
	}
}

// Finding 17: oversized lines are skipped without buffering, and do not stop
// valid records later in the same file.
func TestTailSkipsOversizedLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	huge := "x" + strings.Repeat("y", 4096)
	good := logLine("rid-after-huge") + "\n"
	writeFile(t, path, huge+"\n"+good)

	var got []string
	limits := Limits{MaxLineBytes: 128}
	readFrom(context.Background(), path, tailState{}, Source{Application: "sample_app"}, limits,
		func(_ context.Context, m Match) error {
			got = append(got, m.RequestID)
			return nil
		})
	if len(got) != 1 || got[0] != "rid-after-huge" {
		t.Fatalf("oversized handling ingested %v", got)
	}
}
