package enrich

import (
	"bufio"
	"context"
	"os"
	"strings"
	"time"
)

// TailJSONL polls path and ingests complete JSON lines (Coraza stock json logs).
func TailJSONL(ctx context.Context, path string, source Source, limits Limits, ingest func(context.Context, Match) error) {
	var offset int64
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		offset = readFromOffset(ctx, path, offset, source, limits, ingest)
		time.Sleep(200 * time.Millisecond)
	}
}

func readFromOffset(ctx context.Context, path string, offset int64, source Source, limits Limits, ingest func(context.Context, Match) error) int64 {
	f, err := os.Open(path)
	if err != nil {
		return offset
	}
	defer f.Close()
	if _, err := f.Seek(offset, 0); err != nil {
		return offset
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), limits.MaxLineBytes+1)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		m, err := Parse(strings.NewReader(line), source, limits)
		if err != nil {
			continue
		}
		if m.RequestID == "" {
			continue
		}
		_ = ingest(ctx, m)
	}
	pos, _ := f.Seek(0, 1)
	return pos
}
