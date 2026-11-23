package enrich

import (
	"context"
	"io"
	"os"
	"strings"
	"time"
)

type tailState struct {
	offset int64
	info   os.FileInfo
}

// TailJSONL polls path and ingests only complete, newline-terminated JSONL
// records. The offset advances past a record only after it is persisted.
func TailJSONL(ctx context.Context, path string, source Source, limits Limits, ingest func(context.Context, Match) error) {
	var state tailState
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		state = readFrom(ctx, path, state, source, limits, ingest)
		time.Sleep(200 * time.Millisecond)
	}
}

func readFrom(ctx context.Context, path string, state tailState, source Source, limits Limits, ingest func(context.Context, Match) error) tailState {
	f, err := os.Open(path)
	if err != nil {
		return state
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return state
	}
	if state.info != nil {
		if !os.SameFile(state.info, fi) || state.offset > fi.Size() {
			// Rotation or truncation: the old offset points past the new data.
			state.offset = 0
		}
	}
	state.info = fi
	if state.offset > fi.Size() {
		state.offset = 0
	}
	if _, err := f.Seek(state.offset, io.SeekStart); err != nil {
		return state
	}
	max := limits.MaxLineBytes
	if max <= 0 {
		max = 32 << 10
	}
	lineStart := state.offset
	pos := state.offset
	buf := make([]byte, 0, 4096)
	oversized := false
	chunk := make([]byte, 8192)
	for {
		n, readErr := f.Read(chunk)
		for _, b := range chunk[:n] {
			pos++
			if b == '\n' {
				// A newline closes a record; the line spans lineStart..pos-1.
				if oversized {
					state.offset = pos
					lineStart = pos
					buf = buf[:0]
					oversized = false
					continue
				}
				line := strings.TrimSpace(string(buf))
				buf = buf[:0]
				if line != "" {
					if m, err := Parse(strings.NewReader(line), source, limits); err == nil && m.RequestID != "" {
						if err := ingest(ctx, m); err != nil {
							// Retryable persistence failure: keep the offset on
							// this record so it is replayed on the next poll.
							state.offset = lineStart
							return state
						}
					}
				}
				state.offset = pos
				lineStart = pos
				continue
			}
			if !oversized {
				if len(buf) < max {
					buf = append(buf, b)
				} else {
					// Skip the rest of this oversized line without buffering it.
					buf = buf[:0]
					oversized = true
				}
			}
		}
		if readErr == io.EOF {
			// An unterminated trailing record stays uncommitted; it will be
			// re-read once the writer appends the newline.
			return state
		}
		if readErr != nil || ctx.Err() != nil {
			state.offset = lineStart
			return state
		}
	}
}
