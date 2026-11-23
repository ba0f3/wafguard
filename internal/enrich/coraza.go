package enrich

import (
	"encoding/json"
	"fmt"
	"io"
)

type Source struct {
	Application string
	Identity    string
}

type Limits struct {
	MaxLineBytes int
	MaxTags      int
	MaxTagLen    int
}

type Match struct {
	Application string
	RequestID   string
	RuleID      uint32
	Tags        []string
	Severity    int
	PhaseID     int
}

type stockLog struct {
	UniqueID string `json:"unique_id"`
	RuleID   uint32 `json:"ruleid"`
	Tags     []string `json:"tags"`
	Severity int    `json:"severity"`
	Phase    int    `json:"phase"`
}

func Parse(r io.Reader, source Source, limits Limits) (Match, error) {
	if limits.MaxLineBytes == 0 {
		limits.MaxLineBytes = 32 << 10
	}
	if limits.MaxTags == 0 {
		limits.MaxTags = 32
	}
	if limits.MaxTagLen == 0 {
		limits.MaxTagLen = 128
	}
	buf := make([]byte, limits.MaxLineBytes+1)
	n, err := r.Read(buf)
	if err != nil && err != io.EOF {
		return Match{}, err
	}
	if n > limits.MaxLineBytes {
		return Match{}, fmt.Errorf("line too long")
	}
	var row stockLog
	if err := json.Unmarshal(buf[:n], &row); err != nil {
		return Match{}, err
	}
	tags := row.Tags
	if len(tags) > limits.MaxTags {
		tags = tags[:limits.MaxTags]
	}
	for i, tg := range tags {
		if len(tg) > limits.MaxTagLen {
			tags[i] = tg[:limits.MaxTagLen]
		}
	}
	return Match{
		Application: source.Application,
		RequestID:   row.UniqueID,
		RuleID:      row.RuleID,
		Tags:        tags,
		Severity:    row.Severity,
		PhaseID:     row.Phase,
	}, nil
}
