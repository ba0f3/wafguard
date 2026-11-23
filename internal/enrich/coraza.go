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
	UniqueID string   `json:"unique_id"`
	RuleID   uint32   `json:"ruleid"`
	Tags     []string `json:"tags"`
	Severity int      `json:"severity"`
	Phase    int      `json:"phase"`
}

type stockMatch struct {
	UniqueID   string   `json:"unique_id"`
	RuleID     uint32   `json:"rule_id"`
	Tags       []string `json:"tags"`
	SeverityID int      `json:"severity_id"`
	PhaseID    int      `json:"phase_id"`
}

type zerologLine struct {
	Match json.RawMessage `json:"match"`
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
	buf, err := io.ReadAll(io.LimitReader(r, int64(limits.MaxLineBytes)+1))
	if err != nil {
		return Match{}, err
	}
	if len(buf) > limits.MaxLineBytes {
		return Match{}, fmt.Errorf("line too long")
	}
	var m stockMatch
	var tags []string
	var sev, phase int

	var wrap zerologLine
	if err := json.Unmarshal(buf, &wrap); err == nil && len(wrap.Match) > 0 {
		if err := json.Unmarshal(wrap.Match, &m); err != nil {
			return Match{}, err
		}
		tags = m.Tags
		sev = m.SeverityID
		phase = m.PhaseID
	} else {
		var row stockLog
		if err := json.Unmarshal(buf, &row); err != nil {
			return Match{}, err
		}
		m.UniqueID = row.UniqueID
		m.RuleID = row.RuleID
		tags = row.Tags
		sev = row.Severity
		phase = row.Phase
	}
	if m.UniqueID == "" || m.RuleID == 0 {
		return Match{}, fmt.Errorf("no match fields")
	}
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
		RequestID:   m.UniqueID,
		RuleID:      m.RuleID,
		Tags:        tags,
		Severity:    sev,
		PhaseID:     phase,
	}, nil
}
