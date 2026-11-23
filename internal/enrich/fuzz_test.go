package enrich

import (
	"reflect"
	"strings"
	"testing"
	"testing/iotest"
)

func FuzzParseCorazaLog(f *testing.F) {
	flat := `{"unique_id":"fixture-1","ruleid":101,"tags":["fixture"],"severity":2,"phase":1}`
	f.Add(flat)
	f.Add(`{"match":{"unique_id":"fixture-2","rule_id":102,"tags":["example"],"phase_id":4}}`)
	f.Add(`{"match":`)
	f.Add(flat + strings.Repeat(" ", 1024))

	limits := Limits{MaxLineBytes: 1024, MaxTags: 4, MaxTagLen: 16}
	source := Source{Application: "configured_app", Identity: "fixture"}
	f.Fuzz(func(t *testing.T, line string) {
		if len(line) > 4096 {
			t.Skip()
		}
		match, err := Parse(strings.NewReader(line), source, limits)
		fragmented, fragmentedErr := Parse(iotest.OneByteReader(strings.NewReader(line)), source, limits)
		if (err == nil) != (fragmentedErr == nil) {
			t.Fatal("parser acceptance depends on reader chunk size")
		}
		if err != nil {
			return
		}
		if !reflect.DeepEqual(match, fragmented) {
			t.Fatal("parsed match depends on reader chunk size")
		}
		if len(line) > limits.MaxLineBytes || match.Application != source.Application || match.RequestID == "" || match.RuleID == 0 {
			t.Fatal("accepted match violates size, source, or required fields")
		}
		if len(match.Tags) > limits.MaxTags {
			t.Fatal("accepted match has too many tags")
		}
		for _, tag := range match.Tags {
			if len(tag) > limits.MaxTagLen {
				t.Fatal("accepted match has an oversized tag")
			}
		}
	})
}
