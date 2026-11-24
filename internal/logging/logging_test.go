package logging

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

func TestLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	prevOut := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		SetLevel(LevelInfo)
	})

	SetLevel(LevelInfo)
	Debugf("hidden-debug")
	Infof("shown-info")
	SetLevel(LevelDebug)
	Debugf("shown-debug")

	out := buf.String()
	if strings.Contains(out, "hidden-debug") {
		t.Errorf("Debugf must be silent at info level; got %q", out)
	}
	for _, want := range []string{"shown-info", "shown-debug"} {
		if !strings.Contains(out, want) {
			t.Errorf("log missing %q; got %q", want, out)
		}
	}
}
