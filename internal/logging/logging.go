// Package logging provides a minimal level gate over the standard logger so
// per-request detail can be turned on without changing the log format.
package logging

import (
	"log"
	"strings"
	"sync/atomic"
)

type Level int32

const (
	LevelInfo  Level = 0
	LevelDebug Level = 1
)

var current atomic.Int32

func ParseLevel(s string) Level {
	if strings.EqualFold(strings.TrimSpace(s), "debug") {
		return LevelDebug
	}
	return LevelInfo
}

func SetLevel(l Level) { current.Store(int32(l)) }

func Infof(format string, args ...any) { log.Printf(format, args...) }

func Debugf(format string, args ...any) {
	if Level(current.Load()) >= LevelDebug {
		log.Printf(format, args...)
	}
}
