package spoa

import (
	"context"
	"time"

	"github.com/ba0f3/haproxy-waf-spoe/internal/event"
	"github.com/dropmorepackets/haproxy-go/pkg/encoding"
)

// Backend implements admission checks and behavioral observation.
type Backend interface {
	Check(ctx context.Context, req event.Request) (event.Decision, error)
	Observe(ctx context.Context, ev event.Event) error
}

type Telemetry interface {
	RecordOperation(kind, result string, d time.Duration)
	RecordEvent(kind, result string)
	RecordDrop(reason string)
	IncInflight()
	DecInflight()
}

type noopTelemetry struct{}

func (noopTelemetry) RecordOperation(_, _ string, _ time.Duration) {}
func (noopTelemetry) RecordEvent(_, _ string)                     {}
func (noopTelemetry) RecordDrop(_ string)                         {}
func (noopTelemetry) IncInflight()                                  {}
func (noopTelemetry) DecInflight()                                  {}

// Handler serves behavioral SPOE messages.
type Handler struct {
	Backend   Backend
	Limits    event.Limits
	Timeout   time.Duration
	MaxInflight int
	Telemetry Telemetry

	sem chan struct{}
}

func NewHandler(backend Backend, limits event.Limits) *Handler {
	if limits.MaxPathLen == 0 {
		limits.MaxPathLen = 1024
	}
	if limits.MaxRuleIDs == 0 {
		limits.MaxRuleIDs = 64
	}
	if limits.MaxCategoryLen == 0 {
		limits.MaxCategoryLen = 64
	}
	h := &Handler{
		Backend:     backend,
		Limits:      limits,
		Timeout:     450 * time.Millisecond,
		MaxInflight: 256,
		Telemetry:   noopTelemetry{},
	}
	h.sem = make(chan struct{}, h.MaxInflight)
	return h
}

func (h *Handler) WithMaxInflight(n int) *Handler {
	if n > 0 {
		h.MaxInflight = n
		h.sem = make(chan struct{}, n)
	}
	return h
}

func (h *Handler) HandleSPOE(ctx context.Context, w *encoding.ActionWriter, m *encoding.Message) {
	start := time.Now()
	name := string(m.NameBytes())
	operation := "unknown"
	if _, known := event.PhaseForKind(event.Kind(name)); known {
		operation = name
	}
	result := "ok"
	defer func() {
		h.Telemetry.RecordOperation(operation, result, time.Since(start))
	}()

	select {
	case h.sem <- struct{}{}:
		defer func() { <-h.sem }()
	case <-ctx.Done():
		result = "canceled"
		return
	default:
		result = "overload"
		h.Telemetry.RecordDrop("inflight")
		_ = writeAdmissionACK(w, event.Decision{Action: event.ActionUnknown, Degraded: true})
		return
	}

	h.Telemetry.IncInflight()
	defer h.Telemetry.DecInflight()

	ev, reason, err := decodeMessage(name, m, h.Limits)
	if err != nil {
		result = "invalid"
		h.Telemetry.RecordDrop(string(reason))
		return
	}

	opCtx := ctx
	if h.Timeout > 0 {
		var cancel context.CancelFunc
		opCtx, cancel = context.WithTimeout(ctx, h.Timeout)
		defer cancel()
	}

	switch ev.Kind {
	case event.KindCheckBan:
		d, err := h.Backend.Check(opCtx, ev.Request)
		if err != nil {
			result = "degraded"
			d = event.UnknownDecision(true)
		}
		if err := writeAdmissionACK(w, d); err != nil {
			result = "write_error"
			return
		}
		h.Telemetry.RecordEvent(string(ev.Kind), string(d.Action))
	case event.KindWafVerdict, event.KindObserveResponse:
		if ev.Admission == nil {
			if ev.RequestWAF.Action == "" {
				result = "missing_admission"
				h.Telemetry.RecordDrop("missing_admission")
				return
			}
			// shortcut: HAProxy does not pass admission txn vars into later SPOE message args in this lab
			d, err := h.Backend.Check(opCtx, ev.Request)
			if err != nil || d.Admission == nil {
				result = "missing_admission"
				h.Telemetry.RecordDrop("missing_admission")
				return
			}
			ev.Admission = d.Admission
		}
		if err := h.Backend.Observe(opCtx, ev); err != nil {
			result = "observe_error"
			_ = writeObserveACK(w, true)
			return
		}
		_ = writeObserveACK(w, false)
		h.Telemetry.RecordEvent(string(ev.Kind), "ok")
	default:
		result = "unknown_kind"
	}
}

