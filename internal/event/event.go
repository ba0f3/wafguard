package event

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const SchemaVersion uint16 = 1

const (
	VarPrefix = "wafguard"
)

type Action string

const (
	ActionUnknown  Action = "unknown"
	ActionAllow    Action = "allow"
	ActionBan      Action = "ban"
	ActionThrottle Action = "throttle"
)

type Mode string

const (
	ModeObserve Mode = "observe"
	ModeEnforce Mode = "enforce"
)

type Kind string

const (
	KindCheckBan        Kind = "check-ban"
	KindWafVerdict      Kind = "waf-verdict"
	KindObserveResponse Kind = "observe-response"
)

type Phase string

const (
	PhaseAdmission Phase = "admission"
	PhaseRequest   Phase = "request"
	PhaseResponse  Phase = "response"
)

type Request struct {
	SchemaVersion uint16
	NodeID        string
	RequestID     string
	Application   string
	Backend       string
	Method        string
	Path          string
	RouteGroup    string
	ClientIP      netip.Addr
	PeerIP        netip.Addr
}

type Admission struct {
	Generation string
	At         time.Time
	Revision   uint64
	Mode       Mode
}

type Verdict struct {
	Action          string
	Source          string
	InspectionError bool
	RuleID          *int64
	RulesHit        *int64
	AnomalyScore    *int64
	RuleIDs         []uint32
}

type Event struct {
	Request           Request
	ID                string
	Kind              Kind
	Phase             Phase
	Admission         *Admission
	RequestWAF        Verdict
	ResponseWAF       *Verdict
	OriginStatus      *int
	FinalClientStatus *int
	OwnRejection      bool
}

type Decision struct {
	Action      Action
	Admission   *Admission
	ExpiresAt   time.Time
	Degraded    bool
	Explanation string

	ReqInspect      bool
	ResInspect      bool
	ObserveResponse bool
	Whitelisted     bool
}

type Limits struct {
	AllowedApps     map[string]struct{}
	AllowedBackends map[string]struct{}
	MaxPathLen      int
	MaxRuleIDs      int
	MaxCategoryLen  int
}

type InvalidReason string

const (
	InvalidSchemaVersion InvalidReason = "schema_version"
	InvalidRequestID     InvalidReason = "request_id"
	InvalidApplication   InvalidReason = "application"
	InvalidKindPhase     InvalidReason = "kind_phase"
	InvalidStatus        InvalidReason = "status"
	InvalidRuleIDs       InvalidReason = "rule_ids"
	InvalidForwardingIP  InvalidReason = "forwarding_ip"
	InvalidControlChar   InvalidReason = "control_char"
)

var uuidV4 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func PhaseForKind(k Kind) (Phase, bool) {
	switch k {
	case KindCheckBan:
		return PhaseAdmission, true
	case KindWafVerdict:
		return PhaseRequest, true
	case KindObserveResponse:
		return PhaseResponse, true
	default:
		return "", false
	}
}

func EventID(app, requestID string, kind Kind) string {
	return app + "\x1e" + requestID + "\x1e" + string(kind)
}

func ParseUUIDv4(s string) error {
	if !uuidV4.MatchString(strings.ToLower(s)) {
		return fmt.Errorf("not uuid v4: %q", s)
	}
	_, err := uuid.Parse(s)
	return err
}

func HasControlChar(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func StripQueryPath(raw string) string {
	if i := strings.IndexByte(raw, '?'); i >= 0 {
		return raw[:i]
	}
	return raw
}

func ParseStatusField(name, val string) (*int, error) {
	if val == "" {
		return nil, nil
	}
	n, err := strconv.Atoi(val)
	if err != nil || n < 100 || n > 599 {
		return nil, fmt.Errorf("%s out of range: %q", name, val)
	}
	return &n, nil
}

func Validate(limits Limits, ev Event) (InvalidReason, bool) {
	if ev.Request.SchemaVersion != SchemaVersion {
		return InvalidSchemaVersion, false
	}
	if err := ParseUUIDv4(ev.Request.RequestID); err != nil {
		return InvalidRequestID, false
	}
	if limits.AllowedApps != nil {
		if _, ok := limits.AllowedApps[ev.Request.Application]; !ok {
			return InvalidApplication, false
		}
	}
	wantPhase, ok := PhaseForKind(ev.Kind)
	if !ok || ev.Phase != wantPhase {
		return InvalidKindPhase, false
	}
	// Admission never needs the path. Older SPOP callers send the full raw
	// path (query included) or very long paths here; rejecting them would
	// break check-ban for benign requests.
	if ev.Kind != KindCheckBan {
		maxPath := limits.MaxPathLen
		if maxPath == 0 {
			maxPath = 1024
		}
		if len(ev.Request.Path) > maxPath || HasControlChar(ev.Request.Path) {
			return InvalidControlChar, false
		}
	}
	for _, field := range []string{ev.Request.Application, ev.Request.Backend, ev.Request.Method, ev.Request.NodeID, ev.Request.RouteGroup} {
		if len(field) > limits.MaxCategoryLen || HasControlChar(field) {
			return InvalidControlChar, false
		}
	}
	if ev.OriginStatus != nil && (*ev.OriginStatus < 100 || *ev.OriginStatus > 599) {
		return InvalidStatus, false
	}
	if ev.FinalClientStatus != nil && (*ev.FinalClientStatus < 100 || *ev.FinalClientStatus > 599) {
		return InvalidStatus, false
	}
	ids := ev.RequestWAF.RuleIDs
	if ev.ResponseWAF != nil {
		ids = append(ids, ev.ResponseWAF.RuleIDs...)
	}
	if len(ids) > limits.MaxRuleIDs {
		return InvalidRuleIDs, false
	}
	return "", true
}

func UnknownDecision(degraded bool) Decision {
	return Decision{Action: ActionUnknown, Degraded: degraded}
}
