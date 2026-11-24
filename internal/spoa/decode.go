package spoa

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/ba0f3/haproxy-waf-spoe/internal/event"
	"github.com/dropmorepackets/haproxy-go/pkg/encoding"
)

func parseAddrValue(kv *encoding.KVEntry) (netip.Addr, error) {
	switch kv.Type() {
	case encoding.DataTypeIPV4, encoding.DataTypeIPV6:
		if addr, ok := netip.AddrFromSlice(kv.ValueBytes()); ok {
			return addr, nil
		}
	case encoding.DataTypeString:
		addr, err := netip.ParseAddr(strings.TrimSpace(string(kv.ValueBytes())))
		if err == nil && addr.Zone() == "" {
			return addr, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("invalid IP address")
}

// kvValueString accepts both wire forms: legacy string values and native
// typed SPOE integers/bools written with SetInt64/SetUInt64/SetBool.
func kvValueString(kv *encoding.KVEntry) string {
	switch kv.Type() {
	case encoding.DataTypeInt32, encoding.DataTypeInt64:
		return strconv.FormatInt(kv.ValueInt(), 10)
	case encoding.DataTypeUInt32, encoding.DataTypeUInt64:
		return strconv.FormatUint(uint64(kv.ValueInt()), 10)
	case encoding.DataTypeBool:
		if kv.ValueBool() {
			return "true"
		}
		return "false"
	case encoding.DataTypeIPV4, encoding.DataTypeIPV6:
		return kv.ValueAddr().String()
	default:
		return string(kv.ValueBytes())
	}
}

func decodeMessage(name string, m *encoding.Message, limits event.Limits) (event.Event, event.InvalidReason, error) {
	kind := event.Kind(name)
	phase, ok := event.PhaseForKind(kind)
	if !ok {
		return event.Event{}, event.InvalidKindPhase, fmt.Errorf("unknown message %q", name)
	}
	ev := event.Event{
		Kind:  kind,
		Phase: phase,
	}
	var admissionGen string
	var admissionAtMS int64
	var policyRev uint64
	var behaviorMode string
	kv := encoding.AcquireKVEntry()
	defer encoding.ReleaseKVEntry(kv)
	for m.KV.Next(kv) {
		key := string(kv.NameBytes())
		val := kvValueString(kv)
		switch key {
		case "schema_version":
			v, err := strconv.ParseUint(val, 10, 16)
			if err != nil {
				return ev, event.InvalidSchemaVersion, err
			}
			ev.Request.SchemaVersion = uint16(v)
		case "node_id":
			ev.Request.NodeID = val
		case "request_id":
			ev.Request.RequestID = val
		case "app":
			ev.Request.Application = val
		case "backend":
			ev.Request.Backend = val
		case "method":
			ev.Request.Method = val
		case "path":
			ev.Request.Path = event.StripQueryPath(val)
		case "route_group":
			ev.Request.RouteGroup = val
		case "client_ip":
			addr, err := parseAddrValue(kv)
			if err != nil {
				return ev, event.InvalidForwardingIP, err
			}
			ev.Request.ClientIP = addr.Unmap()
		case "peer_ip":
			addr, err := parseAddrValue(kv)
			if err != nil {
				return ev, event.InvalidForwardingIP, err
			}
			ev.Request.PeerIP = addr.Unmap()
		case "admission_generation":
			admissionGen = val
		case "admission_at_ms":
			if val != "" {
				v, err := strconv.ParseInt(val, 10, 64)
				if err != nil {
					return ev, event.InvalidControlChar, err
				}
				admissionAtMS = v
			}
		case "policy_revision":
			if val != "" {
				v, err := strconv.ParseUint(val, 10, 64)
				if err != nil {
					return ev, event.InvalidControlChar, err
				}
				policyRev = v
			}
		case "behavior_mode":
			behaviorMode = val
		case "own_rejection":
			ev.OwnRejection = val == "true" || val == "1"
		case "origin_status":
			st, err := event.ParseStatusField(key, val)
			if err != nil {
				return ev, event.InvalidStatus, err
			}
			ev.OriginStatus = st
		case "final_client_status":
			st, err := event.ParseStatusField(key, val)
			if err != nil {
				return ev, event.InvalidStatus, err
			}
			ev.FinalClientStatus = st
		default:
			if err := decodeVerdictField(&ev, key, val, limits); err != nil {
				if r, ok := err.(reasonError); ok {
					return ev, r.reason, err
				}
				return ev, event.InvalidControlChar, err
			}
		}
	}
	if admissionGen != "" || admissionAtMS != 0 {
		ev.Admission = &event.Admission{
			Generation: admissionGen,
			At:         time.UnixMilli(admissionAtMS),
			Revision:   policyRev,
			Mode:       event.Mode(behaviorMode),
		}
	}
	if ev.Request.SchemaVersion == 0 {
		ev.Request.SchemaVersion = event.SchemaVersion
	}
	ev.ID = event.EventID(ev.Request.Application, ev.Request.RequestID, ev.Kind)
	if reason, ok := event.Validate(limits, ev); !ok {
		return ev, reason, fmt.Errorf("invalid event: %s", reason)
	}
	return ev, "", nil
}

type reasonError struct {
	reason event.InvalidReason
	err    error
}

func (e reasonError) Error() string { return e.err.Error() }

func decodeVerdictField(ev *event.Event, key, val string, limits event.Limits) error {
	prefix := ""
	target := &ev.RequestWAF
	if strings.HasPrefix(key, "response_waf_") {
		prefix = "response_waf_"
		if ev.ResponseWAF == nil {
			v := event.Verdict{}
			ev.ResponseWAF = &v
		}
		target = ev.ResponseWAF
	} else if strings.HasPrefix(key, "request_waf_") {
		prefix = "request_waf_"
	} else {
		return nil
	}
	sub := strings.TrimPrefix(key, prefix)
	switch sub {
	case "action":
		target.Action = val
	case "source":
		target.Source = val
	case "inspection_error":
		target.InspectionError = val == "true" || val == "1"
	case "rule_id":
		if val == "" {
			target.RuleID = nil
			break
		}
		v, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return reasonError{event.InvalidRuleIDs, err}
		}
		target.RuleID = &v
	case "rules_hit":
		if val == "" {
			target.RulesHit = nil
			break
		}
		v, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return reasonError{event.InvalidRuleIDs, err}
		}
		target.RulesHit = &v
	case "anomaly_score":
		if val == "" {
			target.AnomalyScore = nil
			break
		}
		v, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return reasonError{event.InvalidRuleIDs, err}
		}
		target.AnomalyScore = &v
	case "rule_ids":
		if val == "" {
			target.RuleIDs = nil
			break
		}
		parts := strings.Split(val, ",")
		if len(parts) > limits.MaxRuleIDs {
			return reasonError{event.InvalidRuleIDs, fmt.Errorf("too many rule ids")}
		}
		ids := make([]uint32, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			n, err := strconv.ParseUint(p, 10, 32)
			if err != nil {
				return reasonError{event.InvalidRuleIDs, err}
			}
			ids = append(ids, uint32(n))
		}
		target.RuleIDs = ids
	}
	return nil
}

func writeAdmissionACK(w *encoding.ActionWriter, d event.Decision) error {
	action := string(d.Action)
	if action == "" {
		action = string(event.ActionUnknown)
	}
	if err := w.SetString(encoding.VarScopeTransaction, "action", action); err != nil {
		return err
	}
	if d.Admission != nil {
		if err := w.SetString(encoding.VarScopeTransaction, "admission_generation", d.Admission.Generation); err != nil {
			return err
		}
		if err := w.SetInt64(encoding.VarScopeTransaction, "admission_at_ms", d.Admission.At.UnixMilli()); err != nil {
			return err
		}
		if err := w.SetInt64(encoding.VarScopeTransaction, "policy_revision", int64(d.Admission.Revision)); err != nil {
			return err
		}
		if err := w.SetString(encoding.VarScopeTransaction, "behavior_mode", string(d.Admission.Mode)); err != nil {
			return err
		}
	}
	if d.Degraded {
		if err := w.SetString(encoding.VarScopeTransaction, "degraded", "true"); err != nil {
			return err
		}
	}
	for _, flag := range []struct {
		name    string
		enabled bool
	}{
		{"req_insp", d.ReqInspect},
		{"res_insp", d.ResInspect},
		{"observe_response", d.ObserveResponse},
	} {
		if flag.enabled {
			if err := w.SetString(encoding.VarScopeTransaction, flag.name, "1"); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeObserveACK(w *encoding.ActionWriter, degraded bool) error {
	if degraded {
		return w.SetString(encoding.VarScopeTransaction, "degraded", "true")
	}
	return nil
}
