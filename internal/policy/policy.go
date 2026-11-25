package policy

import (
	"fmt"
	"strings"

	"net/netip"

	"github.com/ba0f3/haproxy-waf-spoe/internal/event"
)

type AuthOutcome string

const (
	AuthSuccess AuthOutcome = "success"
	AuthFailure AuthOutcome = "failure"
)

type AuthReceipt struct {
	Application string      `json:"application,omitempty"`
	RequestID   string      `json:"request_id"`
	SourceID    string      `json:"source_id,omitempty"`
	AccountKey  string      `json:"account_key,omitempty"`
	ClientIP    netip.Addr  `json:"client_ip,omitempty"`
	Outcome     AuthOutcome `json:"outcome"`
}

type Config struct {
	WAFDenyWindowSec   int      `json:"waf_deny_window_sec"`
	WAFDenyThreshold   int      `json:"waf_deny_threshold"`
	WAFDenyBanSec      int      `json:"waf_deny_ban_sec"`
	ScannerWindowSec   int      `json:"scanner_window_sec"`
	ScannerResponses   int      `json:"scanner_responses"`
	ScannerPaths       int      `json:"scanner_paths"`
	BruteWindowSec     int      `json:"brute_window_sec"`
	BruteFailures      int      `json:"brute_failures"`
	ThrottleSec        int      `json:"throttle_sec"`
	OutageWindowSec    int      `json:"outage_window_sec"`
	OutageUniqueIPs    int      `json:"outage_unique_ips"`
	MaxEventAgeSec     int      `json:"max_event_age_sec"`
	AdmissionTTL       int      `json:"admission_ttl"`
	ProbePaths         []string `json:"probe_paths"`
	SlowScannerEnabled bool     `json:"slow_scanner_enabled"`

	ReqInspectPaths      []string `json:"req_inspect_paths,omitempty"`
	ResInspectPaths      []string `json:"res_inspect_paths,omitempty"`
	ObserveResponsePaths []string `json:"observe_response_paths,omitempty"`
	WhitelistIPs         []string `json:"whitelist_ips,omitempty"`

	RepeatBanThreshold int `json:"repeat_ban_threshold,omitempty"`
	RepeatBanWindowSec int `json:"repeat_ban_window_sec,omitempty"`
	RepeatBanTTLSec    int `json:"repeat_ban_ttl_sec,omitempty"`
}

// IPInList reports whether ip matches any IP or CIDR entry. Invalid entries are
// ignored so a single bad value cannot disable the whole whitelist.
func IPInList(ip netip.Addr, entries []string) bool {
	for _, entry := range entries {
		if prefix, err := netip.ParsePrefix(entry); err == nil {
			if prefix.Contains(ip) {
				return true
			}
			continue
		}
		if addr, err := netip.ParseAddr(entry); err == nil && addr == ip {
			return true
		}
	}
	return false
}

// PathMatches implements HAProxy's `path -m beg` semantics for centrally
// configured inspection prefixes.
func PathMatches(path string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

type Evidence struct {
	WAFDeny        bool
	DetectionMatch bool
	ResponseSeen   bool
	Eligible4xx    bool
	ProbePath      bool
	Backend5xx     bool
	PathKey        string
}

func DefaultConfig() Config {
	return Config{
		WAFDenyWindowSec: 30,
		WAFDenyThreshold: 3,
		WAFDenyBanSec:    900,
		ScannerWindowSec: 60,
		ScannerResponses: 30,
		ScannerPaths:     15,
		BruteWindowSec:   60,
		BruteFailures:    10,
		ThrottleSec:      120,
		OutageWindowSec:  60,
		OutageUniqueIPs:  5,
		MaxEventAgeSec:   120,
		AdmissionTTL:     120,
		ProbePaths:          []string{"/.env", "/wp-admin", "/.git"},
		RepeatBanThreshold: 2,
		RepeatBanWindowSec: 604800,
		RepeatBanTTLSec:    2592000,
	}
}

// WithDefaults fills unset (zero) numeric and list fields from DefaultConfig.
// A partially configured app must never inherit a zero threshold that would
// ban on the first failure.
func WithDefaults(cfg Config) Config {
	d := DefaultConfig()
	if cfg.WAFDenyWindowSec <= 0 {
		cfg.WAFDenyWindowSec = d.WAFDenyWindowSec
	}
	if cfg.WAFDenyThreshold <= 0 {
		cfg.WAFDenyThreshold = d.WAFDenyThreshold
	}
	if cfg.WAFDenyBanSec <= 0 {
		cfg.WAFDenyBanSec = d.WAFDenyBanSec
	}
	if cfg.ScannerWindowSec <= 0 {
		cfg.ScannerWindowSec = d.ScannerWindowSec
	}
	if cfg.ScannerResponses <= 0 {
		cfg.ScannerResponses = d.ScannerResponses
	}
	if cfg.ScannerPaths <= 0 {
		cfg.ScannerPaths = d.ScannerPaths
	}
	if cfg.BruteWindowSec <= 0 {
		cfg.BruteWindowSec = d.BruteWindowSec
	}
	if cfg.BruteFailures <= 0 {
		cfg.BruteFailures = d.BruteFailures
	}
	if cfg.ThrottleSec <= 0 {
		cfg.ThrottleSec = d.ThrottleSec
	}
	if cfg.OutageWindowSec <= 0 {
		cfg.OutageWindowSec = d.OutageWindowSec
	}
	if cfg.OutageUniqueIPs <= 0 {
		cfg.OutageUniqueIPs = d.OutageUniqueIPs
	}
	if cfg.MaxEventAgeSec <= 0 {
		cfg.MaxEventAgeSec = d.MaxEventAgeSec
	}
	if cfg.AdmissionTTL <= 0 {
		cfg.AdmissionTTL = d.AdmissionTTL
	}
	if len(cfg.ProbePaths) == 0 {
		cfg.ProbePaths = d.ProbePaths
	}
	if cfg.RepeatBanThreshold <= 0 {
		cfg.RepeatBanThreshold = d.RepeatBanThreshold
	}
	if cfg.RepeatBanWindowSec <= 0 {
		cfg.RepeatBanWindowSec = d.RepeatBanWindowSec
	}
	if cfg.RepeatBanTTLSec <= 0 {
		cfg.RepeatBanTTLSec = d.RepeatBanTTLSec
	}
	return cfg
}

func Validate(cfg Config) error {
	if cfg.WAFDenyWindowSec < 1 || cfg.WAFDenyThreshold < 1 || cfg.WAFDenyBanSec < 1 {
		return fmt.Errorf("waf deny window/threshold/ban must be >= 1")
	}
	if cfg.BruteWindowSec < 1 || cfg.BruteFailures < 1 {
		return fmt.Errorf("brute window/failures must be >= 1")
	}
	if cfg.MaxEventAgeSec < cfg.AdmissionTTL {
		return fmt.Errorf("max_event_age must be >= admission TTL")
	}
	if cfg.RepeatBanThreshold < 1 || cfg.RepeatBanWindowSec < 1 || cfg.RepeatBanTTLSec < cfg.WAFDenyBanSec {
		return fmt.Errorf("repeat ban threshold/window must be >= 1 and ttl >= waf_deny_ban_sec")
	}
	return nil
}

func CanonicalPath(p string) string {
	p = event.StripQueryPath(p)
	if len(p) > 1 && strings.HasSuffix(p, "/") {
		p = strings.TrimSuffix(p, "/")
	}
	return p
}

func Classify(e event.Event, cfg Config) Evidence {
	ev := Evidence{PathKey: CanonicalPath(e.Request.Path)}
	if e.OwnRejection {
		return ev
	}
	if e.OriginStatus != nil {
		ev.ResponseSeen = true
		st := *e.OriginStatus
		if st >= 500 && st <= 504 {
			ev.Backend5xx = true
		}
		if st >= 400 && st < 500 && !e.OwnRejection {
			ev.Eligible4xx = true
		}
	}
	v := e.RequestWAF
	if e.ResponseWAF != nil {
		v = *e.ResponseWAF
	}
	if v.InspectionError {
		return ev
	}
	if v.Source == "hypothetical" {
		ev.DetectionMatch = true
		return ev
	}
	action := strings.ToLower(v.Action)
	if (action == "deny" || action == "drop") && v.Source == "enforced" {
		ev.WAFDeny = true
	}
	for _, probe := range cfg.ProbePaths {
		if ev.PathKey == probe || strings.HasPrefix(ev.PathKey, probe) {
			ev.ProbePath = true
			break
		}
	}
	return ev
}

func WAFDenyContribution(e event.Event, cfg Config) bool {
	ev := Classify(e, cfg)
	return ev.WAFDeny && !e.OwnRejection && !e.RequestWAF.InspectionError
}
