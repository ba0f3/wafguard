package state

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/ba0f3/haproxy-waf-spoe/internal/enrich"
	"github.com/ba0f3/haproxy-waf-spoe/internal/event"
	"github.com/ba0f3/haproxy-waf-spoe/internal/logging"
	"github.com/ba0f3/haproxy-waf-spoe/internal/policy"
	"github.com/redis/go-redis/v9"
)

//go:embed scripts/*.lua
var scriptsFS embed.FS

type Config struct {
	Namespace       string
	DefaultMode     event.Mode
	Apps            map[string]policy.Config
	AuthSource      string
	AuthApplication string
	AdmissionTTL    time.Duration
}

// ErrOperationConflict marks a retry of an unban operation id with a changed
// payload; the HTTP admin API maps it to 409.
var ErrOperationConflict = errors.New("operation id reused with a different payload")

type Store struct {
	client redis.UniversalClient
	cfg    Config
	// *redis.Script keeps the source so Script.Run retries with EVAL after a
	// SCRIPT FLUSH or a Redis failover loses the script cache.
	checkScript      *redis.Script
	observeScript    *redis.Script
	recordAuthScript *redis.Script
	enrichScript     *redis.Script
	policyScript     *redis.Script
	unbanScript      *redis.Script

	mu        sync.RWMutex
	fenceGen  map[string]string
	configs   map[string]policy.Config // converged from Redis on every replica
	configRev map[string]uint64        // revision each cached config was loaded at
}

type Inspection struct {
	Action       event.Action
	ExpiresAt    time.Time
	Revision     uint64
	Mode         event.Mode
	Generation   string
	Explanation  string
	OriginStatus int
	ResponseSeen bool
}

type UnbanRequest struct {
	Application string
	ClientIP    netip.Addr
	Mode        event.Mode
	OperationID string
	Reason      string
	Suppression time.Duration
}

type UnbanResult struct {
	Generation      string
	OperationID     string
	SuppressedUntil time.Time
}

type Page struct {
	Items      []Inspection
	NextCursor string
}

func mustScript(name string) *redis.Script {
	src, err := scriptsFS.ReadFile("scripts/" + name)
	if err != nil {
		panic(err)
	}
	return redis.NewScript(string(src))
}

func New(client redis.UniversalClient, cfg Config) (*Store, error) {
	if cfg.Namespace == "" {
		cfg.Namespace = "wg"
	}
	if cfg.DefaultMode == "" {
		cfg.DefaultMode = event.ModeObserve
	}
	if cfg.Apps == nil {
		cfg.Apps = map[string]policy.Config{"sample_app": policy.DefaultConfig()}
	}
	if cfg.AdmissionTTL <= 0 {
		cfg.AdmissionTTL = 120 * time.Second
	}
	if cfg.AuthSource == "" {
		cfg.AuthSource = "login-app"
	}
	// The auth listener is bound to exactly one application. With several
	// configured apps an explicit auth_application is expected in production;
	// the defaults below stay fail-closed by binding to a single app and
	// rejecting receipts for every other app.
	if cfg.AuthApplication == "" {
		if _, ok := cfg.Apps["sample_app"]; ok {
			cfg.AuthApplication = "sample_app"
		} else if len(cfg.Apps) == 1 {
			for app := range cfg.Apps {
				cfg.AuthApplication = app
			}
		} else {
			apps := make([]string, 0, len(cfg.Apps))
			for app := range cfg.Apps {
				apps = append(apps, app)
			}
			sort.Strings(apps)
			cfg.AuthApplication = apps[0]
		}
	}
	if _, ok := cfg.Apps[cfg.AuthApplication]; !ok {
		return nil, fmt.Errorf("auth application %q is not configured", cfg.AuthApplication)
	}
	s := &Store{
		client:           client,
		cfg:              cfg,
		checkScript:      mustScript("check.lua"),
		observeScript:    mustScript("observe.lua"),
		recordAuthScript: mustScript("record_auth.lua"),
		enrichScript:     mustScript("enrich.lua"),
		policyScript:     mustScript("policy.lua"),
		unbanScript:      mustScript("unban.lua"),
		fenceGen:         map[string]string{},
		configs:          map[string]policy.Config{},
		configRev:        map[string]uint64{},
	}
	ctx := context.Background()
	for _, script := range []*redis.Script{s.checkScript, s.observeScript, s.recordAuthScript, s.enrichScript, s.policyScript, s.unbanScript} {
		if err := script.Load(ctx, client).Err(); err != nil {
			return nil, err
		}
	}
	for app, c := range cfg.Apps {
		c = policy.WithDefaults(c)
		if err := policy.Validate(c); err != nil {
			return nil, fmt.Errorf("app %s: %w", app, err)
		}
		s.configs[app] = c
		_ = client.SetNX(ctx, s.modeKey(app), string(cfg.DefaultMode), 0).Err()
	}
	return s, nil
}

// appCfgAt prefers the config converged from Redis so PUT policy updates apply
// to every replica. The admission revision is the cache key: a policy change
// advances it, so in-flight events from the old revision use the old rules and
// new admissions immediately see the published config.
func (s *Store) appCfgAt(ctx context.Context, app string, rev uint64) (policy.Config, error) {
	s.mu.RLock()
	c, ok := s.configs[app]
	loadedRev := s.configRev[app]
	s.mu.RUnlock()
	if ok && (rev == 0 || loadedRev == rev) {
		return c, nil
	}
	// A newer revision must be loaded from Redis or the operation fails closed;
	// falling back to a cached older config would persist under wrong rules.
	raw, err := s.client.Get(ctx, s.policyConfigKey(app)).Result()
	if err != nil {
		if err == redis.Nil {
			return policy.Config{}, fmt.Errorf("policy config missing for revision %d", rev)
		}
		return policy.Config{}, err
	}
	var loaded policy.Config
	if err := json.Unmarshal([]byte(raw), &loaded); err != nil {
		return policy.Config{}, fmt.Errorf("policy config invalid: %w", err)
	}
	loaded = policy.WithDefaults(loaded)
	if err := policy.Validate(loaded); err != nil {
		return policy.Config{}, fmt.Errorf("policy config invalid: %w", err)
	}
	s.mu.Lock()
	s.configs[app] = loaded
	s.configRev[app] = rev
	s.mu.Unlock()
	return loaded, nil
}

func (s *Store) prefix(parts ...string) string {
	out := s.cfg.Namespace
	for _, p := range parts {
		out += ":" + p
	}
	return out
}

func (s *Store) banKey(app string, ip netip.Addr) string  { return s.prefix("ban", app, ip.String()) }
func (s *Store) metaKey(app string, ip netip.Addr) string { return s.prefix("meta", app, ip.String()) }
func (s *Store) modeKey(app string) string                { return s.prefix("mode", app) }
func (s *Store) supKey(app string, ip netip.Addr) string  { return s.prefix("sup", app, ip.String()) }
func (s *Store) authKey(app, requestID string) string     { return s.prefix("auth", app, requestID) }
func (s *Store) bruteKey(app string, ip netip.Addr) string {
	return s.prefix("brute", app, ip.String())
}
func (s *Store) scannerKey(app string, ip netip.Addr) string {
	return s.prefix("scanner", app, ip.String())
}
func (s *Store) dedupeKey(eventID string) string { return s.prefix("dedupe", eventID) }
func (s *Store) contribKey(app string, ip netip.Addr) string {
	return s.prefix("contrib", app, ip.String())
}
func (s *Store) fenceKey(app string) string { return s.prefix("fence", app) }
func (s *Store) admissionKey(app, requestID string) string {
	return s.prefix("admission", app, requestID)
}
func (s *Store) policyRevKey(app string) string    { return s.prefix("policy", app) + ":revision" }
func (s *Store) policyConfigKey(app string) string { return s.prefix("policy", app) + ":config" }
func (s *Store) unbanOpKey(opID string) string     { return s.prefix("unban-op", opID) }

func (s *Store) Healthy(ctx context.Context) error { return s.client.Ping(ctx).Err() }

// AuthApplication is the single app this auth listener/source is bound to.
func (s *Store) AuthApplication() string { return s.cfg.AuthApplication }

func (s *Store) Check(ctx context.Context, req event.Request) (event.Decision, error) {
	ip := req.ClientIP
	app := req.Application
	keys := []string{
		s.banKey(app, ip), s.metaKey(app, ip), s.modeKey(app), s.supKey(app, ip),
		s.fenceKey(app), s.policyRevKey(app), s.admissionKey(app, req.RequestID),
		s.policyConfigKey(app),
	}
	res, err := s.checkScript.Run(ctx, s.client, keys,
		time.Now().UnixMilli(), string(s.cfg.DefaultMode), req.RequestID,
		s.admissionTTL().Milliseconds(), ip.String(), app,
	).Result()
	if err != nil {
		return event.UnknownDecision(true), err
	}
	row, ok := res.([]interface{})
	if !ok || len(row) < 5 {
		return event.UnknownDecision(true), fmt.Errorf("bad check result")
	}
	action := event.Action(fmt.Sprint(row[0]))
	expMS, _ := strconv.ParseInt(fmt.Sprint(row[1]), 10, 64)
	gen := fmt.Sprint(row[2])
	rev, _ := strconv.ParseUint(fmt.Sprint(row[3]), 10, 64)
	mode := event.Mode(fmt.Sprint(row[4]))
	d := event.Decision{
		Action:    action,
		ExpiresAt: time.UnixMilli(expMS),
		Admission: &event.Admission{
			Generation: gen,
			At:         time.Now(),
			Revision:   rev,
			Mode:       mode,
		},
	}
	if action == event.ActionBan {
		d.Action = event.ActionBan
	}
	if len(row) > 5 {
		switch fmt.Sprint(row[5]) {
		case "suppressed":
			d.Explanation = "suppressed"
		case "observe-mode":
			d.Explanation = "observe-mode"
		}
	}
	return d, nil
}

func (s *Store) Observe(ctx context.Context, ev event.Event) error {
	if ev.OwnRejection {
		return nil
	}
	app := ev.Request.Application
	var rev uint64
	if ev.Admission != nil {
		rev = ev.Admission.Revision
	}
	cfg, err := s.appCfgAt(ctx, app, rev)
	if err != nil {
		return err
	}
	deny := 0
	// Response observation is a separate signal. Reusing the request verdict
	// here would count the same request twice in the deny window.
	if ev.Kind != event.KindObserveResponse && policy.WAFDenyContribution(ev, cfg) {
		deny = 1
	}
	admissionGen := ""
	admissionAt := int64(0)
	if ev.Admission != nil {
		admissionGen = ev.Admission.Generation
		admissionAt = ev.Admission.At.UnixMilli()
	}
	keys := []string{
		s.dedupeKey(ev.ID), s.contribKey(app, ev.Request.ClientIP),
		s.banKey(app, ev.Request.ClientIP), s.metaKey(app, ev.Request.ClientIP),
		s.modeKey(app), s.fenceKey(app), s.authKey(app, ev.Request.RequestID),
		s.bruteKey(app, ev.Request.ClientIP),
		s.admissionKey(app, ev.Request.RequestID), s.policyRevKey(app),
		s.supKey(app, ev.Request.ClientIP), s.scannerKey(app, ev.Request.ClientIP),
	}
	originStatus, finalStatus := "", ""
	if ev.OriginStatus != nil {
		originStatus = strconv.Itoa(*ev.OriginStatus)
	}
	if ev.FinalClientStatus != nil {
		finalStatus = strconv.Itoa(*ev.FinalClientStatus)
	}
	res, err := s.observeScript.Run(ctx, s.client, keys,
		ev.ID, time.Now().UnixMilli(), deny,
		cfg.WAFDenyWindowSec, cfg.WAFDenyThreshold, cfg.WAFDenyBanSec,
		string(s.cfg.DefaultMode), admissionGen, cfg.MaxEventAgeSec*1000,
		admissionAt, cfg.BruteWindowSec, cfg.BruteFailures,
		ev.Request.RequestID, app, ev.Request.ClientIP.String(),
		originStatus, finalStatus, strconv.FormatUint(rev, 10),
		cfg.ScannerWindowSec, cfg.ScannerResponses,
	).Result()
	if err != nil {
		return err
	}
	if row, ok := res.([]interface{}); ok && len(row) > 0 {
		status := fmt.Sprint(row[0])
		banReason := ""
		if len(row) > 1 {
			banReason = fmt.Sprint(row[1])
		}
		banCount, banThreshold := "-", "-"
		for _, item := range row[2:] {
			sig, ok := item.([]interface{})
			if !ok || len(sig) < 3 {
				continue
			}
			reason := fmt.Sprint(sig[0])
			count := fmt.Sprint(sig[1])
			threshold := fmt.Sprint(sig[2])
			if reason == "backend_5xx" {
				logging.Infof("backend_5xx app=%s request_id=%s client_ip=%s status=%s",
					app, ev.Request.RequestID, ev.Request.ClientIP, count)
				continue
			}
			logging.Infof("counter +1 app=%s request_id=%s client_ip=%s reason=%s count=%s threshold=%s",
				app, ev.Request.RequestID, ev.Request.ClientIP, reason, count, threshold)
			if reason == banReason {
				banCount, banThreshold = count, threshold
			}
		}
		switch status {
		case "banned":
			logging.Infof("ban issued app=%s request_id=%s client_ip=%s reason=%s count=%s threshold=%s",
				app, ev.Request.RequestID, ev.Request.ClientIP, banReason, banCount, banThreshold)
		case "shadow":
			logging.Infof("ban would fire app=%s request_id=%s client_ip=%s reason=%s count=%s threshold=%s mode=observe",
				app, ev.Request.RequestID, ev.Request.ClientIP, banReason, banCount, banThreshold)
		}
	}
	return nil
}

func (s *Store) RecordAuth(ctx context.Context, receipt policy.AuthReceipt) error {
	app := receipt.Application
	if receipt.SourceID != s.cfg.AuthSource {
		return fmt.Errorf("auth source %q not trusted for app %q", receipt.SourceID, app)
	}
	if app != s.cfg.AuthApplication {
		return fmt.Errorf("auth application %q not bound to this listener (bound to %q)", app, s.cfg.AuthApplication)
	}
	verdictID := event.EventID(app, receipt.RequestID, event.KindWafVerdict)
	// The client IP comes from the admission token, never from the caller.
	tokenKey := s.admissionKey(app, receipt.RequestID)
	ipStr, err := s.client.HGet(ctx, tokenKey, "ip").Result()
	if err != nil {
		return fmt.Errorf("no admission for auth receipt: %w", err)
	}
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return fmt.Errorf("bad admission ip %q: %w", ipStr, err)
	}
	revStr, err := s.client.HGet(ctx, tokenKey, "rev").Result()
	if err != nil {
		return fmt.Errorf("no admission revision for auth receipt: %w", err)
	}
	rev, err := strconv.ParseUint(revStr, 10, 64)
	if err != nil {
		return fmt.Errorf("bad admission revision %q: %w", revStr, err)
	}
	cfg, err := s.appCfgAt(ctx, app, rev)
	if err != nil {
		return err
	}
	keys := []string{
		s.authKey(app, receipt.RequestID), s.dedupeKey(verdictID),
		s.bruteKey(app, ip), s.banKey(app, ip),
		s.modeKey(app), tokenKey, s.fenceKey(app), s.metaKey(app, ip),
		s.supKey(app, ip), s.policyRevKey(app),
	}
	res, err := s.recordAuthScript.Run(ctx, s.client, keys,
		string(receipt.Outcome), receipt.SourceID, time.Now().UnixMilli(),
		cfg.BruteWindowSec, cfg.BruteFailures, cfg.WAFDenyBanSec,
		receipt.RequestID, string(s.cfg.DefaultMode), s.cfg.AuthSource, app,
		cfg.MaxEventAgeSec*1000, 24*60*60, ip.String(), strconv.FormatUint(rev, 10),
	).Result()
	if err != nil {
		return err
	}
	row, ok := res.([]interface{})
	if !ok || len(row) < 1 {
		return fmt.Errorf("bad auth result")
	}
	// Only a persisted record or a genuine duplicate is a successful write.
	switch fmt.Sprint(row[0]) {
	case "ok", "duplicate", "brute_banned", "suppressed":
		return nil
	default:
		return fmt.Errorf("auth receipt %s: %v", fmt.Sprint(row[0]), row)
	}
}

// Unban requires a caller-supplied, non-empty operation id: it is the
// idempotency key. Reusing it with a different payload is a conflict.
func (s *Store) Unban(ctx context.Context, req UnbanRequest) (UnbanResult, error) {
	opID := req.OperationID
	if opID == "" {
		return UnbanResult{}, fmt.Errorf("operation_id required")
	}
	if req.Suppression < 0 {
		return UnbanResult{}, fmt.Errorf("suppression must be >= 0")
	}
	gen := fmt.Sprintf("unban-%d", time.Now().UnixNano())
	keys := []string{
		s.unbanOpKey(opID), s.banKey(req.Application, req.ClientIP),
		s.contribKey(req.Application, req.ClientIP), s.supKey(req.Application, req.ClientIP),
		s.metaKey(req.Application, req.ClientIP), s.fenceKey(req.Application),
		s.bruteKey(req.Application, req.ClientIP),
	}
	res, err := s.unbanScript.Run(ctx, s.client, keys,
		opID, gen, time.Now().UnixMilli(), req.Suppression.Milliseconds(),
		(24 * time.Hour).Milliseconds(), req.Application, req.ClientIP.String(), req.Reason,
	).Result()
	if err != nil {
		return UnbanResult{}, err
	}
	row, ok := res.([]interface{})
	if !ok || len(row) < 1 {
		return UnbanResult{}, fmt.Errorf("bad unban result")
	}
	resultGen := fmt.Sprint(row[0])
	if resultGen == "conflict" {
		return UnbanResult{}, ErrOperationConflict
	}
	if len(row) < 2 {
		return UnbanResult{}, fmt.Errorf("bad unban result")
	}
	expMS, err := strconv.ParseInt(fmt.Sprint(row[1]), 10, 64)
	if err != nil {
		return UnbanResult{}, fmt.Errorf("bad stored suppression expiry: %w", err)
	}
	s.mu.Lock()
	s.fenceGen[req.Application] = resultGen
	s.mu.Unlock()
	return UnbanResult{
		Generation:      resultGen,
		OperationID:     opID,
		SuppressedUntil: time.UnixMilli(expMS),
	}, nil
}

func (s *Store) PolicyRevision(ctx context.Context, app string) (uint64, error) {
	rev, err := s.client.Get(ctx, s.policyRevKey(app)).Uint64()
	if err == redis.Nil {
		return 0, nil
	}
	return rev, err
}

func (s *Store) ValidatePolicyUpdate(ctx context.Context, app string, expectedRevision uint64, cfg policy.Config) (uint64, error) {
	cfg = policy.WithDefaults(cfg)
	if err := policy.Validate(cfg); err != nil {
		return 0, err
	}
	rev, err := s.PolicyRevision(ctx, app)
	if err != nil {
		return 0, err
	}
	if expectedRevision != rev {
		return rev, fmt.Errorf("stale revision: have %d want %d", rev, expectedRevision)
	}
	return rev + 1, nil
}

func (s *Store) SetPolicy(ctx context.Context, app string, expectedRevision uint64, cfg policy.Config, mode event.Mode) (uint64, error) {
	cfg = policy.WithDefaults(cfg)
	if err := policy.Validate(cfg); err != nil {
		return 0, err
	}
	if mode != event.ModeObserve && mode != event.ModeEnforce {
		return 0, fmt.Errorf("unsupported mode %q", mode)
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return 0, err
	}
	newFence := fmt.Sprintf("rev-%d", expectedRevision+1)
	res, err := s.policyScript.Run(ctx, s.client,
		[]string{s.policyRevKey(app), s.policyConfigKey(app), s.modeKey(app), s.fenceKey(app)},
		expectedRevision, string(raw), string(mode), newFence, (24 * time.Hour).Milliseconds(),
	).Result()
	if err != nil {
		return 0, err
	}
	row, ok := res.([]interface{})
	if !ok || len(row) < 2 {
		return 0, fmt.Errorf("bad policy result")
	}
	if fmt.Sprint(row[0]) == "stale" {
		have, _ := strconv.ParseUint(fmt.Sprint(row[1]), 10, 64)
		return have, fmt.Errorf("stale revision: have %d want %d", have, expectedRevision)
	}
	rev, err := strconv.ParseUint(fmt.Sprint(row[1]), 10, 64)
	if err == nil {
		s.mu.Lock()
		s.configs[app] = cfg
		s.configRev[app] = rev
		s.fenceGen[app] = newFence
		s.mu.Unlock()
	}
	return rev, err
}

func (s *Store) Enrich(ctx context.Context, m enrich.Match) error {
	tags, _ := json.Marshal(m.Tags)
	_, err := s.enrichScript.Run(ctx, s.client, []string{s.enrichKey(m.Application, m.RequestID)},
		strconv.FormatUint(uint64(m.RuleID), 10), string(tags), strconv.Itoa(m.Severity),
		strconv.Itoa(m.PhaseID), "3600",
	).Result()
	return err
}

func (s *Store) HasEnrichment(ctx context.Context, app, requestID string) (bool, error) {
	n, err := s.client.Exists(ctx, s.enrichKey(app, requestID)).Result()
	return n > 0, err
}

func (s *Store) Inspect(ctx context.Context, app string, mode event.Mode, ip netip.Addr) (Inspection, error) {
	dec, err := s.Check(ctx, event.Request{Application: app, ClientIP: ip})
	if err != nil {
		return Inspection{}, err
	}
	insp := Inspection{Action: dec.Action, ExpiresAt: dec.ExpiresAt, Explanation: dec.Explanation}
	if dec.Admission != nil {
		insp.Revision = dec.Admission.Revision
		insp.Mode = dec.Admission.Mode
		insp.Generation = dec.Admission.Generation
	}
	meta := s.client.HGetAll(ctx, s.metaKey(app, ip)).Val()
	if st, err := strconv.Atoi(meta["origin_status"]); err == nil {
		insp.OriginStatus = st
	}
	insp.ResponseSeen = meta["response_seen"] == "1"
	return insp, nil
}

func (s *Store) List(ctx context.Context, app string, mode event.Mode, cursor string, limit int) (Page, error) {
	return Page{Items: nil, NextCursor: ""}, nil
}

func (s *Store) admissionTTL() time.Duration { return s.cfg.AdmissionTTL }

func (s *Store) enrichKey(app, requestID string) string {
	return s.prefix("enrich", app, requestID)
}
