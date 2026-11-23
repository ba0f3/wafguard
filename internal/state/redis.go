package state

import (
	"context"
	"embed"
	"fmt"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"encoding/json"
	"github.com/ba0f3/haproxy-waf-spoe/internal/enrich"
	"github.com/ba0f3/haproxy-waf-spoe/internal/event"
	"github.com/ba0f3/haproxy-waf-spoe/internal/policy"
	"github.com/redis/go-redis/v9"
)

//go:embed scripts/*.lua
var scriptsFS embed.FS

type Config struct {
	Namespace   string
	DefaultMode event.Mode
	Apps        map[string]policy.Config
}

type Store struct {
	client     redis.UniversalClient
	cfg        Config
	checkSHA   string
	observeSHA string
	recordAuthSHA string
	enrichSHA  string
	mu         sync.RWMutex
	fenceGen   map[string]string // app -> generation
}

type Inspection struct {
	Action      event.Action
	ExpiresAt   time.Time
	Revision    uint64
	Mode        event.Mode
	Generation  string
	Explanation string
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
	SuppressedUntil time.Time
}

type Page struct {
	Items      []Inspection
	NextCursor string
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
	checkSrc, err := scriptsFS.ReadFile("scripts/check.lua")
	if err != nil {
		return nil, err
	}
	observeSrc, err := scriptsFS.ReadFile("scripts/observe.lua")
	if err != nil {
		return nil, err
	}
	checkSHA, err := client.ScriptLoad(context.Background(), string(checkSrc)).Result()
	if err != nil {
		return nil, err
	}
	observeSHA, err := client.ScriptLoad(context.Background(), string(observeSrc)).Result()
	if err != nil {
		return nil, err
	}
	recordAuthSrc, err := scriptsFS.ReadFile("scripts/record_auth.lua")
	if err != nil {
		return nil, err
	}
	recordAuthSHA, err := client.ScriptLoad(context.Background(), string(recordAuthSrc)).Result()
	if err != nil {
		return nil, err
	}
	enrichSrc, err := scriptsFS.ReadFile("scripts/enrich.lua")
	if err != nil {
		return nil, err
	}
	enrichSHA, err := client.ScriptLoad(context.Background(), string(enrichSrc)).Result()
	if err != nil {
		return nil, err
	}
	s := &Store{
		client:     client,
		cfg:        cfg,
		checkSHA:   checkSHA,
		observeSHA: observeSHA,
		recordAuthSHA: recordAuthSHA,
		enrichSHA:  enrichSHA,
		fenceGen:   map[string]string{},
	}
	for app := range cfg.Apps {
		modeKey := s.modeKey(app)
		_ = client.SetNX(context.Background(), modeKey, string(cfg.DefaultMode), 0).Err()
	}
	return s, nil
}

func (s *Store) appCfg(app string) policy.Config {
	if c, ok := s.cfg.Apps[app]; ok {
		return c
	}
	return policy.DefaultConfig()
}

func (s *Store) prefix(parts ...string) string {
	out := s.cfg.Namespace
	for _, p := range parts {
		out += ":" + p
	}
	return out
}

func (s *Store) banKey(app string, ip netip.Addr) string {
	return s.prefix("ban", app, ip.String())
}

func (s *Store) metaKey(app string, ip netip.Addr) string {
	return s.prefix("meta", app, ip.String())
}

func (s *Store) modeKey(app string) string {
	return s.prefix("mode", app)
}

func (s *Store) supKey(app string, ip netip.Addr) string {
	return s.prefix("sup", app, ip.String())
}

func (s *Store) authKey(app, requestID string) string {
	return s.prefix("auth", app, requestID)
}

func (s *Store) dedupeKey(eventID string) string {
	return s.prefix("dedupe", eventID)
}

func (s *Store) contribKey(app string, ip netip.Addr) string {
	return s.prefix("contrib", app, ip.String())
}

func (s *Store) fenceKey(app string) string {
	return s.prefix("fence", app)
}

func (s *Store) Healthy(ctx context.Context) error {
	return s.client.Ping(ctx).Err()
}

func (s *Store) Check(ctx context.Context, req event.Request) (event.Decision, error) {
	ip := req.ClientIP
	app := req.Application
	nowMS := time.Now().UnixMilli()
	keys := []string{
		s.banKey(app, ip),
		s.metaKey(app, ip),
		s.modeKey(app),
		s.supKey(app, ip),
	}
	res, err := s.client.EvalSha(ctx, s.checkSHA, keys,
		strconv.FormatInt(nowMS, 10),
		string(s.cfg.DefaultMode),
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
	return d, nil
}

func (s *Store) Observe(ctx context.Context, ev event.Event) error {
	if ev.OwnRejection {
		return nil
	}
	cfg := s.appCfg(ev.Request.Application)
	deny := 0
	if policy.WAFDenyContribution(ev, cfg) {
		deny = 1
	}
	nowMS := time.Now().UnixMilli()
	admissionGen := ""
	admissionAt := int64(0)
	if ev.Admission != nil {
		admissionGen = ev.Admission.Generation
		admissionAt = ev.Admission.At.UnixMilli()
	}
	keys := []string{
		s.dedupeKey(ev.ID),
		s.contribKey(ev.Request.Application, ev.Request.ClientIP),
		s.banKey(ev.Request.Application, ev.Request.ClientIP),
		s.metaKey(ev.Request.Application, ev.Request.ClientIP),
		s.modeKey(ev.Request.Application),
		s.fenceKey(ev.Request.Application),
		s.authKey(ev.Request.Application, ev.Request.RequestID),
	}
	_, err := s.client.EvalSha(ctx, s.observeSHA, keys,
		ev.ID,
		strconv.FormatInt(nowMS, 10),
		strconv.Itoa(deny),
		strconv.Itoa(cfg.WAFDenyWindowSec),
		strconv.Itoa(cfg.WAFDenyThreshold),
		strconv.Itoa(cfg.WAFDenyBanSec),
		string(s.cfg.DefaultMode),
		admissionGen,
		strconv.Itoa(cfg.MaxEventAgeSec*1000),
		strconv.FormatInt(admissionAt, 10),
	).Result()
	return err
}

func (s *Store) RecordAuth(ctx context.Context, receipt policy.AuthReceipt) error {
	verdictID := event.EventID(receipt.Application, receipt.RequestID, event.KindWafVerdict)
	keys := []string{
		s.authKey(receipt.Application, receipt.RequestID),
		s.dedupeKey(verdictID),
	}
	_, err := s.client.EvalSha(ctx, s.recordAuthSHA, keys,
		string(receipt.Outcome),
		receipt.SourceID,
		strconv.FormatInt(time.Now().UnixMilli(), 10),
	).Result()
	return err
}

func (s *Store) Unban(ctx context.Context, req UnbanRequest) (UnbanResult, error) {
	gen := fmt.Sprintf("unban-%d", time.Now().UnixNano())
	pipe := s.client.Pipeline()
	pipe.Del(ctx, s.banKey(req.Application, req.ClientIP))
	pipe.Del(ctx, s.contribKey(req.Application, req.ClientIP))
	if req.Suppression > 0 {
		until := time.Now().Add(req.Suppression).UnixMilli()
		pipe.Set(ctx, s.supKey(req.Application, req.ClientIP), until, req.Suppression)
	}
	pipe.HSet(ctx, s.metaKey(req.Application, req.ClientIP), "generation", gen)
	pipe.Set(ctx, s.fenceKey(req.Application), gen, 24*time.Hour)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return UnbanResult{}, err
	}
	s.mu.Lock()
	s.fenceGen[req.Application] = gen
	s.mu.Unlock()
	return UnbanResult{Generation: gen, SuppressedUntil: time.Now().Add(req.Suppression)}, nil
}

func (s *Store) PolicyRevision(ctx context.Context, app string) (uint64, error) {
	revKey := s.prefix("policy", app) + ":revision"
	rev, err := s.client.Get(ctx, revKey).Uint64()
	if err == redis.Nil {
		return 0, nil
	}
	return rev, err
}

func (s *Store) ValidatePolicyUpdate(ctx context.Context, app string, expectedRevision uint64, cfg policy.Config) (uint64, error) {
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
	meta := s.prefix("policy", app)
	revKey := meta + ":revision"
	rev, err := s.client.Get(ctx, revKey).Uint64()
	if err == redis.Nil {
		rev = 0
	} else if err != nil {
		return 0, err
	}
	if expectedRevision != rev {
		return rev, fmt.Errorf("stale revision: have %d want %d", rev, expectedRevision)
	}
	newRev := rev + 1
	pipe := s.client.Pipeline()
	pipe.Set(ctx, s.modeKey(app), string(mode), 0)
	pipe.Set(ctx, revKey, newRev, 0)
	pipe.Set(ctx, s.fenceKey(app), fmt.Sprintf("rev-%d", newRev), 24*time.Hour)
	_, err = pipe.Exec(ctx)
	return newRev, err
}

func (s *Store) enrichKey(app, requestID string) string {
	return s.prefix("enrich", app, requestID)
}

func (s *Store) Enrich(ctx context.Context, m enrich.Match) error {
	tags, _ := json.Marshal(m.Tags)
	_, err := s.client.EvalSha(ctx, s.enrichSHA, []string{s.enrichKey(m.Application, m.RequestID)},
		strconv.FormatUint(uint64(m.RuleID), 10),
		string(tags),
		strconv.Itoa(m.Severity),
		strconv.Itoa(m.PhaseID),
		"3600",
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
	insp := Inspection{Action: dec.Action, ExpiresAt: dec.ExpiresAt}
	if dec.Admission != nil {
		insp.Revision = dec.Admission.Revision
		insp.Mode = dec.Admission.Mode
		insp.Generation = dec.Admission.Generation
	}
	return insp, nil
}

func (s *Store) List(ctx context.Context, app string, mode event.Mode, cursor string, limit int) (Page, error) {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	return Page{Items: nil, NextCursor: ""}, nil
}
