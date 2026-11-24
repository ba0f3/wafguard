package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ba0f3/haproxy-waf-spoe/internal/admin"
	"github.com/ba0f3/haproxy-waf-spoe/internal/enrich"
	"github.com/ba0f3/haproxy-waf-spoe/internal/event"
	"github.com/ba0f3/haproxy-waf-spoe/internal/logging"
	"github.com/ba0f3/haproxy-waf-spoe/internal/policy"
	"github.com/ba0f3/haproxy-waf-spoe/internal/spoa"
	"github.com/ba0f3/haproxy-waf-spoe/internal/state"
	"github.com/ba0f3/haproxy-waf-spoe/internal/telemetry"
	"github.com/dropmorepackets/haproxy-go/spop"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
)

type fileConfig struct {
	Version                  int                      `json:"version"`
	SPOPListen               string                   `json:"spop_listen"`
	AdminRead                string                   `json:"admin_read_socket"`
	AdminWrite               string                   `json:"admin_write_socket"`
	Metrics                  string                   `json:"metrics_listen"`
	Redis                    redisOptions             `json:"redis"`
	Limits                   limitsConfig             `json:"limits"`
	Apps                     map[string]policy.Config `json:"apps"`
	DefaultMode              string                   `json:"default_mode"`
	AdmissionTTLSeconds      int                      `json:"admission_ttl_seconds"`
	AdminHTTPWrite           string                   `json:"admin_http_write"`
	AdminHTTPWriteToken      string                   `json:"admin_http_write_token"`
	AdminHTTPAuth            string                   `json:"admin_http_auth"`
	AdminHTTPAuthSource      string                   `json:"admin_http_auth_source"`
	AdminHTTPAuthApplication string                   `json:"admin_http_auth_application"`
	AdminHTTPAuthToken       string                   `json:"admin_http_auth_token"`
	EnrichLogFile            string                   `json:"enrich_log_file"`
	EnrichApplication        string                   `json:"enrich_application"`
	LogLevel                 string                   `json:"log_level,omitempty"`
}

type redisOptions struct {
	Addr     string           `json:"addr"`
	Username string           `json:"username,omitempty"`
	Password string           `json:"password,omitempty"`
	DB       int              `json:"db,omitempty"`
	Sentinel *sentinelOptions `json:"sentinel,omitempty"`
}

type sentinelOptions struct {
	MasterName string   `json:"master_name"`
	Addrs      []string `json:"addrs"`
	Username   string   `json:"username,omitempty"`
	Password   string   `json:"password,omitempty"`
}

type limitsConfig struct {
	MaxInflight int      `json:"max_inflight"`
	AllowedApps []string `json:"allowed_apps"`
}

type runtimeConfig struct {
	file fileConfig
}

func loadConfig(r io.Reader) (runtimeConfig, error) {
	var fc fileConfig
	if err := json.NewDecoder(r).Decode(&fc); err != nil {
		return runtimeConfig{}, err
	}
	if fc.Version != 1 {
		return runtimeConfig{}, fmt.Errorf("unsupported config version %d", fc.Version)
	}
	if fc.SPOPListen == "" {
		return runtimeConfig{}, errors.New("spop_listen required")
	}
	if fc.Redis.Sentinel != nil && len(fc.Redis.Sentinel.Addrs) > 0 {
		if fc.Redis.Sentinel.MasterName == "" {
			return runtimeConfig{}, errors.New("redis.sentinel.master_name required")
		}
	} else if fc.Redis.Addr == "" {
		return runtimeConfig{}, errors.New("redis.addr required")
	}
	if fc.AdmissionTTLSeconds > 0 && fc.AdmissionTTLSeconds < 30 {
		return runtimeConfig{}, errors.New("admission_ttl below request timeout")
	}
	if fc.AdminRead != "" && fc.AdminRead == fc.AdminWrite {
		return runtimeConfig{}, errors.New("admin read/write socket collision")
	}
	// HTTP write/admin listeners are unauthenticated by default in Redis and
	// Coraza; require an explicit token so a bind address cannot expose writes.
	if fc.AdminHTTPWrite != "" && fc.AdminHTTPWriteToken == "" {
		return runtimeConfig{}, errors.New("admin_http_write_token required with admin_http_write")
	}
	if fc.AdminHTTPAuth != "" && fc.AdminHTTPAuthToken == "" {
		return runtimeConfig{}, errors.New("admin_http_auth_token required with admin_http_auth")
	}
	return runtimeConfig{file: fc}, nil
}

// Redis I/O is bounded well inside the SPOE handler budget (450 ms) so a
// stalled socket cannot pin a request past HAProxy's processing timeout.
const (
	redisDialTimeout     = 150 * time.Millisecond
	redisIOTimeout       = 250 * time.Millisecond
	redisPoolTimeout     = 250 * time.Millisecond
	redisMaxRetries      = 2
	redisRetryMinBackoff = 5 * time.Millisecond
	redisRetryMaxBackoff = 40 * time.Millisecond
)

func newRedisOptions(ro redisOptions) *redis.Options {
	return &redis.Options{
		Addr: ro.Addr, Username: ro.Username, Password: ro.Password, DB: ro.DB,
		DialTimeout: redisDialTimeout, ReadTimeout: redisIOTimeout,
		WriteTimeout: redisIOTimeout, PoolTimeout: redisPoolTimeout,
		MaxRetries: redisMaxRetries, MinRetryBackoff: redisRetryMinBackoff,
		MaxRetryBackoff: redisRetryMaxBackoff, ContextTimeoutEnabled: true,
	}
}

func newFailoverOptions(ro redisOptions) *redis.FailoverOptions {
	opt := &redis.FailoverOptions{
		Username: ro.Username, Password: ro.Password, DB: ro.DB,
		DialTimeout: redisDialTimeout, ReadTimeout: redisIOTimeout,
		WriteTimeout: redisIOTimeout, PoolTimeout: redisPoolTimeout,
		MaxRetries: redisMaxRetries, MinRetryBackoff: redisRetryMinBackoff,
		MaxRetryBackoff: redisRetryMaxBackoff, ContextTimeoutEnabled: true,
	}
	if ro.Sentinel != nil {
		opt.MasterName = ro.Sentinel.MasterName
		opt.SentinelAddrs = ro.Sentinel.Addrs
		opt.SentinelUsername = ro.Sentinel.Username
		opt.SentinelPassword = ro.Sentinel.Password
	}
	return opt
}

func newRedisClient(ro redisOptions) redis.UniversalClient {
	if ro.Sentinel != nil && ro.Sentinel.MasterName != "" && len(ro.Sentinel.Addrs) > 0 {
		return redis.NewFailoverClient(newFailoverOptions(ro))
	}
	return redis.NewClient(newRedisOptions(ro))
}

func run(ctx context.Context, cfg runtimeConfig) error {
	fc := cfg.file
	logging.SetLevel(logging.ParseLevel(fc.LogLevel))
	authSource := fc.AdminHTTPAuthSource
	if authSource == "" {
		authSource = "login-app"
	}
	redisTarget := fc.Redis.Addr
	if fc.Redis.Sentinel != nil && len(fc.Redis.Sentinel.Addrs) > 0 {
		redisTarget = fc.Redis.Sentinel.MasterName + "@" + strings.Join(fc.Redis.Sentinel.Addrs, ",")
	}
	mode := event.ModeObserve
	if fc.DefaultMode == "enforce" {
		mode = event.ModeEnforce
	}
	logging.Infof("wafguard starting mode=%s redis=%s spop=%s metrics=%s", mode, redisTarget, fc.SPOPListen, fc.Metrics)
	client := newRedisClient(fc.Redis)
	pctx, pcancel := context.WithTimeout(context.Background(), redisIOTimeout)
	pingErr := client.Ping(pctx).Err()
	pcancel()
	if pingErr != nil {
		logging.Infof("redis ping failed target=%s err=%v (continuing; requests will degrade)", redisTarget, pingErr)
	} else {
		logging.Infof("redis ok target=%s", redisTarget)
	}
	store, err := state.New(client, state.Config{
		Namespace:       "wg",
		DefaultMode:     mode,
		Apps:            fc.Apps,
		AuthSource:      authSource,
		AuthApplication: fc.AdminHTTPAuthApplication,
		AdmissionTTL:    time.Duration(fc.AdmissionTTLSeconds) * time.Second,
	})
	if err != nil {
		return err
	}
	allowed := map[string]struct{}{}
	for _, a := range fc.Limits.AllowedApps {
		allowed[a] = struct{}{}
	}
	h := spoa.NewHandler(store, event.Limits{AllowedApps: allowed, MaxPathLen: 1024, MaxRuleIDs: 64, MaxCategoryLen: 64})
	if fc.Limits.MaxInflight > 0 {
		h = h.WithMaxInflight(fc.Limits.MaxInflight)
	}
	reg := prometheus.NewRegistry()
	metrics := telemetry.New(reg)
	metrics.BindHandler(h)
	health := &telemetry.Health{}
	health.SetStoreCheck(func() error {
		cctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		return store.Healthy(cctx)
	})

	agent := &spop.Agent{Handler: h, BaseContext: ctx, Addr: fc.SPOPListen}
	l, err := net.Listen("tcp", fc.SPOPListen)
	if err != nil {
		return err
	}
	logging.Infof("spoe listening addr=%s", l.Addr())
	go func() { _ = agent.Serve(l) }()

	if fc.Metrics != "" {
		logging.Infof("metrics listening addr=%s readyz=%s/readyz", fc.Metrics, fc.Metrics)
		go func() {
			_ = http.ListenAndServe(fc.Metrics, health.Handler(reg))
		}()
	}
	if fc.AdminWrite != "" {
		logging.Infof("admin listening addr=%s kind=unix-write", fc.AdminWrite)
		go serveUnix(fc.AdminWrite, admin.New(store, admin.Access{Role: admin.Write}))
	}
	if fc.AdminRead != "" {
		logging.Infof("admin listening addr=%s kind=unix-read", fc.AdminRead)
		go serveUnix(fc.AdminRead, admin.New(store, admin.Access{Role: admin.Read}))
	}
	if fc.AdminHTTPWrite != "" {
		logging.Infof("admin listening addr=%s kind=http-write", fc.AdminHTTPWrite)
		writeH := admin.New(store, admin.Access{Role: admin.Write})
		go func() {
			_ = http.ListenAndServe(fc.AdminHTTPWrite, withAuthToken(fc.AdminHTTPWriteToken, writeH))
		}()
	}
	if fc.AdminHTTPAuth != "" {
		logging.Infof("admin listening addr=%s kind=http-auth", fc.AdminHTTPAuth)
		authH := admin.New(store, admin.Access{
			Role: admin.Auth, SourceID: authSource, Application: store.AuthApplication(),
		})
		go func() {
			_ = http.ListenAndServe(fc.AdminHTTPAuth, withAuthToken(fc.AdminHTTPAuthToken, authH))
		}()
	}
	if fc.EnrichLogFile != "" {
		app := fc.EnrichApplication
		if app == "" {
			app = "sample_app"
		}
		src := enrich.Source{Application: app}
		lim := enrich.Limits{}
		go enrich.TailJSONL(ctx, fc.EnrichLogFile, src, lim, store.Enrich)
	}
	<-ctx.Done()
	return closeListener(l)
}

// spop.Agent.Serve closes the listener on context cancellation too, so a
// second close from run() is expected and must not fail shutdown.
func closeListener(l net.Listener) error {
	if err := l.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

func serveUnix(path string, h http.Handler) {
	_ = os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		logging.Infof("admin listen %s: %v", path, err)
		return
	}
	// Permissioned Unix socket: owner-only, never group/world writable.
	_ = os.Chmod(path, 0600)
	_ = http.Serve(l, h)
}

func withAuthToken(token string, h http.Handler) http.Handler {
	if token == "" {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("X-Wafguard-Auth-Token")
		if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func main() {
	configPath := flag.String("config", "", "config file")
	flag.Parse()
	if *configPath == "" {
		log.Fatal("-config required")
	}
	f, err := os.Open(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	cfg, err := loadConfig(f)
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Fatal(err)
	}
}
