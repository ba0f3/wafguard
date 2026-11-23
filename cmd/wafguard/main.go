package main

import (
	"context"
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
	"syscall"
	"time"

	"github.com/ba0f3/haproxy-waf-spoe/internal/admin"
	"github.com/ba0f3/haproxy-waf-spoe/internal/enrich"
	"github.com/ba0f3/haproxy-waf-spoe/internal/event"
	"github.com/ba0f3/haproxy-waf-spoe/internal/policy"
	"github.com/ba0f3/haproxy-waf-spoe/internal/spoa"
	"github.com/ba0f3/haproxy-waf-spoe/internal/state"
	"github.com/ba0f3/haproxy-waf-spoe/internal/telemetry"
	"github.com/dropmorepackets/haproxy-go/spop"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
)

type fileConfig struct {
	Version    int `json:"version"`
	SPOPListen string `json:"spop_listen"`
	AdminRead  string `json:"admin_read_socket"`
	AdminWrite string `json:"admin_write_socket"`
	Metrics    string `json:"metrics_listen"`
	Redis      redisOptions `json:"redis"`
	Limits     limitsConfig `json:"limits"`
	Apps       map[string]policy.Config `json:"apps"`
	DefaultMode string `json:"default_mode"`
	AdmissionTTLSeconds int    `json:"admission_ttl_seconds"`
	AdminHTTPWrite      string   `json:"admin_http_write"`
	AdminHTTPAuth       string   `json:"admin_http_auth"`
	AdminHTTPAuthSource string   `json:"admin_http_auth_source"`
	AdminHTTPAuthToken  string   `json:"admin_http_auth_token"`
	EnrichLogFile       string   `json:"enrich_log_file"`
	EnrichApplication   string   `json:"enrich_application"`
}

type redisOptions struct {
	Addr     string          `json:"addr"`
	Sentinel *sentinelOptions `json:"sentinel,omitempty"`
}

type sentinelOptions struct {
	MasterName string   `json:"master_name"`
	Addrs      []string `json:"addrs"`
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
	return runtimeConfig{file: fc}, nil
}

func newRedisClient(ro redisOptions) redis.UniversalClient {
	if ro.Sentinel != nil && ro.Sentinel.MasterName != "" && len(ro.Sentinel.Addrs) > 0 {
		return redis.NewFailoverClient(&redis.FailoverOptions{
			MasterName:    ro.Sentinel.MasterName,
			SentinelAddrs: ro.Sentinel.Addrs,
		})
	}
	return redis.NewClient(&redis.Options{Addr: ro.Addr})
}

func run(ctx context.Context, cfg runtimeConfig) error {
	fc := cfg.file
	client := newRedisClient(fc.Redis)
	mode := event.ModeObserve
	if fc.DefaultMode == "enforce" {
		mode = event.ModeEnforce
	}
	store, err := state.New(client, state.Config{
		Namespace:   "wg",
		DefaultMode: mode,
		Apps:        fc.Apps,
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
	go func() { _ = agent.Serve(l) }()

	if fc.Metrics != "" {
		go func() {
			_ = http.ListenAndServe(fc.Metrics, health.Handler(reg))
		}()
	}
	if fc.AdminWrite != "" {
		go serveUnix(fc.AdminWrite, admin.New(store, admin.Access{Role: admin.Write}))
	}
	if fc.AdminRead != "" {
		go serveUnix(fc.AdminRead, admin.New(store, admin.Access{Role: admin.Read}))
	}
	if fc.AdminHTTPWrite != "" {
		go func() {
			_ = http.ListenAndServe(fc.AdminHTTPWrite, admin.New(store, admin.Access{Role: admin.Write}))
		}()
	}
	if fc.AdminHTTPAuth != "" {
		src := fc.AdminHTTPAuthSource
		if src == "" {
			src = "http-auth"
		}
		authH := admin.New(store, admin.Access{Role: admin.Auth, SourceID: src})
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
	return l.Close()
}

func serveUnix(path string, h http.Handler) {
	_ = os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		log.Printf("admin listen %s: %v", path, err)
		return
	}
	_ = http.Serve(l, h)
}

func withAuthToken(token string, h http.Handler) http.Handler {
	if token == "" {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Wafguard-Auth-Token") != token {
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

