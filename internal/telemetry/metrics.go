package telemetry

import (
	"net/http"
	"sync"
	"time"

	"github.com/ba0f3/haproxy-waf-spoe/internal/spoa"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	ops      *prometheus.HistogramVec
	events   *prometheus.CounterVec
	drops    *prometheus.CounterVec
	redisErr *prometheus.CounterVec
	inflight prometheus.Gauge
}

func New(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		ops: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "wafguard_spoe_operation_duration_seconds",
			Buckets: prometheus.DefBuckets,
		}, []string{"operation", "result"}),
		events: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "wafguard_events_total"}, []string{"kind", "result"}),
		drops:  prometheus.NewCounterVec(prometheus.CounterOpts{Name: "wafguard_events_dropped_total"}, []string{"reason"}),
		redisErr: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "wafguard_redis_failures_total"}, []string{"operation"}),
		inflight: prometheus.NewGauge(prometheus.GaugeOpts{Name: "wafguard_requests_inflight"}),
	}
	reg.MustRegister(m.ops, m.events, m.drops, m.redisErr, m.inflight)
	return m
}

func (m *Metrics) RecordOperation(kind, result string, d time.Duration) {
	m.ops.WithLabelValues(kind, result).Observe(d.Seconds())
}
func (m *Metrics) RecordEvent(kind, result string) { m.events.WithLabelValues(kind, result).Inc() }
func (m *Metrics) RecordDrop(reason string)        { m.drops.WithLabelValues(reason).Inc() }
func (m *Metrics) RecordRedis(operation string)    { m.redisErr.WithLabelValues(operation).Inc() }
func (m *Metrics) IncInflight()                    { m.inflight.Inc() }
func (m *Metrics) DecInflight()                    { m.inflight.Dec() }

func (m *Metrics) BindHandler(h *spoa.Handler) *spoa.Handler {
	h.Telemetry = m
	return h
}

type Health struct {
	mu    sync.RWMutex
	store func() error
}

func (h *Health) SetStoreCheck(fn func() error) { h.store = fn }

func (h *Health) Handler(m *Metrics) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if h.store != nil {
			if err := h.store(); err != nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte("degraded"))
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	return mux
}

