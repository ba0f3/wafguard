package main

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

var hits atomic.Uint64

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/internal/hits", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, strconv.FormatUint(hits.Load(), 10))
	})
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"marker":"fixture-ok"}`)
	})
	mux.HandleFunc("/marker-response-body", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("X-Fixture-Marker", "marker-response-deny")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"marker":"marker-response-deny"}`)
	})
	mux.HandleFunc("/marker-resp-body-benign", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"tag":"benign-body-marker"}`)
	})
	mux.HandleFunc("/marker-resp-body-evil", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("X-Evil-Marker", "evil-body-marker")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"tag":"evil-body-marker"}`)
	})
	fixturePhase4 := func(w http.ResponseWriter, r *http.Request, body string) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Phase4-Fixture", "constant")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, body)
	}
	mux.HandleFunc("/phase4-body-control", func(w http.ResponseWriter, r *http.Request) {
		fixturePhase4(w, r, `{"tag":"neutral-body"}`)
	})
	mux.HandleFunc("/phase4-body-marker", func(w http.ResponseWriter, r *http.Request) {
		fixturePhase4(w, r, `{"tag":"phase4-only-marker"}`)
	})
	mux.HandleFunc("/phase4-body-delayed", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Phase4-Fixture", "constant")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		time.Sleep(250 * time.Millisecond)
		_, _ = io.WriteString(w, `{"tag":"phase4-only-marker"}`)
	})
	mux.HandleFunc("/phase4-body-chunked", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Phase4-Fixture", "constant")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"tag":"phase4-only-`)
		w.(http.Flusher).Flush()
		time.Sleep(250 * time.Millisecond)
		_, _ = io.WriteString(w, `marker"}`)
	})
	largePad := strings.Repeat("x", 200000)
	mux.HandleFunc("/phase4-body-large-early", func(w http.ResponseWriter, r *http.Request) {
		fixturePhase4(w, r, `{"tag":"phase4-only-marker","pad":"`+largePad+`"}`)
	})
	mux.HandleFunc("/phase4-body-large-late", func(w http.ResponseWriter, r *http.Request) {
		fixturePhase4(w, r, `{"pad":"`+largePad+`","tag":"phase4-only-marker"}`)
	})
	mux.HandleFunc("/fixture-disconnect-precheck", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"marker":"fixture-ok"}`)
	})
	mux.HandleFunc("/fixture-disconnect-verdict", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"marker":"fixture-ok"}`)
	})
	mux.HandleFunc("/fixture-affinity-break", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
	mux.HandleFunc("/fixture-precheck-allow-body", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = io.Copy(w, r.Body)
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(b)
	})
	mux.HandleFunc("/status/", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		code := strings.TrimPrefix(r.URL.Path, "/status/")
		n, err := strconv.Atoi(code)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(n)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.NotFound(w, r)
			return
		}
		hits.Add(1)
		http.NotFound(w, r)
	})
	fmt.Println(http.ListenAndServe(":8081", mux))
}
