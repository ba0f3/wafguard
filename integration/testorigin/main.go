package main

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
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
