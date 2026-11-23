package main

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/dropmorepackets/haproxy-go/pkg/encoding"
	"github.com/dropmorepackets/haproxy-go/spop"
)

type snap struct {
	Message          string `json:"message"`
	Action           string `json:"action,omitempty"`
	Source           string `json:"source,omitempty"`
	InspectionError  bool   `json:"inspection_error,omitempty"`
}

type entry struct {
	Calls     []string `json:"calls"`
	Snapshots []snap   `json:"snapshots"`
}

var (
	mu     sync.RWMutex
	byID   = map[string]*entry{}
	lastID string
)

type rec struct{}

func getOrCreate(id string) *entry {
	e, ok := byID[id]
	if !ok {
		e = &entry{}
		byID[id] = e
	}
	return e
}

func kvString(m *encoding.Message, name string) string {
	k := encoding.AcquireKVEntry()
	defer encoding.ReleaseKVEntry(k)
	for m.KV.Next(k) {
		if k.NameEquals(name) {
			return string(k.ValueBytes())
		}
	}
	return ""
}

func (rec) HandleSPOE(ctx context.Context, w *encoding.ActionWriter, m *encoding.Message) {
	name := string(m.NameBytes())
	rid := kvString(m, "request_id")
	path := kvString(m, "path")
	if rid == "" {
		return
	}
	if name == "check-ban" && strings.Contains(path, "fixture-disconnect-precheck") {
		return
	}
	if name == "waf-verdict" && strings.Contains(path, "fixture-disconnect-verdict") {
		return
	}
	mu.Lock()
	lastID = rid
	e := getOrCreate(rid)
	callsBefore := len(e.Calls)
	e.Calls = append(e.Calls, name)
	if name == "waf-verdict" || name == "observe-response" {
		insp := kvString(m, "request_waf_inspection_error") == "1" || (name == "observe-response" && callsBefore == 0)
		e.Snapshots = append(e.Snapshots, snap{
			Message:         name,
			Action:          kvString(m, "request_waf_action"),
			Source:          kvString(m, "request_waf_source"),
			InspectionError: insp,
		})
	}
	mu.Unlock()

	switch name {
	case "check-ban":
		action := "allow"
		if strings.Contains(path, "fixture-precheck-ban") {
			action = "ban"
		}
		_ = w.SetString(encoding.VarScopeTransaction, "wafguard.action", action)
		_ = w.SetString(encoding.VarScopeTransaction, "wafguard.admission_generation", "rec-gen")
		_ = w.SetInt64(encoding.VarScopeTransaction, "wafguard.admission_at_ms", 1)
		_ = w.SetInt64(encoding.VarScopeTransaction, "wafguard.policy_revision", 1)
		_ = w.SetString(encoding.VarScopeTransaction, "wafguard.behavior_mode", "enforce")
	}
}

func httpHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/v1/requests/"):]
	if id == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodGet:
		mu.RLock()
		e := byID[id]
		mu.RUnlock()
		if e == nil {
			e = &entry{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(e)
	case http.MethodDelete:
		mu.Lock()
		delete(byID, id)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method", http.StatusMethodNotAllowed)
	}
}

func main() {
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/v1/requests/", httpHandler)
		mux.HandleFunc("/v1/last", func(w http.ResponseWriter, r *http.Request) {
			mu.RLock()
			id := lastID
			mu.RUnlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"request_id": id})
		})
		log.Println("recorder http on :18090")
		log.Fatal(http.ListenAndServe(":18090", mux))
	}()

	l, err := net.Listen("tcp", ":12346")
	if err != nil {
		log.Fatal(err)
	}
	log.Println("recorder spop on", l.Addr())
	agent := &spop.Agent{Handler: rec{}, Addr: l.Addr().String()}
	log.Fatal(agent.Serve(l))
}
