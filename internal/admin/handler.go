package admin

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"

	"github.com/ba0f3/haproxy-waf-spoe/internal/event"
	"github.com/ba0f3/haproxy-waf-spoe/internal/policy"
	"github.com/ba0f3/haproxy-waf-spoe/internal/state"
)

type Role int

const (
	Read Role = iota
	Write
	Auth
)

type Access struct {
	Role        Role
	SourceID    string
	Application string
}

func New(store *state.Store, access Access) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/apps/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/v1/apps/")
		parts := strings.Split(path, "/")
		if len(parts) < 1 || parts[0] == "" {
			http.NotFound(w, r)
			return
		}
		app := parts[0]
		if access.Application != "" && access.Application != app {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		switch {
		case len(parts) == 2 && parts[1] == "unban" && r.Method == http.MethodPost:
			if access.Role != Write {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			var body struct {
				ClientIP    string `json:"client_ip"`
				OperationID string `json:"operation_id"`
				Reason      string `json:"reason"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			ip, err := netip.ParseAddr(body.ClientIP)
			if err != nil {
				http.Error(w, "bad ip", http.StatusBadRequest)
				return
			}
			res, err := store.Unban(r.Context(), state.UnbanRequest{
				Application: app,
				ClientIP:    ip,
				Mode:        event.ModeEnforce,
				OperationID: body.OperationID,
				Reason:      body.Reason,
			})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(res)
		case len(parts) == 2 && parts[1] == "auth-outcomes" && r.Method == http.MethodPost:
			if access.Role != Auth {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			var rcpt policy.AuthReceipt
			if err := json.NewDecoder(r.Body).Decode(&rcpt); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			rcpt.Application = app
			rcpt.SourceID = access.SourceID
			if err := store.RecordAuth(r.Context(), rcpt); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case len(parts) >= 2 && parts[1] == "decisions" && r.Method == http.MethodGet:
			if access.Role != Read && access.Role != Write {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			if len(parts) == 3 {
				ip, err := netip.ParseAddr(parts[2])
				if err != nil {
					http.Error(w, "bad ip", http.StatusBadRequest)
					return
				}
				insp, err := store.Inspect(r.Context(), app, event.ModeEnforce, ip)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				_ = json.NewEncoder(w).Encode(insp)
			}
		default:
			http.NotFound(w, r)
		}
	})
	return mux
}

