package main

import (
	"context"
	"log"
	"net"
	"sync"

	"github.com/dropmorepackets/haproxy-go/pkg/encoding"
	"github.com/dropmorepackets/haproxy-go/spop"
)

var (
	mu   sync.RWMutex
	byID = map[string][]string{}
)

type rec struct{}

func (rec) HandleSPOE(ctx context.Context, w *encoding.ActionWriter, m *encoding.Message) {
	name := string(m.NameBytes())
	var rid string
	k := encoding.AcquireKVEntry()
	defer encoding.ReleaseKVEntry(k)
	for m.KV.Next(k) {
		if k.NameEquals("request_id") {
			rid = string(k.ValueBytes())
			break
		}
	}
	if rid == "" {
		return
	}
	mu.Lock()
	byID[rid] = append(byID[rid], name)
	mu.Unlock()
	if name == "check-ban" {
		_ = w.SetString(encoding.VarScopeTransaction, "wafguard.action", "allow")
	}
}

func main() {
	l, err := net.Listen("tcp", ":12346")
	if err != nil {
		log.Fatal(err)
	}
	log.Println("recorder on", l.Addr())
	_ = spop.ListenAndServe(l.Addr().String(), rec{})
}

