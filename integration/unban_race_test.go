//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func adminWriteToken() string {
	if t := os.Getenv("WAF_ADMIN_TOKEN"); t != "" {
		return t
	}
	return "operator-lab-only"
}

func adminWriteURL() string {
	if u := os.Getenv("WAF_ADMIN_URL"); u != "" {
		return u
	}
	return "http://127.0.0.1:19200"
}

// Bounded HTTP unban across two wafguard instances (A/B HAProxy) sharing Redis.
func TestHTTPUnbanRaceTwoWafguards(t *testing.T) {
	if os.Getenv("WAF_UNBAN_RACE") == "" {
		t.Skip("set WAF_UNBAN_RACE=1 with rollout admin_http_write up")
	}
	requireRollout(t)
	client := &http.Client{Timeout: 3 * time.Second}
	ip := labClientIP(t)

	for i := 0; i < 3; i++ {
		corazaDeny(t, haproxyURL())
	}
	resp, err := client.Get(haproxyBURL() + "/ok")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("want ban on B got %d", resp.StatusCode)
	}

	body, _ := json.Marshal(map[string]string{
		"client_ip":    ip,
		"operation_id": "unban-race-1",
	})
	unbanReq, _ := http.NewRequest(http.MethodPost, adminWriteURL()+"/v1/apps/sample_app/unban", bytes.NewReader(body))
	unbanReq.Header.Set("Content-Type", "application/json")
	unbanReq.Header.Set("X-Wafguard-Auth-Token", adminWriteToken())
	r, err := client.Do(unbanReq)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode >= 300 {
		t.Fatalf("unban %d", r.StatusCode)
	}

	r2, err := client.Get(haproxyBURL() + "/ok")
	if err != nil {
		t.Fatal(err)
	}
	r2.Body.Close()
	if r2.StatusCode != 200 {
		t.Fatalf("after unban B got %d", r2.StatusCode)
	}
	r3, err := client.Get(haproxyURL() + "/ok")
	if err != nil {
		t.Fatal(err)
	}
	r3.Body.Close()
	if r3.StatusCode != 200 {
		t.Fatalf("after unban A got %d", r3.StatusCode)
	}

	corazaDeny(t, haproxyURL())
	r4, err := client.Get(haproxyBURL() + "/ok")
	if err != nil {
		t.Fatal(err)
	}
	r4.Body.Close()
	if r4.StatusCode != 200 {
		t.Fatalf("one post-unban deny should not re-ban immediately, got %d", r4.StatusCode)
	}
}

// Unban while a late Coraza deny is in flight must not re-ban (fence/unban release).
func TestHTTPUnbanHeldAdmissionRelease(t *testing.T) {
	if os.Getenv("WAF_UNBAN_RACE") == "" {
		t.Skip("set WAF_UNBAN_RACE=1 with rollout admin_http_write up")
	}
	requireRollout(t)
	client := &http.Client{Timeout: 5 * time.Second}
	ip := labClientIP(t)
	clearClientBanState(t)

	for i := 0; i < 3; i++ {
		corazaDeny(t, haproxyURL())
	}
	if _, err := client.Get(haproxyBURL() + "/ok"); err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(map[string]string{"client_ip": ip, "operation_id": "unban-held-1"})
	unbanReq, _ := http.NewRequest(http.MethodPost, adminWriteURL()+"/v1/apps/sample_app/unban", bytes.NewReader(body))
	unbanReq.Header.Set("Content-Type", "application/json")
	unbanReq.Header.Set("X-Wafguard-Auth-Token", adminWriteToken())

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		time.Sleep(60 * time.Millisecond)
		corazaDeny(t, haproxyURL())
	}()
	go func() {
		defer wg.Done()
		r, err := client.Do(unbanReq)
		if err != nil {
			t.Error(err)
			return
		}
		r.Body.Close()
		if r.StatusCode >= 300 {
			t.Errorf("unban %d", r.StatusCode)
		}
	}()
	wg.Wait()
	time.Sleep(200 * time.Millisecond)

	ctx := context.Background()
	c := redis.NewClient(&redis.Options{Addr: redisAddr()})
	ban, _ := c.Get(ctx, "wg:ban:sample_app:"+ip).Result()
	if ban != "" {
		t.Fatalf("held admission release left ban key %q", ban)
	}
	resp, err := client.Get(haproxyBURL() + "/ok")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("replica B after held release got %d", resp.StatusCode)
	}
}
