package state

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/ba0f3/haproxy-waf-spoe/internal/event"
	"github.com/ba0f3/haproxy-waf-spoe/internal/policy"
	"github.com/redis/go-redis/v9"
)

const boundaryRID = "220e8400-e29b-41d4-a716-446655440001"

// Finding 6: the Lua boundary re-checks that the keys computed by the caller
// still correspond to the admission token and the current policy revision.
func TestRecordAuthRejectsTokenAndRevisionMismatch(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer func() { _ = client.Close() }()
	store, err := New(client, Config{
		Namespace: "boundary", DefaultMode: event.ModeEnforce,
		Apps:       map[string]policy.Config{"sample_app": policy.DefaultConfig()},
		AuthSource: "login-app", AdmissionTTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ip := netip.MustParseAddr("192.0.2.90")
	if _, err := store.Check(ctx, event.Request{Application: "sample_app", ClientIP: ip, RequestID: boundaryRID}); err != nil {
		t.Fatal(err)
	}
	tokenKey := store.admissionKey("sample_app", boundaryRID)
	revText := client.HGet(ctx, tokenKey, "rev").Val()

	call := func(expectedIP, expectedRev string) []interface{} {
		t.Helper()
		keys := []string{
			store.authKey("sample_app", boundaryRID),
			store.dedupeKey(event.EventID("sample_app", boundaryRID, event.KindWafVerdict)),
			store.bruteKey("sample_app", ip), store.banKey("sample_app", ip),
			store.modeKey("sample_app"), tokenKey, store.fenceKey("sample_app"),
			store.metaKey("sample_app", ip), store.supKey("sample_app", ip),
			store.policyRevKey("sample_app"),
		}
		res, err := store.recordAuthScript.Run(ctx, client, keys,
			"failure", "login-app", time.Now().UnixMilli(), 60, 2, 900,
			boundaryRID, "enforce", "login-app", "sample_app", 120000, 86400,
			expectedIP, expectedRev,
		).Result()
		if err != nil {
			t.Fatal(err)
		}
		row, ok := res.([]interface{})
		if !ok || len(row) == 0 {
			t.Fatalf("bad result %v", res)
		}
		return row
	}

	if row := call("192.0.2.91", revText); fmt.Sprint(row[0]) != "fenced" {
		t.Fatalf("IP mismatch accepted: %v", row)
	}
	if row := call(ip.String(), "999"); fmt.Sprint(row[0]) != "fenced" {
		t.Fatalf("revision mismatch accepted: %v", row)
	}
	if client.Exists(ctx, store.authKey("sample_app", boundaryRID)).Val() != 0 {
		t.Fatal("mismatched calls persisted an auth hash")
	}
	if row := call(ip.String(), revText); fmt.Sprint(row[0]) != "ok" {
		t.Fatalf("matching call rejected: %v", row)
	}
	// A policy update between token mint and write fences the stale revision.
	if _, err := store.SetPolicy(ctx, "sample_app", 0, policy.DefaultConfig(), event.ModeEnforce); err != nil {
		t.Fatal(err)
	}
	if err := client.Del(ctx, store.authKey("sample_app", boundaryRID)).Err(); err != nil {
		t.Fatal(err)
	}
	if row := call(ip.String(), revText); fmt.Sprint(row[0]) != "fenced" {
		t.Fatalf("stale revision accepted after policy update: %v", row)
	}
}

// Finding 6: Observe re-checks the admission IP and revision at the Lua
// boundary; a token mutated between check and observe cannot persist a deny.
func TestObserveRejectsTokenAndRevisionMismatch(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer func() { _ = client.Close() }()
	store, err := New(client, Config{
		Namespace: "boundaryobs", DefaultMode: event.ModeEnforce,
		Apps: map[string]policy.Config{"sample_app": {WAFDenyWindowSec: 30, WAFDenyThreshold: 1,
			WAFDenyBanSec: 900, BruteWindowSec: 60, BruteFailures: 2, MaxEventAgeSec: 120, AdmissionTTL: 120}},
		AuthSource: "login-app", AdmissionTTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ip := netip.MustParseAddr("192.0.2.95")
	d, err := store.Check(ctx, event.Request{Application: "sample_app", ClientIP: ip, RequestID: boundaryRID})
	if err != nil {
		t.Fatal(err)
	}
	rev := strconv.FormatUint(d.Admission.Revision, 10)
	call := func(expectedIP, expectedRev string) []interface{} {
		t.Helper()
		eventID := event.EventID("sample_app", boundaryRID, event.KindWafVerdict)
		keys := []string{
			store.dedupeKey(eventID), store.contribKey("sample_app", ip),
			store.banKey("sample_app", ip), store.metaKey("sample_app", ip),
			store.modeKey("sample_app"), store.fenceKey("sample_app"),
			store.authKey("sample_app", boundaryRID), store.bruteKey("sample_app", ip),
			store.admissionKey("sample_app", boundaryRID), store.policyRevKey("sample_app"),
			store.supKey("sample_app", ip), store.scannerKey("sample_app", ip),
			store.banHistoryKey("sample_app", ip), store.banInfoKey("sample_app", ip),
		}
		res, err := store.observeScript.Run(ctx, client, keys,
			eventID, time.Now().UnixMilli(), 1, 30, 1, 900, "enforce", "",
			120000, d.Admission.At.UnixMilli(), 60, 2, boundaryRID,
			"sample_app", expectedIP, "", "", expectedRev,
			60, 30, 2, 604800, 2592000,
		).Result()
		if err != nil {
			t.Fatal(err)
		}
		row, ok := res.([]interface{})
		if !ok || len(row) == 0 {
			t.Fatalf("bad result %v", res)
		}
		return row
	}
	if row := call("192.0.2.96", rev); fmt.Sprint(row[0]) != "fenced" {
		t.Fatalf("IP mismatch accepted by observe: %v", row)
	}
	if row := call(ip.String(), "999"); fmt.Sprint(row[0]) != "fenced" {
		t.Fatalf("revision mismatch accepted by observe: %v", row)
	}
	if client.Get(ctx, "boundaryobs:ban:sample_app:"+ip.String()).Val() != "" {
		t.Fatal("mismatched observe created a ban")
	}
	client.Del(ctx, store.dedupeKey(event.EventID("sample_app", boundaryRID, event.KindWafVerdict)))
	if row := call(ip.String(), rev); fmt.Sprint(row[0]) == "fenced" {
		t.Fatalf("matching observe rejected: %v", row)
	}
	if client.Get(ctx, "boundaryobs:ban:sample_app:"+ip.String()).Val() == "" {
		t.Fatal("matching observe did not ban")
	}
}
