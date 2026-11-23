//go:build integration

package integration

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func TestObserveResponsePhase(t *testing.T) {
	requireCompose(t)
	resp, err := http.Get(haproxyURL() + "/.env")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("probe status %d", resp.StatusCode)
	}
	ctx := context.Background()
	cli := redis.NewClient(&redis.Options{Addr: redisAddr()})
	deadline := time.Now().Add(10 * time.Second)
	var found bool
	for time.Now().Before(deadline) {
		keys, err := cli.Keys(ctx, "wg:dedupe:sample_app*").Result()
		if err == nil {
			for _, k := range keys {
				if strings.Contains(k, "observe-response") {
					found = true
					break
				}
			}
		}
		if found {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !found {
		t.Fatal("no observe-response dedupe record")
	}
}
