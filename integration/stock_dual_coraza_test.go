//go:build integration

package integration

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func haproxyCorazaServerStat(t *testing.T, server string) (stot int, up bool) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", "127.0.0.1:19999", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = fmt.Fprintf(conn, "show stat\n")
	sc := bufio.NewScanner(conn)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), ",")
		if len(fields) < 18 || fields[0] != "coraza-spoa" || fields[1] != server {
			continue
		}
		for _, idx := range []int{7, 8} {
			if n, err := strconv.Atoi(fields[idx]); err == nil {
				stot = n
				break
			}
		}
		up = fields[17] == "UP"
		return
	}
	return 0, false
}

func TestStockDualCorazaRoundRobinCorrelation(t *testing.T) {
	if os.Getenv("WAF_RECORDER_BODY") == "" {
		t.Skip("set WAF_RECORDER_BODY=1 with dual coraza matrix")
	}
	requireCompose(t)
	client := &http.Client{Timeout: 3 * time.Second}

	c1Before, c1Up := haproxyCorazaServerStat(t, "c1")
	c2Before, c2Up := haproxyCorazaServerStat(t, "c2")
	if !c1Up || !c2Up {
		t.Fatalf("coraza backends UP c1=%v c2=%v", c1Up, c2Up)
	}
	for i := 0; i < 30; i++ {
		resp, err := client.Get(haproxyURL() + "/ok")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("ok %d", resp.StatusCode)
		}
	}
	c1After, _ := haproxyCorazaServerStat(t, "c1")
	c2After, _ := haproxyCorazaServerStat(t, "c2")
	if c1After <= c1Before {
		t.Fatalf("primary coraza stot %d->%d want increase", c1Before, c1After)
	}
	if c2After > c2Before {
		t.Logf("backup c2 also served stot %d->%d", c2Before, c2After)
	} else {
		t.Log("c2 backup: request/response cache pinned on c1; c2 hot-standby (see docs/evidence)")
	}

	resp, err := client.Get(haproxyURL() + "/marker-response-body")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("response deny got %d want 403 (req/res stick)", resp.StatusCode)
	}
}
