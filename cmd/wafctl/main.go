// wafctl manages a running wafguard through its admin HTTP API.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type client struct {
	base  string
	token string
	app   string
	http  *http.Client
}

func (c *client) do(method, path string, body any) ([]byte, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Wafguard-Auth-Token", c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return data, nil
}

func (c *client) appPath(suffix string) string {
	return "/v1/apps/" + url.PathEscape(c.app) + suffix
}

func printRaw(out io.Writer, data []byte, asJSON bool) error {
	if asJSON {
		_, err := out.Write(data)
		return err
	}
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		_, err = fmt.Fprintf(out, "%s", data)
		return err
	}
	switch x := v.(type) {
	case map[string]any:
		for _, k := range sortedKeys(x) {
			_, _ = fmt.Fprintf(out, "%s=%v\n", k, x[k])
		}
	case []any:
		for _, item := range x {
			_, _ = fmt.Fprintln(out, item)
		}
	default:
		_, _ = fmt.Fprintln(out, v)
	}
	return nil
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

func run(args []string, c *client, out io.Writer, asJSON bool) error {
	if len(args) == 0 {
		return errors.New("usage: wafctl <status|policy|mode|whitelist|unban|inspect>")
	}
	switch args[0] {
	case "status":
		data, err := c.do(http.MethodGet, c.appPath("/status"), nil)
		if err != nil {
			return err
		}
		return printRaw(out, data, asJSON)
	case "policy":
		if len(args) < 2 || args[1] != "get" {
			return errors.New("usage: wafctl policy get")
		}
		data, err := c.do(http.MethodGet, c.appPath("/policy"), nil)
		if err != nil {
			return err
		}
		return printRaw(out, data, asJSON)
	case "mode":
		if len(args) < 2 {
			return errors.New("usage: wafctl mode get|set <observe|enforce>")
		}
		if args[1] == "get" {
			data, err := c.do(http.MethodGet, c.appPath("/status"), nil)
			if err != nil {
				return err
			}
			var st struct {
				Mode string `json:"mode"`
			}
			if err := json.Unmarshal(data, &st); err != nil {
				return err
			}
			_, _ = fmt.Fprintln(out, st.Mode)
			return nil
		}
		if args[1] != "set" || len(args) != 3 {
			return errors.New("usage: wafctl mode set <observe|enforce>")
		}
		mode := args[2]
		if mode != "observe" && mode != "enforce" {
			return fmt.Errorf("invalid mode %q", mode)
		}
		data, err := c.do(http.MethodGet, c.appPath("/policy"), nil)
		if err != nil {
			return err
		}
		var pol struct {
			Revision uint64 `json:"revision"`
			Config   any    `json:"config"`
		}
		if err := json.Unmarshal(data, &pol); err != nil {
			return err
		}
		result, err := c.do(http.MethodPut, c.appPath("/policy"), map[string]any{
			"expected_revision": pol.Revision,
			"mode":              mode,
			"config":            pol.Config,
		})
		if err != nil {
			return err
		}
		return printRaw(out, result, asJSON)
	case "whitelist":
		if len(args) < 2 {
			return errors.New("usage: wafctl whitelist <list|add|remove> [ip/cidr ...]")
		}
		method := http.MethodGet
		var body any
		switch args[1] {
		case "list":
		case "add", "remove":
			if len(args) < 3 {
				return errors.New("whitelist add/remove needs at least one IP or CIDR")
			}
			if args[1] == "add" {
				method = http.MethodPost
			} else {
				method = http.MethodDelete
			}
			body = map[string]any{"ips": args[2:]}
		default:
			return fmt.Errorf("unknown whitelist command %q", args[1])
		}
		data, err := c.do(method, c.appPath("/whitelist"), body)
		if err != nil {
			return err
		}
		return printRaw(out, data, asJSON)
	case "unban":
		if len(args) < 2 {
			return errors.New("usage: wafctl unban <ip> [reason]")
		}
		reason := "manual unban via wafctl"
		if len(args) > 2 {
			reason = strings.Join(args[2:], " ")
		}
		result, err := c.do(http.MethodPost, c.appPath("/unban"), map[string]any{
			"client_ip":    args[1],
			"operation_id": fmt.Sprintf("wafctl-%d", time.Now().UnixNano()),
			"reason":       reason,
		})
		if err != nil {
			return err
		}
		return printRaw(out, result, asJSON)
	case "inspect":
		if len(args) != 2 {
			return errors.New("usage: wafctl inspect <ip>")
		}
		data, err := c.do(http.MethodGet, c.appPath("/decisions/"+url.PathEscape(args[1])), nil)
		if err != nil {
			return err
		}
		return printRaw(out, data, asJSON)
	}
	return fmt.Errorf("unknown command %q", args[0])
}

func loadEnvFile(path string) map[string]string {
	vals := map[string]string{}
	f, err := os.Open(path)
	if err != nil {
		return vals
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			vals[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return vals
}

func main() {
	endpoint := flag.String("endpoint", "", "admin API base URL")
	token := flag.String("token", "", "admin write token")
	app := flag.String("app", "", "application name")
	asJSON := flag.Bool("json", false, "print raw JSON")
	flag.Parse()

	env := loadEnvFile(".env")
	get := func(key, fallback string) string {
		if v := os.Getenv(key); v != "" {
			return v
		}
		if v := env[key]; v != "" {
			return v
		}
		return fallback
	}
	if *endpoint == "" {
		*endpoint = get("WAFGUARD_ENDPOINT", "http://127.0.0.1:19200")
	}
	if *token == "" {
		*token = get("WAFGUARD_TOKEN", "")
	}
	if *app == "" {
		*app = get("WAFGUARD_APP", "sample_app")
	}
	c := &client{
		base: strings.TrimRight(*endpoint, "/"), token: *token, app: *app,
		http: &http.Client{Timeout: 10 * time.Second},
	}
	if err := run(flag.Args(), c, os.Stdout, *asJSON); err != nil {
		fmt.Fprintln(os.Stderr, "wafctl:", err)
		os.Exit(1)
	}
}
