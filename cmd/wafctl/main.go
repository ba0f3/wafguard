// wafctl manages a running wafguard through its admin HTTP API.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ba0f3/haproxy-waf-spoe/internal/policy"
	"github.com/spf13/cobra"
)

type client struct {
	base        string
	metricsBase string
	token       string
	app         string
	http        *http.Client
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

func (c *client) getPolicy() (map[string]any, uint64, error) {
	data, err := c.do(http.MethodGet, c.appPath("/policy"), nil)
	if err != nil {
		return nil, 0, err
	}
	var pol struct {
		Revision uint64         `json:"revision"`
		Config   map[string]any `json:"config"`
	}
	if err := json.Unmarshal(data, &pol); err != nil {
		return nil, 0, err
	}
	return pol.Config, pol.Revision, nil
}

func (c *client) putPolicy(cfg map[string]any, rev uint64, mode string) ([]byte, error) {
	body := map[string]any{"expected_revision": rev, "config": cfg}
	if mode != "" {
		body["mode"] = mode
	}
	return c.do(http.MethodPut, c.appPath("/policy"), body)
}

func printValue(out io.Writer, v any) error {
	switch x := v.(type) {
	case []any:
		parts := make([]string, len(x))
		for i, item := range x {
			parts[i] = fmt.Sprint(item)
		}
		_, err := fmt.Fprintln(out, strings.Join(parts, ","))
		return err
	default:
		_, err := fmt.Fprintln(out, v)
		return err
	}
}

func printJSONOrValue(out io.Writer, data []byte, asJSON bool) error {
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
			_, _ = fmt.Fprintf(out, "%s=", k)
			if err := printValue(out, x[k]); err != nil {
				return err
			}
		}
	default:
		return printValue(out, v)
	}
	return nil
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// configFieldKind reads the JSON tag and Go kind straight from policy.Config so
// the CLI never drifts from the server's config schema.
func configFieldKind(key string) (string, bool) {
	t := reflect.TypeOf(policy.Config{})
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := strings.Split(f.Tag.Get("json"), ",")[0]
		if tag != key {
			continue
		}
		switch f.Type.Kind() {
		case reflect.Int:
			return "int", true
		case reflect.Bool:
			return "bool", true
		case reflect.Slice:
			return "list", true
		}
	}
	return "", false
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

func newRootCmd(out io.Writer, makeClient func(endpoint, metrics, token, app string) *client) *cobra.Command {
	var endpoint, metricsEndpoint, token, app string
	var asJSON bool

	root := &cobra.Command{
		Use:           "wafctl",
		Short:         "Manage a running wafguard over its admin API",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&endpoint, "endpoint", "", "admin API URL")
	root.PersistentFlags().StringVar(&metricsEndpoint, "metrics-endpoint", "", "metrics URL")
	root.PersistentFlags().StringVar(&token, "token", "", "admin write token")
	root.PersistentFlags().StringVar(&app, "app", "", "application name")
	root.PersistentFlags().BoolVar(&asJSON, "json", false, "print raw JSON")

	var c *client
	root.PersistentPreRunE = func(_ *cobra.Command, _ []string) error {
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
		if endpoint == "" {
			endpoint = get("WAFGUARD_ENDPOINT", "http://127.0.0.1:19200")
		}
		if metricsEndpoint == "" {
			metricsEndpoint = get("WAFGUARD_METRICS", "http://127.0.0.1:9090/metrics")
		}
		if token == "" {
			token = get("WAFGUARD_TOKEN", "")
		}
		if app == "" {
			app = get("WAFGUARD_APP", "sample_app")
		}
		c = makeClient(strings.TrimRight(endpoint, "/"), metricsEndpoint, token, app)
		if c.http == nil {
			c.http = &http.Client{Timeout: 10 * time.Second}
		}
		return nil
	}

	root.AddCommand(
		&cobra.Command{
			Use:   "status",
			Short: "Show mode, revision and whitelist count",
			Args:  cobra.NoArgs,
			RunE: func(_ *cobra.Command, _ []string) error {
				data, err := c.do(http.MethodGet, c.appPath("/status"), nil)
				if err != nil {
					return err
				}
				return printJSONOrValue(out, data, asJSON)
			},
		},
	)

	configCmd := &cobra.Command{Use: "config", Short: "Inspect and edit policy config"}
	configCmd.AddCommand(
		&cobra.Command{
			Use:   "list",
			Short: "List every config field",
			Args:  cobra.NoArgs,
			RunE: func(_ *cobra.Command, _ []string) error {
				cfg, _, err := c.getPolicy()
				if err != nil {
					return err
				}
				for _, k := range sortedKeys(cfg) {
					_, _ = fmt.Fprintf(out, "%s=", k)
					if err := printValue(out, cfg[k]); err != nil {
						return err
					}
				}
				return nil
			},
		},
		&cobra.Command{
			Use:   "get <key>",
			Short: "Print one config field",
			Args:  cobra.ExactArgs(1),
			RunE: func(_ *cobra.Command, args []string) error {
				if _, ok := configFieldKind(args[0]); !ok {
					return fmt.Errorf("unknown config key %q", args[0])
				}
				cfg, _, err := c.getPolicy()
				if err != nil {
					return err
				}
				v, ok := cfg[args[0]]
				if !ok {
					return fmt.Errorf("config key %q not set", args[0])
				}
				return printValue(out, v)
			},
		},
		newConfigEditCmd(func() *client { return c }, out, "set", "Set a scalar config field", func(cfg map[string]any, key string, args []string) error {
			kind, ok := configFieldKind(key)
			if !ok {
				return fmt.Errorf("unknown config key %q", key)
			}
			if kind == "list" {
				return fmt.Errorf("use 'config add'/'config del' for %q", key)
			}
			if len(args) != 1 {
				return errors.New("config set needs exactly one value")
			}
			switch kind {
			case "int":
				v, err := strconv.Atoi(args[0])
				if err != nil {
					return fmt.Errorf("invalid integer %q", args[0])
				}
				cfg[key] = v
			case "bool":
				v, err := strconv.ParseBool(args[0])
				if err != nil {
					return fmt.Errorf("invalid boolean %q", args[0])
				}
				cfg[key] = v
			}
			return nil
		}),
		newConfigEditCmd(func() *client { return c }, out, "add", "Add values to a list config field", func(cfg map[string]any, key string, args []string) error {
			kind, ok := configFieldKind(key)
			if !ok {
				return fmt.Errorf("unknown config key %q", key)
			}
			if kind != "list" {
				return fmt.Errorf("config add only works on list fields, not %q", key)
			}
			cur := toStringSlice(cfg[key])
			seen := map[string]bool{}
			for _, v := range cur {
				seen[v] = true
			}
			for _, v := range args {
				if !seen[v] {
					cur = append(cur, v)
					seen[v] = true
				}
			}
			cfg[key] = cur
			return nil
		}),
		newConfigEditCmd(func() *client { return c }, out, "del", "Remove values from a list config field", func(cfg map[string]any, key string, args []string) error {
			kind, ok := configFieldKind(key)
			if !ok {
				return fmt.Errorf("unknown config key %q", key)
			}
			if kind != "list" {
				return fmt.Errorf("config del only works on list fields, not %q", key)
			}
			remove := map[string]bool{}
			for _, v := range args {
				remove[v] = true
			}
			var outSlice []string
			for _, v := range toStringSlice(cfg[key]) {
				if !remove[v] {
					outSlice = append(outSlice, v)
				}
			}
			cfg[key] = outSlice
			return nil
		}),
	)
	root.AddCommand(configCmd)

	modeCmd := &cobra.Command{Use: "mode", Short: "Read or set the app mode"}
	modeCmd.AddCommand(
		&cobra.Command{
			Use:   "get",
			Short: "Print the current mode",
			Args:  cobra.NoArgs,
			RunE: func(_ *cobra.Command, _ []string) error {
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
				_, err = fmt.Fprintln(out, st.Mode)
				return err
			},
		},
		&cobra.Command{
			Use:   "set <observe|enforce>",
			Short: "Set the mode",
			Args:  cobra.ExactArgs(1),
			RunE: func(_ *cobra.Command, args []string) error {
				mode := args[0]
				if mode != "observe" && mode != "enforce" {
					return fmt.Errorf("invalid mode %q", mode)
				}
				cfg, rev, err := c.getPolicy()
				if err != nil {
					return err
				}
				data, err := c.putPolicy(cfg, rev, mode)
				if err != nil {
					return err
				}
				return printJSONOrValue(out, data, asJSON)
			},
		},
	)
	root.AddCommand(modeCmd)

	wlCmd := &cobra.Command{Use: "whitelist", Short: "Manage the IP whitelist"}
	wlCmd.AddCommand(
		&cobra.Command{
			Use:   "list",
			Short: "List whitelisted IPs/CIDRs",
			Args:  cobra.NoArgs,
			RunE: func(_ *cobra.Command, _ []string) error {
				data, err := c.do(http.MethodGet, c.appPath("/whitelist"), nil)
				if err != nil {
					return err
				}
				return printJSONOrValue(out, data, asJSON)
			},
		},
		&cobra.Command{
			Use:   "add <ip/cidr>...",
			Short: "Add whitelisted IPs/CIDRs",
			Args:  cobra.MinimumNArgs(1),
			RunE: func(_ *cobra.Command, args []string) error {
				cfg, rev, err := c.getPolicy()
				if err != nil {
					return err
				}
				cur := toStringSlice(cfg["whitelist_ips"])
				seen := map[string]bool{}
				for _, v := range cur {
					seen[v] = true
				}
				for _, v := range args {
					if !seen[v] {
						cur = append(cur, v)
					}
				}
				cfg["whitelist_ips"] = cur
				data, err := c.putPolicy(cfg, rev, "")
				if err != nil {
					return err
				}
				return printJSONOrValue(out, data, asJSON)
			},
		},
		&cobra.Command{
			Use:   "remove <ip/cidr>...",
			Short: "Remove whitelisted IPs/CIDRs",
			Args:  cobra.MinimumNArgs(1),
			RunE: func(_ *cobra.Command, args []string) error {
				cfg, rev, err := c.getPolicy()
				if err != nil {
					return err
				}
				remove := map[string]bool{}
				for _, v := range args {
					remove[v] = true
				}
				var kept []string
				for _, v := range toStringSlice(cfg["whitelist_ips"]) {
					if !remove[v] {
						kept = append(kept, v)
					}
				}
				cfg["whitelist_ips"] = kept
				data, err := c.putPolicy(cfg, rev, "")
				if err != nil {
					return err
				}
				return printJSONOrValue(out, data, asJSON)
			},
		},
	)
	root.AddCommand(wlCmd)

	banCmd := &cobra.Command{Use: "ban", Short: "Inspect and clear bans"}
	banCmd.AddCommand(
		&cobra.Command{
			Use:   "list",
			Short: "List active bans with expiry",
			Args:  cobra.NoArgs,
			RunE: func(_ *cobra.Command, _ []string) error {
				data, err := c.do(http.MethodGet, c.appPath("/bans"), nil)
				if err != nil {
					return err
				}
				if asJSON {
					_, err = out.Write(data)
					return err
				}
				var result struct {
					Bans []struct {
						ClientIP  string `json:"client_ip"`
						ExpiresAt string `json:"expires_at"`
						Reason    string `json:"reason"`
						BanCount  int    `json:"ban_count"`
					} `json:"bans"`
				}
				if err := json.Unmarshal(data, &result); err != nil {
					return err
				}
				for _, b := range result.Bans {
					_, _ = fmt.Fprintf(out, "client_ip=%s expires_at=%s reason=%s ban_count=%d\n",
						b.ClientIP, b.ExpiresAt, b.Reason, b.BanCount)
				}
				return nil
			},
		},
	)
	root.AddCommand(banCmd)

	root.AddCommand(
		&cobra.Command{
			Use:   "unban <ip> [reason]",
			Short: "Clear an IP ban",
			Args:  cobra.RangeArgs(1, 2),
			RunE: func(_ *cobra.Command, args []string) error {
				reason := "manual unban via wafctl"
				if len(args) == 2 {
					reason = args[1]
				}
				data, err := c.do(http.MethodPost, c.appPath("/unban"), map[string]any{
					"client_ip":    args[0],
					"operation_id": fmt.Sprintf("wafctl-%d", time.Now().UnixNano()),
					"reason":       reason,
				})
				if err != nil {
					return err
				}
				return printJSONOrValue(out, data, asJSON)
			},
		},
		&cobra.Command{
			Use:   "inspect <ip>",
			Short: "Inspect one IP's decision state",
			Args:  cobra.ExactArgs(1),
			RunE: func(_ *cobra.Command, args []string) error {
				data, err := c.do(http.MethodGet, c.appPath("/decisions/"+url.PathEscape(args[0])), nil)
				if err != nil {
					return err
				}
				return printJSONOrValue(out, data, asJSON)
			},
		},
		&cobra.Command{
			Use:   "metrics",
			Short: "Print wafguard Prometheus metrics",
			Args:  cobra.NoArgs,
			RunE: func(_ *cobra.Command, _ []string) error {
				resp, err := c.http.Get(c.metricsBase)
				if err != nil {
					return err
				}
				defer func() { _ = resp.Body.Close() }()
				data, err := io.ReadAll(resp.Body)
				if err != nil {
					return err
				}
				for _, line := range strings.Split(string(data), "\n") {
					if strings.HasPrefix(line, "wafguard_") {
						_, _ = fmt.Fprintln(out, line)
					}
				}
				return nil
			},
		},
	)
	return root
}

func toStringSlice(v any) []string {
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, fmt.Sprint(item))
	}
	return out
}

func newConfigEditCmd(getC func() *client, out io.Writer, use, short string, edit func(map[string]any, string, []string) error) *cobra.Command {
	return &cobra.Command{
		Use:   use + " <key> <value...>",
		Short: short,
		Args:  cobra.MinimumNArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			c := getC()
			cfg, rev, err := c.getPolicy()
			if err != nil {
				return err
			}
			if err := edit(cfg, args[0], args[1:]); err != nil {
				return err
			}
			data, err := c.putPolicy(cfg, rev, "")
			if err != nil {
				return err
			}
			return printJSONOrValue(out, data, false)
		},
	}
}

func main() {
	root := newRootCmd(os.Stdout, func(endpoint, metrics, token, app string) *client {
		return &client{base: endpoint, metricsBase: metrics, token: token, app: app}
	})
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "wafctl:", err)
		os.Exit(1)
	}
}
