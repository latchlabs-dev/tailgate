package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"time"
)

type configSource struct {
	URL       string `json:"url"`
	Gateway   string `json:"gateway"`
	TokenFile string `json:"token_file"`
}

func (c configSource) validate() error {
	u, err := url.Parse(c.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "/gateway-config/v1/"+c.Gateway || u.RawPath != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || !label.MatchString(c.Gateway) || c.TokenFile != "/secrets/config-token" {
		return errors.New("config_service requires an exact HTTPS gateway endpoint, gateway ID and /secrets/config-token")
	}
	return nil
}

type remoteRule struct {
	Version      int      `json:"version"`
	Gateway      string   `json:"gateway"`
	Revision     uint64   `json:"revision"`
	Enabled      bool     `json:"enabled"`
	AllowedUsers []string `json:"allowed_users"`
}
type configReader struct {
	source configSource
	client *http.Client
	last   *remoteRule
}

func newConfigReader(source *configSource) *configReader {
	if source == nil {
		return nil
	}
	return &configReader{source: *source, client: &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}
func (r *configReader) users(ctx context.Context) []string {
	// A credential is a separate, root-owned read-only secret mount. Read each
	// request so rotation does not require keeping credentials in a config file.
	f, err := os.Open(r.source.TokenFile)
	if err != nil {
		return nil
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil
	}
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(b) > 4096 {
		return nil
	}
	token := strings.TrimSpace(string(b))
	if len(token) < 32 || strings.ContainsAny(token, "\r\n") {
		return nil
	}
	users, err := r.fetch(ctx, token)
	if err != nil {
		return nil
	}
	return users
}
func (r *configReader) fetch(ctx context.Context, token string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", r.source.URL, nil)
	if err != nil {
		return nil, errors.New("invalid configuration endpoint")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Cache-Control", "no-cache, no-store")
	response, err := r.client.Do(req)
	if err != nil {
		return nil, errors.New("configuration service unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("configuration read denied")
	}
	b, err := io.ReadAll(io.LimitReader(response.Body, 131073))
	if err != nil || len(b) > 131072 {
		return nil, errors.New("invalid configuration response size")
	}
	var rule remoteRule
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if d.Decode(&rule) != nil || d.Decode(&struct{}{}) != io.EOF || rule.Version != 1 || rule.Gateway != r.source.Gateway || rule.Revision == 0 || len(rule.AllowedUsers) > 256 {
		return nil, errors.New("invalid remote rule")
	}
	seen := map[string]bool{}
	for _, user := range rule.AllowedUsers {
		if !validLogin(user) || seen[user] {
			return nil, errors.New("invalid remote account")
		}
		seen[user] = true
	}
	if r.last != nil && (rule.Revision < r.last.Revision || rule.Revision == r.last.Revision && !reflect.DeepEqual(rule, *r.last)) {
		return nil, errors.New("configuration revision regressed or changed in place")
	}
	r.last = &rule
	if !rule.Enabled {
		return nil, nil
	}
	return append([]string(nil), rule.AllowedUsers...), nil
}
