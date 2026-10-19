// Tailgate administration: a private, loopback-only UI and narrow Headscale API adapter.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

//go:embed web/*
var assets embed.FS

const maxResponse = 2 << 20

type options struct {
	listen, origin, upstream, keyFile, loginFile, configFile, googleFile string
	workflowFile, operationsFile, publicSite, configServiceFile          string
	deviceMetadataFile                                                   string
	demo, writes, accessWrites, configWrites                             bool
}
type session struct {
	id      string
	csrf    string
	expires time.Time
	email   string
	subject string
	member  bool
}
type attempt struct {
	count int
	until time.Time
}
type user struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Email       string `json:"email"`
	Provider    string `json:"provider"`
	CreatedAt   string `json:"createdAt"`
}

// Explicit projection excludes preAuthKey, machineKey, nodeKey and discoKey.
type node struct {
	ID                  string   `json:"id"`
	Name                string   `json:"name"`
	GivenName           string   `json:"givenName"`
	IPs                 []string `json:"ipAddresses"`
	User                user     `json:"user"`
	LastSeen            string   `json:"lastSeen"`
	Expiry              string   `json:"expiry"`
	CreatedAt           string   `json:"createdAt"`
	Online              bool     `json:"online"`
	Tags                []string `json:"tags"`
	Routes              []string `json:"approvedRoutes"`
	OS                  string   `json:"os,omitempty"`
	OSVersion           string   `json:"osVersion,omitempty"`
	Model               string   `json:"model,omitempty"`
	Architecture        string   `json:"architecture,omitempty"`
	MetadataCollectedAt string   `json:"metadataCollectedAt,omitempty"`
	Version             string   `json:"version,omitempty"`
}
type record struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}
type settings struct {
	ControlURL    string              `json:"controlURL"`
	DeviceDomain  string              `json:"deviceDomain"`
	MagicDNS      bool                `json:"magicDNS"`
	OverrideDNS   bool                `json:"overrideDNS"`
	Global        []string            `json:"globalNameservers"`
	Split         map[string][]string `json:"splitNameservers"`
	Search        []string            `json:"searchDomains"`
	Records       []record            `json:"records"`
	PolicyMode    string              `json:"policyMode"`
	OwnRelaysOnly bool                `json:"ownRelaysOnly"`
}
type snapshot struct {
	Bridge          json.RawMessage   `json:"bridge,omitempty"`
	Demo            bool              `json:"demo"`
	Writes          bool              `json:"writes"`
	Nodes           []node            `json:"nodes"`
	Users           []user            `json:"users"`
	Settings        settings          `json:"settings"`
	Policy          string            `json:"policy"`
	ConfigAvailable bool              `json:"configAvailable"`
	UpdatedAt       string            `json:"updatedAt"`
	Workflow        *workflowView     `json:"workflow,omitempty"`
	Operations      *operationsStatus `json:"operations,omitempty"`
}
type app struct {
	o         options
	loginHash [32]byte
	google    *googleAuth
	workflow  *workflow
	bridge    *bridgeService
	client    *http.Client
	mu        sync.Mutex
	sessions  map[string]session
	attempts  map[string]attempt
	demo      snapshot
}

func secret(path string, minimum int) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", errors.New("credential file is unavailable")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return "", errors.New("credential file must be regular and accessible only to its owner")
	}
	b, err := io.ReadAll(io.LimitReader(f, 8193))
	if err != nil || len(b) > 8192 {
		return "", errors.New("invalid credential file")
	}
	s := strings.TrimSpace(string(b))
	if len(s) < minimum || strings.ContainsAny(s, "\r\n") {
		return "", errors.New("credential is too short or contains newlines")
	}
	return s, nil
}
func newApp(o options) (*app, error) {
	host, _, err := net.SplitHostPort(o.listen)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return nil, errors.New("admin listener must use a numeric loopback address")
	}
	u, err := url.Parse(o.origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("origin must be an exact HTTP(S) origin")
	}
	a := &app{o: o, sessions: map[string]session{}, attempts: map[string]attempt{}, demo: demoData()}
	if o.publicSite != "" {
		public, err := url.Parse(o.publicSite)
		if err != nil || public.Scheme != "https" || public.Host == "" || public.User != nil || (public.Path != "" && public.Path != "/") || public.RawQuery != "" || public.Fragment != "" || !publicSiteDomain.MatchString(public.Hostname()) || net.ParseIP(public.Hostname()) != nil || strings.HasSuffix(public.Hostname(), ".localhost") || (public.Port() != "" && public.Port() != "443") {
			return nil, errors.New("public site must be an exact HTTPS DNS origin")
		}
		a.o.publicSite = "https://" + public.Hostname()
		if u.Scheme == "https" && u.Hostname() == public.Hostname() && (u.Port() == "" || u.Port() == "443") {
			return nil, errors.New("public information site requires a separate origin")
		}
	}
	a.client = &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if o.demo && o.googleFile != "" {
		return nil, errors.New("Google authentication cannot be combined with preview mode")
	}
	if !o.demo {
		v, e := url.Parse(o.upstream)
		if e != nil || (v.Scheme != "http" && v.Scheme != "https") || v.Host == "" || v.User != nil || v.Path != "" || v.RawQuery != "" || v.Fragment != "" {
			return nil, errors.New("Headscale URL must be an exact HTTP(S) origin")
		}
		if v.Scheme == "http" {
			ip := net.ParseIP(v.Hostname())
			if ip == nil || !ip.IsLoopback() {
				return nil, errors.New("unencrypted Headscale API must be on numeric loopback")
			}
		}
		_, e = secret(o.keyFile, 16)
		if e != nil {
			return nil, e
		}
		if o.googleFile != "" {
			if o.loginFile != "" {
				return nil, errors.New("Google authentication cannot have a token-login fallback")
			}
			a.google, e = loadGoogle(o.googleFile, o.origin)
			if e != nil {
				return nil, e
			}
			if settings, _, available := a.config(); available && settings.ControlURL == o.origin {
				return nil, errors.New("Google administration requires a dedicated origin separate from the controller")
			}
		} else {
			login, e := secret(o.loginFile, 32)
			if e != nil {
				return nil, e
			}
			a.loginHash = sha256.Sum256([]byte(login))
		}
	}
	if o.workflowFile != "" {
		if o.demo {
			return nil, errors.New("approval workflow requires a real private controller")
		}
		s, _, available := a.config()
		if !available || s.PolicyMode != "database" {
			return nil, errors.New("approval workflow requires database policy mode")
		}
		a.workflow, err = loadWorkflow(o.workflowFile)
		if err != nil {
			return nil, err
		}
		if a.google != nil {
			a.google.memberDomains = a.workflow.domains
		}
	} else if o.accessWrites {
		return nil, errors.New("access changes require workflow configuration")
	}
	if o.configWrites && o.configServiceFile == "" && !o.demo {
		return nil, errors.New("configuration changes require a configuration service")
	}
	if o.configServiceFile != "" {
		if o.demo || !strings.HasPrefix(o.origin, "https://") {
			return nil, errors.New("configuration service requires a real HTTPS console")
		}
		a.bridge, err = loadBridgeService(o.configServiceFile)
		if err != nil {
			return nil, err
		}
	} else if o.demo {
		a.bridge = &bridgeService{state: emptyBridgeState([]string{"example-gateway"})}
	}
	return a, nil
}
func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("secure randomness unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func respond(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func fail(w http.ResponseWriter, status int, message string) {
	respond(w, status, map[string]string{"error": message})
}
func body(w http.ResponseWriter, r *http.Request, v any) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		fail(w, 415, "Expected JSON")
		return false
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(&struct{}{}) != io.EOF {
		fail(w, 400, "Invalid request")
		return false
	}
	return true
}
func (a *app) auth(r *http.Request) (session, bool) {
	if a.o.demo {
		return session{csrf: "local-demo"}, true
	}
	c, e := r.Cookie(a.sessionCookieName())
	if e != nil {
		return session{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[c.Value]
	allowed := a.google == nil
	if a.google != nil {
		allowed = a.google.allowed(s.email)
		if s.member {
			allowed = a.google.memberAllowed(s.email)
		}
	}
	if ok && time.Now().Before(s.expires) && allowed {
		return s, true
	}
	delete(a.sessions, c.Value)
	return session{}, false
}
func (a *app) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		u, _ := url.Parse(a.o.origin)
		if r.Host != u.Host {
			fail(w, 403, "Invalid host")
			return
		}
		if r.Method != "GET" && r.Method != "POST" {
			fail(w, 405, "Method not allowed")
			return
		}
		if r.Method == "POST" && r.Header.Get("Origin") != a.o.origin {
			fail(w, 403, "Invalid origin")
			return
		}
		if r.URL.Path == "/api/login" && r.Method == "POST" {
			if a.google != nil {
				fail(w, 404, "Token login is unavailable")
				return
			}
			a.login(w, r)
			return
		}
		if a.google != nil && r.Method == "GET" {
			switch r.URL.Path {
			case "/auth/google/start", "/auth/google/member/start":
				if r.URL.Path == "/auth/google/member/start" && a.workflow == nil {
					fail(w, 503, "Company requests are unavailable")
					return
				}
				a.googleStart(w, r)
				return
			case "/auth/google/callback":
				a.googleCallback(w, r)
				return
			case "/auth/google/error":
				a.googleErrorPage(w, r)
				return
			}
		}
		if strings.HasPrefix(r.URL.Path, "/gateway-config/") {
			a.gatewayConfig(w, r)
			return
		}
		s, ok := a.auth(r)
		if r.URL.Path == "/api/session" && r.Method == "GET" {
			mode := "token"
			if a.google != nil {
				mode = "google"
			} else if a.o.demo {
				mode = "demo"
			}
			role := ""
			if ok {
				role = "admin"
				if s.member {
					role = "member"
				}
			}
			respond(w, 200, map[string]any{"authenticated": ok, "demo": a.o.demo, "csrf": s.csrf, "authMode": mode, "role": role, "publicSiteURL": a.o.publicSite})
			return
		}
		if r.URL.Path == "/health" && r.Method == "GET" {
			respond(w, 200, map[string]bool{"ok": true})
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			ctx, cancel := context.WithTimeout(r.Context(), 18*time.Second)
			defer cancel()
			r = r.WithContext(ctx)
			if !ok {
				fail(w, 401, "Sign in to continue")
				return
			}
			if r.Method == "POST" && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(s.csrf)) != 1 {
				fail(w, 403, "Invalid request token")
				return
			}
			if r.URL.Path == "/api/logout" && r.Method == "POST" {
				if c, e := r.Cookie(a.sessionCookieName()); e == nil {
					a.mu.Lock()
					delete(a.sessions, c.Value)
					a.mu.Unlock()
				}
				if a.google != nil {
					if id := a.google.cancel(r); id != "" {
						a.mu.Lock()
						delete(a.sessions, id)
						a.mu.Unlock()
					}
					a.google.flowCookie(w, "", -1)
				}
				a.cookie(w, "", -1)
				respond(w, 200, map[string]bool{"ok": true})
				return
			}
			if r.URL.Path == "/api/member" || r.URL.Path == "/api/member/request" {
				a.memberRequest(w, r, s)
				return
			}
			if s.member {
				fail(w, 403, "Administrator access required")
				return
			}
			if r.URL.Path == "/api/bridge-config" {
				a.bridgeConfig(w, r, s)
				return
			}
			if r.URL.Path == "/api/requests/review" {
				a.reviewRequest(w, r, s)
				return
			}
			if r.URL.Path == "/api/snapshot" && r.Method == "GET" {
				a.getSnapshot(w, r)
				return
			}
			if strings.HasPrefix(r.URL.Path, "/api/workflow") {
				a.workflowRequest(w, r, s)
				return
			}
			if r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/api/machines/") {
				a.machine(w, r)
				return
			}
			fail(w, 404, "Unknown action")
			return
		}
		if r.Method != "GET" {
			fail(w, 405, "Method not allowed")
			return
		}
		if r.URL.Path == "/" && ok && s.member {
			http.Redirect(w, r, "/start", http.StatusSeeOther)
			return
		}
		files := map[string]string{"/": "index.html", "/start": "member.html", "/member.js": "member.js", "/app.js": "app.js", "/style.css": "style.css", "/favicon.svg": "favicon.svg", "/google-sign-in.png": "google-sign-in.png"}
		name, found := files[r.URL.Path]
		if !found {
			http.NotFound(w, r)
			return
		}
		data, _ := assets.ReadFile("web/" + name)
		types := map[string]string{"index.html": "text/html; charset=utf-8", "member.html": "text/html; charset=utf-8", "member.js": "text/javascript; charset=utf-8", "app.js": "text/javascript; charset=utf-8", "style.css": "text/css; charset=utf-8", "favicon.svg": "image/svg+xml", "google-sign-in.png": "image/png"}
		w.Header().Set("Content-Type", types[name])
		_, _ = w.Write(data)
	})
}
func (a *app) cookie(w http.ResponseWriter, value string, age int) {
	http.SetCookie(w, &http.Cookie{Name: a.sessionCookieName(), Value: value, Path: "/", HttpOnly: true, Secure: strings.HasPrefix(a.o.origin, "https://"), SameSite: http.SameSiteStrictMode, MaxAge: age})
}
func (a *app) sessionCookieName() string {
	if strings.HasPrefix(a.o.origin, "https://") {
		return "__Host-tailgate_session"
	}
	return "tailgate_session"
}
func (a *app) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token string `json:"token"`
	}
	if !body(w, r, &in) {
		return
	}
	h := sha256.Sum256([]byte(in.Token))
	if !a.o.demo && subtle.ConstantTimeCompare(h[:], a.loginHash[:]) == 1 {
		// A shared proxy IP's invalid-attempt budget cannot lock out a correct
		// high-entropy operator credential. Never trust forwarding headers here.
		if s, ok := a.issueSession(w, "", "", time.Now().Add(8*time.Hour)); ok {
			respond(w, 200, map[string]string{"csrf": s.csrf})
		}
		return
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	now := time.Now()
	a.mu.Lock()
	for k, v := range a.attempts {
		if now.After(v.until) {
			delete(a.attempts, k)
		}
	}
	v := a.attempts[ip]
	if v.count >= 5 || len(a.attempts) >= 256 {
		a.mu.Unlock()
		fail(w, 429, "Too many sign-in attempts. Try again in a minute.")
		return
	}
	if v.count == 0 {
		v.until = now.Add(time.Minute)
	}
	v.count++
	a.attempts[ip] = v
	a.mu.Unlock()
	fail(w, 401, "Sign-in failed")
}
func (a *app) issueSession(w http.ResponseWriter, email, subject string, expires time.Time) (session, bool) {
	return a.issueRoleSession(w, email, subject, expires, false)
}
func (a *app) issueRoleSession(w http.ResponseWriter, email, subject string, expires time.Time, member bool) (session, bool) {
	now := time.Now()
	if !expires.After(now) {
		if a.google == nil {
			fail(w, 403, "Sign-in expired")
		}
		return session{}, false
	}
	token := randomToken()
	s := session{id: token, csrf: randomToken(), expires: expires, email: email, subject: subject, member: member}
	a.mu.Lock()
	for k, v := range a.sessions {
		if now.After(v.expires) {
			delete(a.sessions, k)
		}
	}
	if len(a.sessions) >= 1024 {
		a.mu.Unlock()
		if a.google == nil {
			fail(w, 503, "Sign-in temporarily unavailable")
		}
		return session{}, false
	}
	a.sessions[token] = s
	a.mu.Unlock()
	a.cookie(w, token, int(expires.Sub(now).Seconds()))
	return s, true
}
func (a *app) upstream(method, path string, input any, output any) error {
	return a.upstreamContext(context.Background(), method, path, input, output)
}
func (a *app) upstreamContext(ctx context.Context, method, path string, input any, output any) error {
	key, err := secret(a.o.keyFile, 16)
	if err != nil {
		return errors.New("Headscale API credential is unavailable")
	}
	var payload io.Reader
	if input != nil {
		b, _ := json.Marshal(input)
		payload = bytes.NewReader(b)
	}
	r, err := http.NewRequestWithContext(ctx, method, a.o.upstream+path, payload)
	if err != nil {
		return errors.New("invalid upstream request")
	}
	r.Header.Set("Authorization", "Bearer "+key)
	r.Header.Set("Accept", "application/json")
	if input != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	response, err := a.client.Do(r)
	if err != nil {
		return errors.New("Headscale is unavailable")
	}
	defer response.Body.Close()
	b, err := io.ReadAll(io.LimitReader(response.Body, maxResponse+1))
	if err != nil || len(b) > maxResponse {
		return errors.New("invalid Headscale response")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("Headscale rejected the request (%d)", response.StatusCode)
	}
	if output != nil && json.Unmarshal(b, output) != nil {
		return errors.New("invalid Headscale response")
	}
	return nil
}
func readBounded(path string) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, maxResponse+1))
	if len(b) > maxResponse {
		return nil, errors.New("configuration too large")
	}
	return b, e
}
func (a *app) config() (settings, string, bool) {
	var c struct {
		URL string `json:"server_url"`
		DNS struct {
			Magic    bool     `json:"magic_dns"`
			Base     string   `json:"base_domain"`
			Override bool     `json:"override_local_dns"`
			Search   []string `json:"search_domains"`
			Records  string   `json:"extra_records_path"`
			Names    struct {
				Global []string            `json:"global"`
				Split  map[string][]string `json:"split"`
			} `json:"nameservers"`
		} `json:"dns"`
		Policy struct {
			Mode string `json:"mode"`
			Path string `json:"path"`
		} `json:"policy"`
		DERP struct {
			URLs   []string `json:"urls"`
			Server struct {
				Enabled bool `json:"enabled"`
			} `json:"server"`
			Paths []string `json:"paths"`
		} `json:"derp"`
	}
	b, e := readBounded(a.o.configFile)
	if e != nil || json.Unmarshal(b, &c) != nil {
		return settings{}, "", false
	}
	s := settings{ControlURL: c.URL, DeviceDomain: c.DNS.Base, MagicDNS: c.DNS.Magic, OverrideDNS: c.DNS.Override, Global: c.DNS.Names.Global, Split: c.DNS.Names.Split, Search: c.DNS.Search, PolicyMode: c.Policy.Mode, OwnRelaysOnly: len(c.DERP.URLs) == 0 && (c.DERP.Server.Enabled || len(c.DERP.Paths) > 0)}
	if b, e := readBounded(c.DNS.Records); e == nil {
		_ = json.Unmarshal(b, &s.Records)
	}
	policy := ""
	if c.Policy.Mode == "file" {
		if b, e := readBounded(c.Policy.Path); e == nil {
			policy = string(b)
		}
	}
	return s, policy, true
}
func (a *app) getSnapshot(w http.ResponseWriter, r *http.Request) {
	if a.o.demo {
		a.mu.Lock()
		defer a.mu.Unlock()
		data := a.demo
		data.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		data.Bridge = a.bridgeSnapshot()
		respond(w, 200, data)
		return
	}
	var nodes struct {
		Nodes []node `json:"nodes"`
	}
	var users struct {
		Users []user `json:"users"`
	}
	if e := a.upstreamContext(r.Context(), "GET", "/api/v1/node", nil, &nodes); e != nil {
		fail(w, 502, e.Error())
		return
	}
	if e := a.upstreamContext(r.Context(), "GET", "/api/v1/user", nil, &users); e != nil {
		fail(w, 502, e.Error())
		return
	}
	applyDeviceMetadata(a.o.deviceMetadataFile, nodes.Nodes)
	s, p, ok := a.config()
	if s.PolicyMode == "database" {
		var v struct {
			Policy string `json:"policy"`
		}
		if a.upstreamContext(r.Context(), "GET", "/api/v1/policy", nil, &v) == nil {
			p = v.Policy
		}
	}
	if nodes.Nodes == nil {
		nodes.Nodes = []node{}
	}
	if users.Users == nil {
		users.Users = []user{}
	}
	var workflowData *workflowView
	if a.workflow != nil {
		var err error
		workflowData, err = a.workflowSnapshot(r.Context())
		if err != nil {
			fail(w, 502, err.Error())
			return
		}
		for i := range nodes.Nodes {
			if original, ok := workflowData.Owners[nodes.Nodes[i].ID]; ok {
				nodes.Nodes[i].User = original
			}
		}
	}
	respond(w, 200, snapshot{Bridge: a.bridgeSnapshot(), Nodes: nodes.Nodes, Users: users.Users, Settings: s, Policy: p, ConfigAvailable: ok, Writes: a.o.writes, UpdatedAt: time.Now().UTC().Format(time.RFC3339), Workflow: workflowData, Operations: readOperations(a.o.operationsFile)})
}

var idPattern = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
var publicSiteDomain = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
var namePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func (a *app) machine(w http.ResponseWriter, r *http.Request) {
	if !a.o.demo && !a.o.writes {
		fail(w, 403, "Device changes are disabled")
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/machines/"), "/")
	if len(parts) != 2 || !idPattern.MatchString(parts[0]) {
		fail(w, 400, "Invalid device")
		return
	}
	id, action := parts[0], parts[1]
	if action != "rename" && action != "expire" && action != "delete" {
		fail(w, 404, "Unknown action")
		return
	}
	var in struct {
		Name         string `json:"name"`
		Confirmation string `json:"confirmation"`
	}
	if !body(w, r, &in) {
		return
	}
	if action == "rename" && !namePattern.MatchString(in.Name) {
		fail(w, 400, "Use a lowercase device name with letters, numbers and hyphens (up to 63 characters)")
		return
	}
	var n node
	if a.o.demo {
		a.mu.Lock()
		defer a.mu.Unlock()
		index := -1
		for i, v := range a.demo.Nodes {
			if v.ID == id {
				index = i
				n = v
				break
			}
		}
		if index < 0 {
			fail(w, 404, "Device not found")
			return
		}
		if action != "rename" && in.Confirmation != n.GivenName {
			fail(w, 409, "Device name confirmation does not match")
			return
		}
		switch action {
		case "rename":
			a.demo.Nodes[index].GivenName = in.Name
		case "expire":
			a.demo.Nodes[index].Online = false
			a.demo.Nodes[index].Expiry = time.Now().UTC().Format(time.RFC3339)
		case "delete":
			a.demo.Nodes = append(a.demo.Nodes[:index], a.demo.Nodes[index+1:]...)
		}
	} else {
		var v struct {
			Node node `json:"node"`
		}
		if e := a.upstreamContext(r.Context(), "GET", "/api/v1/node/"+id, nil, &v); e != nil {
			fail(w, 502, e.Error())
			return
		}
		n = v.Node
		name := n.GivenName
		if name == "" {
			name = n.Name
		}
		if action != "rename" && in.Confirmation != name {
			fail(w, 409, "Device name confirmation does not match")
			return
		}
		// Confirm the current device name before withdrawing access. Grants must
		// be removed and read back before any managed expiry or deletion.
		if a.workflow != nil && action != "rename" {
			if !a.o.accessWrites {
				fail(w, 403, "Access changes are disabled")
				return
			}
			if err := a.withdrawDevice(r.Context(), id); err != nil {
				fail(w, 409, err.Error())
				return
			}
		}
		path := "/api/v1/node/" + id
		method := "POST"
		switch action {
		case "rename":
			path += "/rename/" + url.PathEscape(in.Name)
		case "expire":
			path += "/expire"
		case "delete":
			method = "DELETE"
		}
		if e := a.upstreamContext(r.Context(), method, path, nil, nil); e != nil {
			fail(w, 502, e.Error())
			return
		}
	}
	log.Printf("device_action action=%s id=%s result=success demo=%t", action, id, a.o.demo)
	respond(w, 200, map[string]bool{"ok": true})
}
func demoData() snapshot {
	now := time.Now().UTC()
	alice := user{ID: "1", Name: "alice", DisplayName: "Alice Chen", Email: "alice@example.com", Provider: "oidc", CreatedAt: now.Add(-30 * 24 * time.Hour).Format(time.RFC3339)}
	bob := user{ID: "2", Name: "bob", DisplayName: "Bob Rivera", Email: "bob@example.com", Provider: "oidc", CreatedAt: alice.CreatedAt}
	nodes := []node{
		{ID: "1", GivenName: "alice-macbook", Name: "Alice’s MacBook", IPs: []string{"100.64.0.2"}, User: alice, Online: true, OS: "macOS", Version: "1.102.5"},
		{ID: "2", GivenName: "build-01", Name: "build-01", IPs: []string{"100.64.0.10"}, User: alice, Online: true, OS: "Linux", Version: "1.102.5", Tags: []string{"tag:build"}},
		{ID: "3", GivenName: "design-desktop", Name: "design-desktop", IPs: []string{"100.64.0.12"}, User: bob, Online: false, OS: "Windows", Version: "1.102.5", LastSeen: now.Add(-2 * time.Hour).Format(time.RFC3339)},
		{ID: "4", GivenName: "exit-london", Name: "exit-london", IPs: []string{"100.64.0.20"}, User: alice, Online: true, OS: "Linux", Version: "1.102.5", Tags: []string{"tag:exit"}, Routes: []string{"0.0.0.0/0", "::/0"}},
		{ID: "5", GivenName: "bob-iphone", Name: "Bob’s iPhone", IPs: []string{"100.64.0.30"}, User: bob, Online: true, OS: "iOS", OSVersion: "18.0", Model: "iPhone14,7", Architecture: "arm64", Version: "1.102.5"},
		{ID: "6", GivenName: "dev-workstation", Name: "dev-workstation", IPs: []string{"100.64.0.40"}, User: alice, Online: false, OS: "Linux", Version: "1.102.5", Tags: []string{"tag:dev"}, LastSeen: now.Add(-22 * time.Hour).Format(time.RFC3339)},
	}
	for i := range nodes {
		nodes[i].CreatedAt = alice.CreatedAt
		if len(nodes[i].Tags) == 0 {
			nodes[i].Expiry = now.Add(60 * 24 * time.Hour).Format(time.RFC3339)
		}
	}
	return snapshot{Demo: true, Writes: true, ConfigAvailable: true, Nodes: nodes, Users: []user{alice, bob}, Policy: "{\n  \"grants\": []\n}\n", Settings: settings{ControlURL: "https://control.example.com", DeviceDomain: "mesh.example.com", MagicDNS: true, PolicyMode: "file", OwnRelaysOnly: true, Records: []record{{Name: "dashboard.apps.example.com", Type: "A", Value: "100.64.0.10"}}}}
}
func main() {
	var o options
	var operatorFile string
	var operatorApply bool
	flag.StringVar(&operatorFile, "operator-request-file", "", "private reviewed access request; no HTTP listener is started")
	flag.BoolVar(&operatorApply, "operator-apply", false, "apply the reviewed operator request; default is review only")
	flag.StringVar(&o.listen, "listen", "127.0.0.1:18100", "numeric loopback listener")
	flag.StringVar(&o.origin, "origin", "", "exact browser origin (defaults to http://listen)")
	flag.BoolVar(&o.demo, "demo", false, "local, fictitious in-memory preview")
	flag.BoolVar(&o.writes, "allow-device-changes", false, "enable authenticated rename/expire/remove")
	flag.StringVar(&o.upstream, "headscale-url", "", "private Headscale HTTP(S) origin")
	flag.StringVar(&o.keyFile, "api-key-file", "", "owner-only Headscale API credential file")
	flag.StringVar(&o.loginFile, "login-token-file", "", "owner-only separate admin login token (at least 32 characters)")
	flag.StringVar(&o.configFile, "config-file", "", "read-only JSON Headscale configuration")
	flag.StringVar(&o.googleFile, "google-config-file", "", "Google-only administrator authentication JSON configuration")
	flag.BoolVar(&o.configWrites, "allow-config-changes", false, "enable authenticated central bridge rule changes")
	flag.StringVar(&o.configServiceFile, "config-service-file", "", "private common configuration service registry and durable state path")
	flag.StringVar(&o.workflowFile, "workflow-config-file", "", "private durable device and access approval configuration")
	flag.BoolVar(&o.accessWrites, "allow-access-changes", false, "enable explicit proposal approval, revocation and reconciliation")
	flag.StringVar(&o.deviceMetadataFile, "device-metadata-file", "", "read-only device metadata projection")
	flag.StringVar(&o.operationsFile, "operations-status-file", "", "read-only safe operational status JSON projection")
	flag.StringVar(&o.publicSite, "public-site-url", "", "public HTTPS information-site origin for privacy, terms and support links")
	flag.Parse()
	if operatorApply && operatorFile == "" {
		log.Fatal("operator apply requires a reviewed request file")
	}
	if o.origin == "" {
		o.origin = "http://" + o.listen
	}
	a, e := newApp(o)
	if e != nil {
		log.Fatal(e)
	}
	if operatorFile != "" {
		if o.googleFile == "" || o.loginFile != "" {
			log.Fatal("operator mode requires the existing Google administrator configuration")
		}
		if e = a.operatorApproval(operatorFile, operatorApply, os.Stdout); e != nil {
			log.Fatal(e)
		}
		return
	}
	if a.workflow != nil {
		go a.workflowMonitor()
	}
	s := &http.Server{Addr: o.listen, Handler: a.handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
	log.Printf("Tailgate admin listening on %s demo=%t device_changes=%t", o.listen, o.demo, o.writes)
	log.Fatal(s.ListenAndServe())
}
