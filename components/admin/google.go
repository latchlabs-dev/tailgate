package main

// Google-only authorization-code login. Provider addresses are fixed, never
// read from a request or configuration file. All transport/JWT checks fail shut.
import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const googleFlowCookie = "__Host-tailgate_oauth"
const googleFlowTTL = 5 * time.Minute
const googleSessionTTL = 8 * time.Hour
const googleResponseLimit = 128 << 10

type googleConfig struct {
	ClientID          string   `json:"client_id"`
	ClientSecretFile  string   `json:"client_secret_file"`
	AdminEmails       []string `json:"admin_emails"`
	IdentityStoreFile string   `json:"identity_store_file"`
}
type googleProvider struct {
	discovery, issuer, authorize, token, jwks string
}

var productionGoogle = googleProvider{
	discovery: "https://accounts.google.com/.well-known/openid-configuration",
	issuer:    "https://accounts.google.com",
	authorize: "https://accounts.google.com/o/oauth2/v2/auth",
	token:     "https://oauth2.googleapis.com/token",
	jwks:      "https://www.googleapis.com/oauth2/v3/certs",
}

type googleFlow struct {
	bindingHash     [32]byte
	nonce, verifier string
	expires         time.Time
	used, cancelled bool
	sessionID       string
	member          bool
}
type googleAuth struct {
	clientID, clientSecret, callback string
	admins                           map[string]bool
	memberDomains                    map[string]bool
	provider                         googleProvider
	client                           *http.Client
	fetchGate                        chan struct{}
	mu                               sync.Mutex
	flows                            map[string]*googleFlow
	metadataUntil, keysUntil         time.Time
	keys                             map[string]*rsa.PublicKey
	identityMu                       sync.Mutex
	identityStore                    *privateState
	identities                       pinnedIdentities
	startAttempts                    map[string]attempt
	startGlobal                      attempt
	diagnosticMu                     sync.Mutex
	diagnosticUntil                  map[googleDiagnostic]googleDiagnosticRecord
	diagnosticLogger                 *log.Logger
}

// Diagnostics contain only finite operator categories. Never format an error,
// request, URL, provider response, claim or credential into authentication logs.
type googleDiagnostic uint8

const (
	googleOK googleDiagnostic = iota
	googleInternal
	googleStartOrigin
	googleStartBudget
	googleStartCapacity
	googleDiscovery
	googleTransactionCookie
	googleTransactionState
	googleTransactionMissing
	googleTransactionReplay
	googleTransactionCancelled
	googleTransactionExpired
	googleTransactionBinding
	googleCallbackQuery
	googleTokenExchange
	googleTokenResponse
	googleIDFormat
	googleIDKeys
	googleIDSignature
	googleClaimsJSON
	googleClaimsIssuer
	googleClaimsSubject
	googleClaimsTime
	googleClaimsNonce
	googleClaimsEmail
	googleClaimsAllowlist
	googleClaimsDomain
	googleClaimsAudience
	googleIdentityPin
	googleSessionIssue
)

func (d googleDiagnostic) name() string {
	switch d {
	case googleStartOrigin:
		return "start_origin"
	case googleStartBudget:
		return "start_budget"
	case googleStartCapacity:
		return "start_capacity"
	case googleDiscovery:
		return "provider_discovery"
	case googleTransactionCookie:
		return "transaction_cookie"
	case googleTransactionState:
		return "transaction_state"
	case googleTransactionMissing:
		return "transaction_missing"
	case googleTransactionReplay:
		return "transaction_replay"
	case googleTransactionCancelled:
		return "transaction_cancelled"
	case googleTransactionExpired:
		return "transaction_expired"
	case googleTransactionBinding:
		return "transaction_binding"
	case googleCallbackQuery:
		return "callback_query"
	case googleTokenExchange:
		return "provider_exchange"
	case googleTokenResponse:
		return "provider_response"
	case googleIDFormat:
		return "id_token_format"
	case googleIDKeys:
		return "id_token_keys"
	case googleIDSignature:
		return "id_token_signature"
	case googleClaimsJSON:
		return "claims_json"
	case googleClaimsIssuer:
		return "claims_issuer"
	case googleClaimsSubject:
		return "claims_subject"
	case googleClaimsTime:
		return "claims_time"
	case googleClaimsNonce:
		return "claims_nonce"
	case googleClaimsEmail:
		return "claims_email_verified"
	case googleClaimsAllowlist:
		return "account_allowlist"
	case googleClaimsDomain:
		return "claims_workspace_domain"
	case googleClaimsAudience:
		return "claims_audience"
	case googleIdentityPin:
		return "identity_pin"
	case googleSessionIssue:
		return "session_issue"
	default:
		return "internal"
	}
}

type googleAuthError struct{ stage googleDiagnostic }

func (e googleAuthError) Error() string        { return "Google sign-in was rejected" }
func googleError(stage googleDiagnostic) error { return googleAuthError{stage: stage} }
func googleErrorStage(err error) googleDiagnostic {
	var rejected googleAuthError
	if errors.As(err, &rejected) {
		return rejected.stage
	}
	return googleInternal
}

type googleDiagnosticRecord struct {
	until     time.Time
	reference string
}

func (g *googleAuth) diagnose(stage googleDiagnostic) string {
	// Unknown enum values collapse to one key, keeping both labels and memory
	// bounded. One line per category per ten seconds prevents callback spam.
	if stage == googleOK || stage > googleSessionIssue {
		stage = googleInternal
	}
	now := time.Now()
	g.diagnosticMu.Lock()
	defer g.diagnosticMu.Unlock()
	if g.diagnosticUntil == nil {
		g.diagnosticUntil = map[googleDiagnostic]googleDiagnosticRecord{}
	}
	if record := g.diagnosticUntil[stage]; now.Before(record.until) {
		return record.reference
	}
	reference := "TG-" + randomToken()[:16]
	g.diagnosticUntil[stage] = googleDiagnosticRecord{until: now.Add(10 * time.Second), reference: reference}
	logger := g.diagnosticLogger
	if logger == nil {
		logger = log.Default()
	}
	logger.Print("google_auth result=rejected stage=" + stage.name() + " reference=" + reference)
	return reference
}

type pinnedIdentity struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
}
type pinnedIdentities struct {
	Version  int                       `json:"version"`
	Accounts map[string]pinnedIdentity `json:"accounts"`
}
type googleIdentity struct {
	email, subject string
	expires        time.Time
}

func loadGoogle(path, origin string) (*googleAuth, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || net.ParseIP(u.Hostname()) != nil || strings.EqualFold(u.Hostname(), "localhost") {
		return nil, errors.New("Google administration requires a dedicated HTTPS hostname")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("Google configuration is unavailable")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return nil, errors.New("Google configuration must be a regular file not writable by group or others")
	}
	b, err := io.ReadAll(io.LimitReader(f, 32769))
	if err != nil || len(b) > 32768 {
		return nil, errors.New("invalid Google configuration")
	}
	var c googleConfig
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if uniqueJSON(b) != nil || d.Decode(&c) != nil || d.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("invalid Google configuration")
	}
	if !strings.HasSuffix(c.ClientID, ".apps.googleusercontent.com") || len(c.ClientID) > 256 || strings.ContainsAny(c.ClientID, " \r\n\t") || !filepath.IsAbs(c.ClientSecretFile) || !filepath.IsAbs(c.IdentityStoreFile) || len(c.AdminEmails) == 0 || len(c.AdminEmails) > 128 {
		return nil, errors.New("Google client, secret path and explicit administrator emails are required")
	}
	admins := make(map[string]bool)
	for _, email := range c.AdminEmails {
		parsed, err := mail.ParseAddress(email)
		if err != nil || parsed.Address != email || email != strings.ToLower(email) || len(email) > 254 || !strings.Contains(email, "@") || strings.ContainsAny(email, "* \r\n\t") || admins[email] {
			return nil, errors.New("administrator emails must be distinct exact lowercase addresses")
		}
		admins[email] = true
	}
	secret, err := secret(c.ClientSecretFile, 16)
	if err != nil {
		return nil, err
	}
	store, err := openPrivateState(c.IdentityStoreFile)
	if err != nil {
		return nil, err
	}
	identities := pinnedIdentities{Version: 1, Accounts: make(map[string]pinnedIdentity)}
	if exists, err := store.read(&identities); err != nil || (exists && (identities.Version != 1 || identities.Accounts == nil || len(identities.Accounts) > 128)) {
		store.close()
		return nil, errors.New("administrator identity pins are unavailable or invalid")
	}
	for email, identity := range identities.Accounts {
		if email == "" || identity.Issuer != productionGoogle.issuer || identity.Subject == "" || len(identity.Subject) > 255 {
			store.close()
			return nil, errors.New("administrator identity pins are invalid")
		}
	}
	return &googleAuth{
		clientID: c.ClientID, clientSecret: secret, callback: origin + "/auth/google/callback",
		admins: admins, provider: productionGoogle, flows: make(map[string]*googleFlow), fetchGate: make(chan struct{}, 1),
		identityStore: store, identities: identities, startAttempts: make(map[string]attempt),
		client: &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}, nil
}
func (g *googleAuth) allowed(email string) bool { return g.admins[email] }
func (g *googleAuth) memberAllowed(email string) bool {
	parts := strings.Split(email, "@")
	parsed, err := mail.ParseAddress(email)
	return err == nil && parsed.Address == email && len(parts) == 2 && email == strings.ToLower(email) && g.memberDomains[parts[1]]
}
func (g *googleAuth) pin(identity googleIdentity) error {
	g.identityMu.Lock()
	defer g.identityMu.Unlock()
	if old, exists := g.identities.Accounts[identity.email]; exists {
		if old.Issuer != productionGoogle.issuer || old.Subject != identity.subject {
			return errors.New("Google administrator identity changed")
		}
		return nil
	}
	if len(g.identities.Accounts) >= 128 {
		return errors.New("administrator identity store is full")
	}
	next := pinnedIdentities{Version: 1, Accounts: make(map[string]pinnedIdentity)}
	for email, pin := range g.identities.Accounts {
		next.Accounts[email] = pin
	}
	next.Accounts[identity.email] = pinnedIdentity{Issuer: productionGoogle.issuer, Subject: identity.subject}
	if err := g.identityStore.write(next); err != nil {
		return err
	}
	g.identities = next
	return nil
}
func (g *googleAuth) permitStart(r *http.Request) bool {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	for key, entry := range g.startAttempts {
		if !now.Before(entry.until) {
			delete(g.startAttempts, key)
		}
	}
	if !now.Before(g.startGlobal.until) {
		g.startGlobal = attempt{until: now.Add(time.Minute)}
	}
	entry := g.startAttempts[ip]
	if !now.Before(entry.until) {
		entry = attempt{until: now.Add(time.Minute)}
	}
	// At most 60 new transactions per minute globally keeps five-minute state
	// far below its 1024-entry cap; direct-IP limits do not trust proxy headers.
	if entry.count >= 15 || g.startGlobal.count >= 60 {
		return false
	}
	entry.count++
	g.startGlobal.count++
	g.startAttempts[ip] = entry
	return true
}
func (g *googleAuth) flowCookie(w http.ResponseWriter, value string, age int) {
	http.SetCookie(w, &http.Cookie{Name: googleFlowCookie, Value: value, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: age})
}
func flowBinding(r *http.Request) (string, string, bool) {
	c, err := r.Cookie(googleFlowCookie)
	if err != nil {
		return "", "", false
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) != 2 || len(parts[0]) != 43 || len(parts[1]) != 43 {
		return "", "", false
	}
	return parts[0], parts[1], true
}
func (g *googleAuth) cancel(r *http.Request) string {
	state, binding, ok := flowBinding(r)
	if !ok {
		return ""
	}
	h := sha256.Sum256([]byte(binding))
	g.mu.Lock()
	defer g.mu.Unlock()
	if flow := g.flows[state]; flow != nil && subtle.ConstantTimeCompare(h[:], flow.bindingHash[:]) == 1 {
		flow.cancelled = true
		delete(g.flows, state)
		return flow.sessionID
	}
	return ""
}
func (a *app) googleStart(w http.ResponseWriter, r *http.Request) {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		a.googleRejected(w, r, googleStartOrigin)
		return
	}
	g := a.google
	if !g.permitStart(r) {
		a.googleRejected(w, r, googleStartBudget)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	if err := g.metadata(ctx); err != nil {
		a.googleRejected(w, r, googleDiscovery)
		return
	}
	g.cancel(r)
	state, binding, nonce, verifier := randomToken(), randomToken(), randomToken(), randomToken()
	now := time.Now()
	g.mu.Lock()
	for key, flow := range g.flows {
		if !now.Before(flow.expires) {
			delete(g.flows, key)
		}
	}
	if len(g.flows) >= 1024 {
		g.mu.Unlock()
		a.googleRejected(w, r, googleStartCapacity)
		return
	}
	g.flows[state] = &googleFlow{bindingHash: sha256.Sum256([]byte(binding)), nonce: nonce, verifier: verifier, expires: now.Add(googleFlowTTL), member: r.URL.Path == "/auth/google/member/start"}
	g.mu.Unlock()
	g.flowCookie(w, state+"."+binding, int(googleFlowTTL.Seconds()))
	challenge := sha256.Sum256([]byte(verifier))
	query := url.Values{
		"client_id": {g.clientID}, "redirect_uri": {g.callback}, "response_type": {"code"},
		"scope": {"openid email profile"}, "state": {state}, "nonce": {nonce}, "prompt": {"select_account"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}, "code_challenge_method": {"S256"},
	}
	http.Redirect(w, r, g.provider.authorize+"?"+query.Encode(), http.StatusSeeOther)
}
func (g *googleAuth) consume(r *http.Request) (*googleFlow, googleDiagnostic) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	state, binding, ok := flowBinding(r)
	if err != nil || len(query["state"]) != 1 {
		return nil, googleCallbackQuery
	}
	if !ok {
		return nil, googleTransactionCookie
	}
	if subtle.ConstantTimeCompare([]byte(query.Get("state")), []byte(state)) != 1 {
		return nil, googleTransactionState
	}
	h := sha256.Sum256([]byte(binding))
	g.mu.Lock()
	defer g.mu.Unlock()
	flow := g.flows[state]
	if flow == nil {
		return nil, googleTransactionMissing
	}
	if flow.used {
		return nil, googleTransactionReplay
	}
	if flow.cancelled {
		return nil, googleTransactionCancelled
	}
	if !time.Now().Before(flow.expires) {
		return nil, googleTransactionExpired
	}
	if subtle.ConstantTimeCompare(h[:], flow.bindingHash[:]) != 1 {
		return nil, googleTransactionBinding
	}
	flow.used = true // Single-use even if provider exchange or claims fail.
	return flow, googleOK
}
func (a *app) googleRejected(w http.ResponseWriter, r *http.Request, stage googleDiagnostic) {
	reference := a.google.diagnose(stage)
	// Only fixed, non-sensitive outcomes reach the browser. Never copy callback
	// parameters, provider errors or identity claims into the destination.
	reason := "not-accepted"
	switch stage {
	case googleClaimsAllowlist:
		reason = "account-not-approved"
	case googleTransactionExpired:
		reason = "expired"
	case googleIdentityPin:
		reason = "contact-operator"
	case googleStartBudget, googleStartCapacity:
		reason = "busy"
	case googleDiscovery, googleSessionIssue:
		reason = "unavailable"
	}
	http.Redirect(w, r, "/auth/google/error?reason="+reason+"&ref="+reference, http.StatusSeeOther)
}

var googleErrorTemplate = template.Must(template.ParseFS(assets, "web/signin-error.html"))
var googleReferencePattern = regexp.MustCompile(`^TG-[A-Za-z0-9_-]{16}$`)

func (a *app) googleErrorPage(w http.ResponseWriter, r *http.Request) {
	message := "Google sign-in was not accepted. Start again using the button below."
	reference := ""
	status := http.StatusForbidden
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err == nil && len(query["reason"]) == 1 && len(query["ref"]) == 1 && googleReferencePattern.MatchString(query.Get("ref")) {
		reference = query.Get("ref")
		switch query.Get("reason") {
		case "account-not-approved":
			message = "This Google account is not approved for this sign-in. Use your company account for Get started, or an approved administrator account for Admin login."
		case "expired":
			message = "Google sign-in expired. Start a fresh sign-in using the button below."
		case "contact-operator":
			message = "This administrator identity was not accepted. Contact your administrator with the error reference below."
		case "busy":
			message = "There are too many sign-in attempts. Wait a minute, then try again."
			status = http.StatusTooManyRequests
		case "unavailable":
			message = "Sign-in is temporarily unavailable. Wait a minute, then try again."
			status = http.StatusServiceUnavailable
		}
	}
	var body bytes.Buffer
	if err := googleErrorTemplate.Execute(&body, struct{ Message, Reference, PublicSiteURL string }{message, reference, a.o.publicSite}); err != nil {
		fail(w, 503, "Sign-in page is temporarily unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable {
		w.Header().Set("Retry-After", "60")
	}
	w.WriteHeader(status)
	_, _ = w.Write(body.Bytes())
}
func (a *app) googleCallback(w http.ResponseWriter, r *http.Request) {
	g := a.google
	flow, rejection := g.consume(r)
	g.flowCookie(w, "", -1)
	if rejection != googleOK {
		a.googleRejected(w, r, rejection)
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(query["code"]) != 1 || query.Get("code") == "" || len(query.Get("code")) > 4096 || strings.ContainsAny(query.Get("code"), "\x00\r\n") || len(query["error"]) != 0 || (len(query["iss"]) != 0 && (len(query["iss"]) != 1 || query.Get("iss") != g.provider.issuer)) {
		a.googleRejected(w, r, googleCallbackQuery)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	identity, err := g.exchange(ctx, query.Get("code"), flow)
	if err != nil {
		// Never print provider errors, codes, ID tokens or rejected identities.
		a.googleRejected(w, r, googleErrorStage(err))
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if flow.cancelled || !time.Now().Before(flow.expires) {
		if flow.cancelled {
			a.googleRejected(w, r, googleTransactionCancelled)
		} else {
			a.googleRejected(w, r, googleTransactionExpired)
		}
		return
	}
	if !flow.member || g.allowed(identity.email) {
		if err := g.pin(identity); err != nil {
			a.googleRejected(w, r, googleIdentityPin)
			return
		}
	}
	// The ID token must still be valid when the login completes. The session
	// then has its own fixed lifetime, independent of the provider token.
	if !identity.expires.After(time.Now()) {
		a.googleRejected(w, r, googleClaimsTime)
		return
	}
	if session, ok := a.issueRoleSession(w, identity.email, identity.subject, time.Now().Add(googleSessionTTL), flow.member); ok {
		flow.sessionID = session.id
		destination := "/"
		if flow.member {
			destination = "/start"
		}
		http.Redirect(w, r, destination, http.StatusSeeOther)
	} else {
		a.googleRejected(w, r, googleSessionIssue)
	}
}
func (g *googleAuth) exchange(ctx context.Context, code string, flow *googleFlow) (googleIdentity, error) {
	if err := g.metadata(ctx); err != nil {
		return googleIdentity{}, googleError(googleDiscovery)
	}
	form := url.Values{
		"client_id": {g.clientID}, "client_secret": {g.clientSecret}, "code": {code},
		"redirect_uri": {g.callback}, "grant_type": {"authorization_code"}, "code_verifier": {flow.verifier},
	}
	r, err := http.NewRequestWithContext(ctx, "POST", g.provider.token, strings.NewReader(form.Encode()))
	if err != nil {
		return googleIdentity{}, googleError(googleTokenExchange)
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Accept", "application/json")
	b, err := g.fetch(r)
	if err != nil {
		return googleIdentity{}, googleError(googleTokenExchange)
	}
	var token struct {
		IDToken string `json:"id_token"`
	}
	if uniqueJSON(b) != nil || json.Unmarshal(b, &token) != nil || token.IDToken == "" {
		return googleIdentity{}, googleError(googleTokenResponse)
	}
	return g.validateRoleIDToken(ctx, token.IDToken, flow.nonce, flow.member)
}
func (g *googleAuth) fetch(r *http.Request) ([]byte, error) {
	b, _, err := g.fetchCached(r)
	return b, err
}
func (g *googleAuth) fetchCached(r *http.Request) ([]byte, time.Duration, error) {
	res, err := g.client.Do(r)
	if err != nil {
		return nil, 0, errors.New("Google is unavailable")
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, googleResponseLimit+1))
	if err != nil || len(b) > googleResponseLimit || res.StatusCode != 200 {
		return nil, 0, errors.New("invalid Google response")
	}
	ttl := 5 * time.Minute
	for _, directive := range strings.Split(res.Header.Get("Cache-Control"), ",") {
		directive = strings.TrimSpace(strings.ToLower(directive))
		if directive == "no-cache" || directive == "no-store" {
			ttl = 0
			break
		}
		if strings.HasPrefix(directive, "max-age=") {
			seconds, err := strconv.ParseInt(strings.Trim(strings.TrimPrefix(directive, "max-age="), `"`), 10, 64)
			if err != nil || seconds < 0 {
				ttl = 0
			} else if seconds > 3600 {
				ttl = time.Hour
			} else {
				ttl = time.Duration(seconds) * time.Second
			}
		}
	}
	if age, err := strconv.ParseInt(res.Header.Get("Age"), 10, 64); err == nil && age > 0 {
		if age >= int64(ttl.Seconds()) {
			ttl = 0
		} else {
			ttl -= time.Duration(age) * time.Second
		}
	}
	return b, ttl, nil
}
func (g *googleAuth) metadata(ctx context.Context) error {
	g.mu.Lock()
	if time.Now().Before(g.metadataUntil) {
		g.mu.Unlock()
		return nil
	}
	g.mu.Unlock()
	if err := g.acquireFetch(ctx); err != nil {
		return err
	}
	defer func() { <-g.fetchGate }()
	g.mu.Lock()
	cached := time.Now().Before(g.metadataUntil)
	g.mu.Unlock()
	if cached {
		return nil
	}
	r, err := http.NewRequestWithContext(ctx, "GET", g.provider.discovery, nil)
	if err != nil {
		return errors.New("invalid Google discovery request")
	}
	b, ttl, err := g.fetchCached(r)
	if err != nil {
		return err
	}
	var data struct {
		Issuer    string `json:"issuer"`
		Authorize string `json:"authorization_endpoint"`
		Token     string `json:"token_endpoint"`
		JWKS      string `json:"jwks_uri"`
	}
	if uniqueJSON(b) != nil || json.Unmarshal(b, &data) != nil || data.Issuer != g.provider.issuer || data.Authorize != g.provider.authorize || data.Token != g.provider.token || data.JWKS != g.provider.jwks {
		return errors.New("untrusted Google discovery metadata")
	}
	g.mu.Lock()
	g.metadataUntil = time.Now().Add(ttl)
	g.mu.Unlock()
	return nil
}
func (g *googleAuth) acquireFetch(ctx context.Context) error {
	select {
	case g.fetchGate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return errors.New("Google metadata request timed out")
	}
}
func (g *googleAuth) signingKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	g.mu.Lock()
	if key := g.keys[kid]; key != nil && time.Now().Before(g.keysUntil) {
		g.mu.Unlock()
		return key, nil
	}
	g.mu.Unlock()
	if err := g.acquireFetch(ctx); err != nil {
		return nil, err
	}
	defer func() { <-g.fetchGate }()
	g.mu.Lock()
	key, cached := g.keys[kid], time.Now().Before(g.keysUntil)
	g.mu.Unlock()
	if key != nil && cached {
		return key, nil
	}
	r, err := http.NewRequestWithContext(ctx, "GET", g.provider.jwks, nil)
	if err != nil {
		return nil, errors.New("invalid Google signing-key request")
	}
	b, ttl, err := g.fetchCached(r)
	if err != nil {
		return nil, err
	}
	var data struct {
		Keys []struct {
			Kty, Kid, Alg, Use, N, E string
		} `json:"keys"`
	}
	if uniqueJSON(b) != nil || json.Unmarshal(b, &data) != nil || len(data.Keys) == 0 || len(data.Keys) > 32 {
		return nil, errors.New("invalid Google signing keys")
	}
	keys := make(map[string]*rsa.PublicKey)
	for _, value := range data.Keys {
		if value.Kty != "RSA" || value.Kid == "" || len(value.Kid) > 128 || value.Alg != "RS256" || value.Use != "sig" || keys[value.Kid] != nil {
			return nil, errors.New("invalid Google signing key")
		}
		n, errN := base64.RawURLEncoding.Strict().DecodeString(value.N)
		e, errE := base64.RawURLEncoding.Strict().DecodeString(value.E)
		if errN != nil || errE != nil || len(n) < 256 || len(n) > 512 || len(e) == 0 || len(e) > 4 || n[0] == 0 || e[0] == 0 {
			return nil, errors.New("invalid Google RSA parameters")
		}
		modulus, exponent := new(big.Int).SetBytes(n), new(big.Int).SetBytes(e).Int64()
		if modulus.BitLen() < 2048 || exponent < 3 || exponent > 2147483647 || exponent%2 == 0 {
			return nil, errors.New("unsafe Google RSA parameters")
		}
		keys[value.Kid] = &rsa.PublicKey{N: modulus, E: int(exponent)}
	}
	g.mu.Lock()
	g.keys, g.keysUntil = keys, time.Now().Add(ttl)
	g.mu.Unlock()
	if key := keys[kid]; key != nil {
		return key, nil
	}
	return nil, errors.New("unknown Google signing key")
}
func (g *googleAuth) validateIDToken(ctx context.Context, token, nonce string) (googleIdentity, error) {
	return g.validateRoleIDToken(ctx, token, nonce, false)
}
func (g *googleAuth) validateRoleIDToken(ctx context.Context, token, nonce string, member bool) (googleIdentity, error) {
	stage := googleIDFormat
	reject := func() (googleIdentity, error) { return googleIdentity{}, googleError(stage) }
	if len(token) > 32768 {
		return reject()
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return reject()
	}
	header, errH := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	payload, errP := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	signature, errS := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	var h struct {
		Alg, Kid, Typ string
		Crit          []string
	}
	if errH != nil || errP != nil || errS != nil || uniqueJSON(header) != nil || json.Unmarshal(header, &h) != nil || h.Alg != "RS256" || h.Kid == "" || len(h.Kid) > 128 || (h.Typ != "" && h.Typ != "JWT") || len(h.Crit) != 0 {
		return reject()
	}
	key, err := g.signingKey(ctx, h.Kid)
	if err != nil {
		stage = googleIDKeys
		return reject()
	}
	hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], signature) != nil {
		stage = googleIDSignature
		return reject()
	}
	var c struct {
		Issuer        string          `json:"iss"`
		Audience      json.RawMessage `json:"aud"`
		Authorized    string          `json:"azp"`
		Subject       string          `json:"sub"`
		Expires       int64           `json:"exp"`
		Issued        int64           `json:"iat"`
		NotBefore     int64           `json:"nbf"`
		Nonce         string          `json:"nonce"`
		Email         string          `json:"email"`
		EmailVerified bool            `json:"email_verified"`
		HostedDomain  string          `json:"hd"`
	}
	if uniqueJSON(payload) != nil || json.Unmarshal(payload, &c) != nil {
		stage = googleClaimsJSON
		return reject()
	}
	now := time.Now().Unix()
	if c.Issuer != g.provider.issuer && !(g.provider.issuer == productionGoogle.issuer && c.Issuer == "accounts.google.com") {
		stage = googleClaimsIssuer
		return reject()
	}
	if !googleMemberSubject.MatchString(c.Subject) {
		stage = googleClaimsSubject
		return reject()
	}
	if c.Expires <= now || c.Issued <= 0 || c.Issued > now+60 || c.Issued >= c.Expires || c.NotBefore > now+60 || c.Expires-now > 86400 {
		stage = googleClaimsTime
		return reject()
	}
	if nonce == "" || subtle.ConstantTimeCompare([]byte(c.Nonce), []byte(nonce)) != 1 {
		stage = googleClaimsNonce
		return reject()
	}
	if !c.EmailVerified {
		stage = googleClaimsEmail
		return reject()
	}
	allowed := g.allowed(c.Email)
	if member {
		allowed = g.memberAllowed(c.Email)
	}
	if !allowed {
		stage = googleClaimsAllowlist
		return reject()
	}
	partsEmail := strings.Split(c.Email, "@")
	if len(partsEmail) != 2 {
		stage = googleClaimsEmail
		return reject()
	}
	if partsEmail[1] != "gmail.com" && partsEmail[1] != "googlemail.com" && c.HostedDomain != partsEmail[1] {
		stage = googleClaimsDomain
		return reject()
	}
	stage = googleClaimsAudience
	var audience string
	if json.Unmarshal(c.Audience, &audience) == nil {
		if audience != g.clientID {
			return reject()
		}
	} else {
		var audiences []string
		if json.Unmarshal(c.Audience, &audiences) != nil || len(audiences) == 0 || len(audiences) > 8 {
			return reject()
		}
		found := false
		seen := make(map[string]bool)
		for _, audience := range audiences {
			if audience == "" || seen[audience] {
				return reject()
			}
			seen[audience] = true
			found = found || audience == g.clientID
		}
		if !found || (len(audiences) > 1 && c.Authorized != g.clientID) {
			return reject()
		}
	}
	if c.Authorized != "" && c.Authorized != g.clientID {
		return reject()
	}
	return googleIdentity{email: c.Email, subject: c.Subject, expires: time.Unix(c.Expires, 0)}, nil
}

// Reject duplicate JSON members and deep/unbounded nesting before decoding
// security metadata. Other claims remain permitted for provider compatibility.
func uniqueJSON(b []byte) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var read func(int) error
	read = func(depth int) error {
		if depth > 16 {
			return errors.New("JSON nesting too deep")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]bool)
			for d.More() {
				key, err := d.Token()
				name, ok := key.(string)
				if err != nil || !ok || seen[strings.ToLower(name)] {
					return errors.New("duplicate or invalid JSON member")
				}
				seen[strings.ToLower(name)] = true
				if err := read(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := read(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("invalid JSON delimiter")
		}
		_, err = d.Token()
		return err
	}
	if err := read(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
