package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const googleTestID = "12345-test.apps.googleusercontent.com"
const googleTestSecret = "test-only-google-client-secret"

func privateFilename(t *testing.T, name string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, name)
}

type googleFixture struct {
	a        *app
	server   *httptest.Server
	key      *rsa.PrivateKey
	mu       sync.Mutex
	nonce    string
	verifier string
	mode     string
	calls    int
	started  chan struct{}
	release  chan struct{}
	logs     bytes.Buffer
}

func newGoogleFixture(t *testing.T) *googleFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &googleFixture{key: key}
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		mode, nonce, verifier := f.mode, f.nonce, f.verifier
		f.mu.Unlock()
		switch r.URL.Path {
		case "/discovery":
			token := f.server.URL + "/token"
			if mode == "untrusted-metadata" {
				token = "https://attacker.example.com/token"
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": f.server.URL, "authorization_endpoint": f.server.URL + "/authorize", "token_endpoint": token, "jwks_uri": f.server.URL + "/jwks"})
		case "/jwks":
			n := f.key.N.Bytes()
			if mode == "weak-key" {
				n = []byte{1, 2, 3}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "test-key", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(n), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(f.key.E)).Bytes())}}})
		case "/token":
			f.mu.Lock()
			f.calls++
			f.mu.Unlock()
			if r.Method != "POST" || r.ParseForm() != nil || r.Form.Get("client_id") != googleTestID || r.Form.Get("client_secret") != googleTestSecret || r.Form.Get("redirect_uri") != "https://admin.example.com/auth/google/callback" || r.Form.Get("code_verifier") != verifier || r.Form.Get("grant_type") != "authorization_code" {
				t.Error("invalid server-side authorization-code exchange")
				w.WriteHeader(400)
				return
			}
			if mode == "redirect" {
				http.Redirect(w, r, f.server.URL+"/credential-target", 307)
				return
			}
			if mode == "token-rejected" {
				http.Error(w, "provider-body-secret "+googleTestSecret+" good-code alice@example.com", 400)
				return
			}
			if f.started != nil {
				close(f.started)
				<-f.release
			}
			claims := f.claims(nonce)
			if mode == "unapproved-email" {
				claims["email"] = "mallory@example.com"
			}
			if mode == "bad-nonce" {
				claims["nonce"] = "another-browser"
			}
			if mode == "missing-hd" {
				claims["hd"] = ""
			}
			if mode == "unverified-email" {
				claims["email_verified"] = false
			}
			if mode == "wrong-audience" {
				claims["aud"] = "other-client.apps.googleusercontent.com"
			}
			if mode == "expired-token" {
				claims["exp"] = time.Now().Add(-time.Minute).Unix()
			}
			idToken := f.sign(t, map[string]any{"alg": "RS256", "kid": "test-key", "typ": "JWT"}, claims)
			if mode == "bad-signature" {
				parts := strings.Split(idToken, ".")
				sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
				sig[0] ^= 1
				parts[2] = base64.RawURLEncoding.EncodeToString(sig)
				idToken = strings.Join(parts, ".")
			}
			if mode == "malformed-id-token" {
				idToken = "opaque-fixture-id-token"
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"id_token": idToken})
		case "/credential-target":
			t.Error("followed redirect carrying OAuth credential")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.server.Close)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, `{"nodes":[],"users":[]}`) }))
	t.Cleanup(upstream.Close)
	config := googleConfig{ClientID: googleTestID, ClientSecretFile: credential(t, "google-secret", googleTestSecret), AdminEmails: []string{"alice@example.com"}, IdentityStoreFile: privateFilename(t, "identities.json")}
	b, _ := json.Marshal(config)
	path := credential(t, "google-config", string(b))
	f.a, err = newApp(options{listen: "127.0.0.1:18100", origin: "https://admin.example.com", upstream: upstream.URL, keyFile: credential(t, "api", testKey), googleFile: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.a.google.identityStore.close)
	// The fake provider is injected only in _test.go. No runtime configuration or
	// flag can change Google's production origins or relax TLS verification.
	f.a.google.provider = googleProvider{discovery: f.server.URL + "/discovery", issuer: f.server.URL, authorize: f.server.URL + "/authorize", token: f.server.URL + "/token", jwks: f.server.URL + "/jwks"}
	f.a.google.client = f.server.Client()
	f.a.google.client.Timeout = 2 * time.Second
	f.a.google.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	f.a.google.diagnosticLogger = log.New(&f.logs, "", 0)
	return f
}
func (f *googleFixture) claims(nonce string) map[string]any {
	now := time.Now().Unix()
	return map[string]any{"iss": f.server.URL, "aud": googleTestID, "sub": "test-google-subject", "exp": now + 3600, "iat": now - 1, "nonce": nonce, "email": "alice@example.com", "email_verified": true, "hd": "example.com"}
}
func (f *googleFixture) sign(t *testing.T, header, claims any) string {
	t.Helper()
	h, _ := json.Marshal(header)
	b, _ := json.Marshal(claims)
	return f.signRaw(t, h, b)
}
func (f *googleFixture) signRaw(t *testing.T, header, claims []byte) string {
	t.Helper()
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	hash := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(sig)
}
func (f *googleFixture) start(t *testing.T) (string, string) {
	t.Helper()
	w := call(f.a, "GET", "/auth/google/start", "", "", "", "", "admin.example.com")
	if w.Code != 303 {
		t.Fatalf("start status %d", w.Code)
	}
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil || u.Scheme+"://"+u.Host+u.Path != f.server.URL+"/authorize" {
		t.Fatal("invalid Google authorization destination")
	}
	cookie := w.Result().Cookies()[0]
	if cookie.Name != googleFlowCookie || !cookie.Secure || !cookie.HttpOnly || cookie.Domain != "" || cookie.Path != "/" || cookie.SameSite != http.SameSiteLaxMode || cookie.MaxAge != 300 {
		t.Fatal("unsafe temporary browser-binding cookie")
	}
	state := u.Query().Get("state")
	flow := f.a.google.flows[state]
	challenge := sha256.Sum256([]byte(flow.verifier))
	if len(state) != 43 || u.Query().Get("nonce") == "" || u.Query().Get("code_challenge_method") != "S256" || u.Query().Get("code_challenge") != base64.RawURLEncoding.EncodeToString(challenge[:]) || u.Query().Get("scope") != "openid email profile" || u.Query().Get("redirect_uri") != "https://admin.example.com/auth/google/callback" {
		t.Fatal("missing OAuth state/nonce/PKCE or wrong scopes/callback")
	}
	f.mu.Lock()
	f.nonce, f.verifier = flow.nonce, flow.verifier
	f.mu.Unlock()
	return state, cookie.Name + "=" + cookie.Value
}
func (f *googleFixture) callback(state, cookie string) *httptest.ResponseRecorder {
	return call(f.a, "GET", "/auth/google/callback?state="+url.QueryEscape(state)+"&code=good-code", "", cookie, "", "", "admin.example.com")
}
func sessionCookie(w *httptest.ResponseRecorder) *http.Cookie {
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == "__Host-tailgate_session" {
			return cookie
		}
	}
	return nil
}
func assertGoogleFailureRedirect(t *testing.T, w *httptest.ResponseRecorder) *url.URL {
	t.Helper()
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil || w.Code != http.StatusSeeOther || sessionCookie(w) != nil || u.Scheme != "" || u.Host != "" || u.Path != "/auth/google/error" || len(u.Query()) != 2 || !googleReferencePattern.MatchString(u.Query().Get("ref")) {
		t.Fatalf("rejection did not redirect safely without a session (%d)", w.Code)
	}
	switch u.Query().Get("reason") {
	case "not-accepted", "account-not-approved", "expired", "contact-operator", "busy", "unavailable":
	default:
		t.Fatal("unbounded error reason")
	}
	return u
}
func assertGoogleRejection(t *testing.T, w *httptest.ResponseRecorder) *url.URL {
	t.Helper()
	u := assertGoogleFailureRedirect(t, w)
	cleared := false
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == googleFlowCookie && cookie.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("rejected flow retained its browser cookie")
	}
	return u
}

func TestGoogleAuthorizationCodeSessionAndNoFallback(t *testing.T) {
	f := newGoogleFixture(t)
	state, binding := f.start(t)
	w := f.callback(state, binding)
	cookie := sessionCookie(w)
	if w.Code != 303 || w.Header().Get("Location") != "/" || cookie == nil || !cookie.Secure || !cookie.HttpOnly || cookie.Domain != "" || cookie.Path != "/" || cookie.SameSite != http.SameSiteStrictMode || cookie.MaxAge < int(googleSessionTTL.Seconds())-5 || cookie.MaxAge > int(googleSessionTTL.Seconds()) {
		t.Fatal("Google login did not issue an eight-hour secure host-only session")
	}
	if remaining := time.Until(f.a.sessions[cookie.Value].expires); remaining < googleSessionTTL-5*time.Second || remaining > googleSessionTTL {
		t.Fatalf("administrator session lifetime is %s, want eight hours", remaining)
	}
	credentials := cookie.Name + "=" + cookie.Value
	w = call(f.a, "GET", "/api/session", "", credentials, "", "", "admin.example.com")
	var result struct {
		Authenticated bool   `json:"authenticated"`
		Mode          string `json:"authMode"`
		CSRF          string `json:"csrf"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	if !result.Authenticated || result.Mode != "google" || result.CSRF == "" {
		t.Fatal("missing authenticated Google session/CSRF")
	}
	if w := call(f.a, "POST", "/api/login", `{"token":"`+testLogin+`"}`, "", "", f.a.o.origin, "admin.example.com"); w.Code != 404 {
		t.Fatal("Google mode accepted token fallback")
	}
	if w := call(f.a, "POST", "/api/logout", `{}`, credentials, "wrong", f.a.o.origin, "admin.example.com"); w.Code != 403 {
		t.Fatal("Google session logout accepted bad CSRF")
	}
	if w := call(f.a, "POST", "/api/logout", `{}`, credentials, result.CSRF, f.a.o.origin, "admin.example.com"); w.Code != 200 {
		t.Fatal("Google logout failed")
	}
	if _, valid := f.a.auth(httptest.NewRequest("GET", "/", nil)); valid {
		t.Fatal("unauthenticated request accepted")
	}
	assertGoogleRejection(t, f.callback(state, binding))
}
func TestGoogleStateBindingExpiryAndDeniedIdentity(t *testing.T) {
	f := newGoogleFixture(t)
	for _, mode := range []string{"missing-cookie", "wrong-browser", "wrong-state", "duplicate-state", "expired-state", "unapproved-email", "bad-nonce", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			f.mu.Lock()
			f.mode = mode
			f.mu.Unlock()
			state, binding := f.start(t)
			path := "/auth/google/callback?state=" + state + "&code=good-code"
			switch mode {
			case "missing-cookie":
				binding = ""
			case "wrong-browser":
				binding = googleFlowCookie + "=" + state + "." + randomToken()
			case "wrong-state":
				path = "/auth/google/callback?state=" + randomToken() + "&code=good-code"
			case "duplicate-state":
				path += "&state=" + state
			case "expired-state":
				f.a.google.flows[state].expires = time.Now().Add(-time.Minute)
			}
			w := call(f.a, "GET", path, "", binding, "", "", "admin.example.com")
			assertGoogleRejection(t, w)
			for _, secret := range []string{googleTestSecret, testKey, "good-code", "mallory@example.com"} {
				if strings.Contains(w.Body.String(), secret) {
					t.Fatal("provider credential, code or rejected identity exposed")
				}
			}
		})
	}
}
func TestGoogleJWTClaimAndSignatureRejections(t *testing.T) {
	f := newGoogleFixture(t)
	nonce := randomToken()
	header := map[string]any{"alg": "RS256", "kid": "test-key", "typ": "JWT"}
	if _, err := f.a.google.validateIDToken(context.Background(), f.sign(t, header, f.claims(nonce)), nonce); err != nil {
		t.Fatal("valid signed claims rejected", err)
	}
	cases := []struct {
		name, claim string
		value       any
	}{
		{"wrong issuer", "iss", "https://attacker.example.com"},
		{"wrong audience", "aud", "other.apps.googleusercontent.com"},
		{"wrong authorized party", "azp", "other.apps.googleusercontent.com"},
		{"expired", "exp", time.Now().Unix() - 1},
		{"future issued", "iat", time.Now().Unix() + 120},
		{"future not before", "nbf", time.Now().Unix() + 120},
		{"missing subject", "sub", ""},
		{"wrong nonce", "nonce", randomToken()},
		{"unverified email", "email_verified", false},
		{"string verified email", "email_verified", "true"},
		{"unapproved email", "email", "bob@example.com"},
		{"case changed email", "email", "Alice@example.com"},
		{"domain suffix spoof", "email", "alice@example.com.attacker.example"},
		{"missing Workspace domain", "hd", ""},
		{"wrong Workspace domain", "hd", "attacker.example.com"},
		{"numeric audience", "aud", 12345},
		{"multi-audience no authorized party", "aud", []string{googleTestID, "other"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			claims := f.claims(nonce)
			claims[c.claim] = c.value
			if _, err := f.a.google.validateIDToken(context.Background(), f.sign(t, header, claims), nonce); err == nil {
				t.Fatal("invalid claim accepted")
			}
		})
	}
	for _, alg := range []string{"none", "HS256", "RS512"} {
		h := map[string]any{"alg": alg, "kid": "test-key"}
		if _, err := f.a.google.validateIDToken(context.Background(), f.sign(t, h, f.claims(nonce)), nonce); err == nil {
			t.Fatal("unexpected JWT algorithm accepted")
		}
	}
	token := strings.Split(f.sign(t, header, f.claims(nonce)), ".")
	sig, _ := base64.RawURLEncoding.DecodeString(token[2])
	sig[0] ^= 1
	token[2] = base64.RawURLEncoding.EncodeToString(sig)
	if _, err := f.a.google.validateIDToken(context.Background(), strings.Join(token, "."), nonce); err == nil {
		t.Fatal("forged signature accepted")
	}
	b, _ := json.Marshal(f.claims(nonce))
	b = append(b[:len(b)-1], []byte(`,"aud":"other"}`)...)
	h, _ := json.Marshal(header)
	if _, err := f.a.google.validateIDToken(context.Background(), f.signRaw(t, h, b), nonce); err == nil {
		t.Fatal("duplicate claim accepted")
	}
	claims := f.claims(nonce)
	claims["aud"], claims["azp"] = []string{googleTestID, "other"}, googleTestID
	if _, err := f.a.google.validateIDToken(context.Background(), f.sign(t, header, claims), nonce); err != nil {
		t.Fatal("valid multi-audience authorized party rejected")
	}
}
func TestGoogleFixedDiscoveryAndWeakKeyFailClosed(t *testing.T) {
	for _, mode := range []string{"untrusted-metadata", "weak-key"} {
		t.Run(mode, func(t *testing.T) {
			f := newGoogleFixture(t)
			f.mode = mode
			if mode == "untrusted-metadata" {
				w := call(f.a, "GET", "/auth/google/start", "", "", "", "", "admin.example.com")
				if u := assertGoogleFailureRedirect(t, w); u.Query().Get("reason") != "unavailable" {
					t.Fatal("untrusted discovery was not rejected locally")
				}
			} else {
				nonce := randomToken()
				if _, err := f.a.google.validateIDToken(context.Background(), f.sign(t, map[string]any{"alg": "RS256", "kid": "test-key"}, f.claims(nonce)), nonce); err == nil {
					t.Fatal("unsafe signing key accepted")
				}
			}
		})
	}
}
func TestGoogleCancelledInFlightCallbackCannotCreateSession(t *testing.T) {
	f := newGoogleFixture(t)
	f.started, f.release = make(chan struct{}), make(chan struct{})
	state, binding := f.start(t)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- f.callback(state, binding) }()
	<-f.started
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Cookie", binding)
	f.a.google.cancel(r)
	close(f.release)
	w := <-done
	assertGoogleRejection(t, w)
	if len(f.a.sessions) != 0 {
		t.Fatal("cancelled provider exchange created an administrator session")
	}
}
func TestGoogleConfigIsStrictAndRequiresHTTPSNoFallback(t *testing.T) {
	secret := credential(t, "google", googleTestSecret)
	valid := googleConfig{ClientID: googleTestID, ClientSecretFile: secret, AdminEmails: []string{"alice@example.com"}, IdentityStoreFile: privateFilename(t, "identities.json")}
	b, _ := json.Marshal(valid)
	p := credential(t, "config", string(b))
	for _, origin := range []string{"http://admin.example.com", "http://127.0.0.1:18100", "https://127.0.0.1", "https://localhost"} {
		if _, err := loadGoogle(p, origin); err == nil {
			t.Fatal("unsafe Google browser origin accepted")
		}
	}
	if g, err := loadGoogle(p, "https://admin.example.com"); err != nil {
		t.Fatal("valid Google configuration rejected", err)
	} else {
		g.identityStore.close()
	}
	for _, emails := range [][]string{nil, {"*@example.com"}, {"alice@example.com", "alice@example.com"}, {"Alice@example.com"}, {"Alice <alice@example.com>"}} {
		invalid := valid
		invalid.AdminEmails = emails
		b, _ := json.Marshal(invalid)
		_ = os.WriteFile(p, b, 0600)
		if _, err := loadGoogle(p, "https://admin.example.com"); err == nil {
			t.Fatal("non-exact or missing administrator allowlist accepted")
		}
	}
	_ = os.WriteFile(p, append(b[:len(b)-1], []byte(`,"provider":"https://attacker.example.com"}`)...), 0600)
	if _, err := loadGoogle(p, "https://admin.example.com"); err == nil {
		t.Fatal("runtime provider override accepted")
	}
	_ = os.WriteFile(p, b, 0600)
	if _, err := newApp(options{demo: true, listen: "127.0.0.1:18100", origin: "https://admin.example.com", googleFile: p}); err == nil {
		t.Fatal("Google configuration ignored in demo mode")
	}
	if _, err := newApp(options{listen: "127.0.0.1:18100", origin: "https://admin.example.com", upstream: "http://127.0.0.1:18090", keyFile: credential(t, "api", testKey), googleFile: p, loginFile: credential(t, "login", testLogin)}); err == nil {
		t.Fatal("token fallback accepted alongside Google")
	}
	// Missing secret files are rejected without leaking the path/value.
	valid.ClientSecretFile = filepath.Join(t.TempDir(), "missing")
	b, _ = json.Marshal(valid)
	_ = os.WriteFile(p, b, 0600)
	if _, err := loadGoogle(p, "https://admin.example.com"); err == nil {
		t.Fatal("missing client secret accepted")
	}
}

func TestGoogleDurableIdentityPinsRejectReassignedAddress(t *testing.T) {
	f := newGoogleFixture(t)
	identity := googleIdentity{email: "alice@example.com", subject: "original-google-subject", expires: time.Now().Add(time.Hour)}
	if err := f.a.google.pin(identity); err != nil {
		t.Fatal(err)
	}
	if err := f.a.google.pin(identity); err != nil {
		t.Fatal("same identity rejected", err)
	}
	identity.subject = "reassigned-google-subject"
	if err := f.a.google.pin(identity); err == nil {
		t.Fatal("reassigned address accepted")
	}
	var stored pinnedIdentities
	if exists, err := f.a.google.identityStore.read(&stored); err != nil || !exists || stored.Accounts["alice@example.com"].Subject != "original-google-subject" {
		t.Fatal("identity pin not durable")
	}
	info, err := os.Stat(f.a.google.identityStore.path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("identity pin permissions unsafe")
	}
}
func TestGoogleStartsBoundedWithoutForwardedHeaderTrust(t *testing.T) {
	f := newGoogleFixture(t)
	for i := 0; i < 15; i++ {
		f.start(t)
	}
	r := httptest.NewRequest("GET", "/auth/google/start", nil)
	r.Host = "admin.example.com"
	r.Header.Set("X-Forwarded-For", "198.51.100.99")
	w := httptest.NewRecorder()
	f.a.handler().ServeHTTP(w, r)
	u := assertGoogleFailureRedirect(t, w)
	if u.Query().Get("reason") != "busy" || len(f.a.google.flows) != 15 {
		t.Fatal("start budget bypassed with forwarding header")
	}
	w = call(f.a, "GET", u.String(), "", "", "", "", "admin.example.com")
	if w.Code != 429 || w.Header().Get("Retry-After") != "60" || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
		t.Fatal("start throttling did not display a retryable HTML page")
	}
	if len(f.a.google.flows) >= 1024 {
		t.Fatal("start budget did not bound state")
	}
}
func TestGoogleFailureDiagnosticsAreFiniteAndNeverExposeCredentialsOrClaims(t *testing.T) {
	cases := []struct{ mode, stage string }{
		{"missing-cookie", "transaction_cookie"}, {"state-lost-after-start", "transaction_missing"}, {"expired-state", "transaction_expired"}, {"callback-query", "callback_query"},
		{"token-rejected", "provider_exchange"}, {"untrusted-metadata", "provider_discovery"}, {"malformed-id-token", "id_token_format"}, {"weak-key", "id_token_keys"}, {"bad-signature", "id_token_signature"},
		{"bad-nonce", "claims_nonce"}, {"expired-token", "claims_time"}, {"missing-hd", "claims_workspace_domain"}, {"unverified-email", "claims_email_verified"}, {"unapproved-email", "account_allowlist"}, {"wrong-audience", "claims_audience"}, {"changed-pin", "identity_pin"},
	}
	for _, c := range cases {
		t.Run(c.mode, func(t *testing.T) {
			f := newGoogleFixture(t)
			state, binding := f.start(t)
			f.mu.Lock()
			f.mode = c.mode
			f.mu.Unlock()
			path := "/auth/google/callback?state=" + state + "&code=good-code"
			switch c.mode {
			case "missing-cookie":
				binding = ""
			case "state-lost-after-start":
				f.a.google.mu.Lock()
				f.a.google.flows = map[string]*googleFlow{}
				f.a.google.mu.Unlock()
			case "expired-state":
				f.a.google.flows[state].expires = time.Now().Add(-time.Minute)
			case "callback-query":
				path += "&error=provider-body-secret"
			case "untrusted-metadata":
				f.a.google.metadataUntil = time.Time{}
			case "changed-pin":
				f.a.google.identities.Accounts["alice@example.com"] = pinnedIdentity{Issuer: productionGoogle.issuer, Subject: "previous-private-subject"}
			}
			w := call(f.a, "GET", path, "", binding, "", "", "admin.example.com")
			u := assertGoogleRejection(t, w)
			want := "google_auth result=rejected stage=" + c.stage + " reference=" + u.Query().Get("ref") + "\n"
			if f.logs.String() != want {
				t.Fatalf("unexpected diagnostic classification: %q", f.logs.String())
			}
			for _, private := range []string{googleTestID, googleTestSecret, testKey, "good-code", "alice@example.com", "mallory@example.com", "test-google-subject", "previous-private-subject", "provider-body-secret", "opaque-fixture-id-token", state, f.nonce, f.verifier} {
				if strings.Contains(f.logs.String(), private) || strings.Contains(w.Body.String(), private) {
					t.Fatal("authentication diagnostic exposed private input")
				}
			}
		})
	}
}
func TestGoogleErrorPageAndCorrelation(t *testing.T) {
	f := newGoogleFixture(t)
	f.a.o.publicSite = "https://control.example.com"
	state, binding := f.start(t)
	f.mu.Lock()
	f.mode = "unapproved-email"
	f.mu.Unlock()
	u := assertGoogleRejection(t, f.callback(state, binding))
	if u.Query().Get("reason") != "account-not-approved" || !strings.Contains(f.logs.String(), "reference="+u.Query().Get("ref")) {
		t.Fatal("error reference did not identify its backend diagnostic")
	}
	w := call(f.a, "GET", u.String(), "", "", "", "", "admin.example.com")
	if w.Code != http.StatusForbidden || w.Header().Get("Content-Type") != "text/html; charset=utf-8" || sessionCookie(w) != nil {
		t.Fatal("error page is not unauthenticated HTML")
	}
	for _, expected := range []string{"Sign-in unsuccessful", "approved administrator account", u.Query().Get("ref"), `href="/auth/google/start"`, `href="/start"`, "https://control.example.com/privacy"} {
		if !strings.Contains(w.Body.String(), expected) {
			t.Fatal("error page missing safe retry, disclosure or correlation")
		}
	}
	for _, forbidden := range []string{"console-header", "data-page", "<script", "good-code", state, "mallory@example.com", "alice@example.com", googleTestSecret} {
		if strings.Contains(w.Body.String(), forbidden) || strings.Contains(u.String(), forbidden) {
			t.Fatal("error page exposed console or private callback data")
		}
	}
	// Untrusted query text must never become page content or a redirect target.
	w = call(f.a, "GET", "/auth/google/error?reason="+url.QueryEscape(`<script>location='https://evil.example.com'</script>`)+"&ref="+url.QueryEscape(`<img src=x onerror=alert(1)>`), "", "", "", "", "admin.example.com")
	if strings.Contains(w.Body.String(), "evil.example.com") || strings.Contains(w.Body.String(), "onerror") || w.Header().Get("Location") != "" {
		t.Fatal("error page reflected attacker input")
	}
	first := f.a.google.diagnose(googleTransactionCookie)
	second := f.a.google.diagnose(googleTransactionCookie)
	if first != second || strings.Count(f.logs.String(), "stage=transaction_cookie") != 1 {
		t.Fatal("throttled diagnostics lost correlation or became unbounded")
	}
	f.a.google.diagnosticMu.Lock()
	f.a.google.diagnosticUntil[googleTransactionCookie] = googleDiagnosticRecord{}
	f.a.google.diagnosticMu.Unlock()
	third := f.a.google.diagnose(googleTransactionCookie)
	if third == first || !googleReferencePattern.MatchString(third) {
		t.Fatal("new diagnostic window reused its old reference")
	}
}
func TestGoogleSessionCapacityProducesCorrelatedHTMLWithoutSession(t *testing.T) {
	f := newGoogleFixture(t)
	state, binding := f.start(t)
	for i := 0; i < 1024; i++ {
		f.a.sessions[fmt.Sprint(i)] = session{expires: time.Now().Add(time.Hour)}
	}
	u := assertGoogleRejection(t, f.callback(state, binding))
	if u.Query().Get("reason") != "unavailable" || len(f.a.sessions) != 1024 || !strings.Contains(f.logs.String(), "stage=session_issue reference="+u.Query().Get("ref")) {
		t.Fatal("session capacity bypassed or correlation missing")
	}
	w := call(f.a, "GET", u.String(), "", "", "", "", "admin.example.com")
	if w.Code != 503 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") || w.Header().Get("Retry-After") != "60" {
		t.Fatal("session failure returned raw JSON")
	}
}
func TestGoogleDiagnosticRateAndUnknownErrorsStayBounded(t *testing.T) {
	f := newGoogleFixture(t)
	for i := 0; i < 100; i++ {
		f.a.google.diagnose(googleTransactionMissing)
	}
	if strings.Count(f.logs.String(), "transaction_missing") != 1 {
		t.Fatal("authentication diagnostic spam was not bounded")
	}
	f.a.google.diagnose(googleErrorStage(errors.New("private-provider-body-secret")))
	f.a.google.diagnose(googleDiagnostic(255))
	if strings.Count(f.logs.String(), "stage=internal") != 1 || strings.Contains(f.logs.String(), "private-provider-body-secret") || len(f.a.google.diagnosticUntil) > 2 {
		t.Fatal("unknown diagnostics leaked values or unbounded categories")
	}
}
