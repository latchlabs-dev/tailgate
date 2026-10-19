package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const testLogin = "test-only-administrator-token-32-characters"
const testKey = "test-only-headscale-key"

func credential(t *testing.T, name, value string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if e := os.WriteFile(p, []byte(value), 0600); e != nil {
		t.Fatal(e)
	}
	return p
}
func testApp(t *testing.T, upstream string, writes bool) *app {
	t.Helper()
	a, e := newApp(options{listen: "127.0.0.1:18100", origin: "http://127.0.0.1:18100", upstream: upstream, keyFile: credential(t, "api", testKey), loginFile: credential(t, "login", testLogin), writes: writes})
	if e != nil {
		t.Fatal(e)
	}
	return a
}
func call(a *app, method, path, payload, cookie, csrf, origin, host string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(payload))
	r.Host = host
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", origin)
	r.Header.Set("X-CSRF-Token", csrf)
	if cookie != "" {
		r.Header.Set("Cookie", cookie)
	}
	w := httptest.NewRecorder()
	a.handler().ServeHTTP(w, r)
	return w
}
func authorized(t *testing.T, a *app) (string, string) {
	t.Helper()
	w := call(a, "POST", "/api/login", `{"token":"`+testLogin+`"}`, "", "", a.o.origin, "127.0.0.1:18100")
	if w.Code != 200 {
		t.Fatalf("login status %d", w.Code)
	}
	var result struct {
		CSRF string `json:"csrf"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	cookie := w.Result().Cookies()[0]
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Value == testLogin {
		t.Fatal("unsafe cookie")
	}
	return cookie.Name + "=" + cookie.Value, result.CSRF
}

func TestRejectUnsafeStartup(t *testing.T) {
	for _, listen := range []string{"0.0.0.0:18100", "localhost:18100", "[::]:18100"} {
		if _, e := newApp(options{demo: true, listen: listen, origin: "http://127.0.0.1:18100"}); e == nil {
			t.Fatal("unsafe listener accepted")
		}
	}
	for _, origin := range []string{"https://example.com/", "https://user@example.com", "https://example.com?token=x", "https://example.com#fragment"} {
		if _, e := newApp(options{demo: true, listen: "127.0.0.1:18100", origin: origin}); e == nil {
			t.Fatal("invalid origin accepted")
		}
	}
	p := credential(t, "bad", "long-enough-but-world-readable-secret")
	_ = os.Chmod(p, 0644)
	if _, e := secret(p, 16); e == nil {
		t.Fatal("world-readable credential accepted")
	}
	if _, e := newApp(options{listen: "127.0.0.1:18100", origin: "http://127.0.0.1:18100", upstream: "http://example.com"}); e == nil {
		t.Fatal("nonlocal cleartext API accepted")
	}
}
func TestPublicInformationOriginIsStrictAndSeparate(t *testing.T) {
	base := options{demo: true, listen: "127.0.0.1:18100", origin: "https://console.example.com", publicSite: "https://control.example.com/"}
	a, err := newApp(base)
	if err != nil || a.o.publicSite != "https://control.example.com" {
		t.Fatal("valid public origin rejected")
	}
	for _, site := range []string{"http://example.com", "javascript:alert(1)", "https://user:password@example.com", "https://example.com/path", "https://example.com?secret=x", "https://127.0.0.1", "https://console.example.com", "https://example.com:8443", "https://app.localhost"} {
		o := base
		o.publicSite = site
		if _, err := newApp(o); err == nil {
			t.Fatalf("unsafe public origin accepted %s", site)
		}
	}
}
func TestPublicInformationAndGoogleAssetNeverExposeInventory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("public metadata requested live inventory")
		w.WriteHeader(500)
	}))
	defer server.Close()
	a, err := newApp(options{listen: "127.0.0.1:18100", origin: "http://127.0.0.1:18100", upstream: server.URL, keyFile: credential(t, "api", testKey), loginFile: credential(t, "login", testLogin), publicSite: "https://control.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	r := call(a, "GET", "/api/session", "", "", "", a.o.origin, "127.0.0.1:18100")
	if r.Code != 200 || !strings.Contains(r.Body.String(), `"publicSiteURL":"https://control.example.com"`) || strings.Contains(r.Body.String(), testKey) || strings.Contains(r.Body.String(), "nodes") {
		t.Fatal("unexpected public metadata")
	}
	r = call(a, "GET", "/google-sign-in.png", "", "", "", a.o.origin, "127.0.0.1:18100")
	if r.Code != 200 || r.Header().Get("Content-Type") != "image/png" || fmt.Sprintf("%x", sha256.Sum256(r.Body.Bytes())) != "892062091f35e69dd838ba4a4f238d37a0562d52ecda6406eb343a1127251409" {
		t.Fatal("official locally served button differs")
	}
	r = call(a, "GET", "/api/snapshot", "", "", "", a.o.origin, "127.0.0.1:18100")
	if r.Code != 401 {
		t.Fatal("public pages bypassed inventory authentication")
	}
}
func TestAuthenticationHostOriginAndCSRF(t *testing.T) {
	u := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, `{"nodes":[],"users":[]}`) }))
	defer u.Close()
	a := testApp(t, u.URL, true)
	checks := []struct {
		method, path, body, origin, host string
		status                           int
	}{
		{"GET", "/api/snapshot", "", "", "127.0.0.1:18100", 401},
		{"GET", "/api/session", "", "", "attacker.example", 403},
		{"POST", "/api/login", `{"token":"` + testLogin + `"}`, "http://attacker.example", "127.0.0.1:18100", 403},
		{"POST", "/api/login", `{"token":"wrong"}`, a.o.origin, "127.0.0.1:18100", 401},
		{"POST", "/api/login", `{"token":"x","extra":true}`, a.o.origin, "127.0.0.1:18100", 400},
	}
	for _, v := range checks {
		w := call(a, v.method, v.path, v.body, "", "", v.origin, v.host)
		if w.Code != v.status {
			t.Fatalf("%s status %d, want %d", v.path, w.Code, v.status)
		}
	}
	cookie, csrf := authorized(t, a)
	if w := call(a, "POST", "/api/machines/1/delete", `{"confirmation":"device"}`, cookie, "wrong", a.o.origin, "127.0.0.1:18100"); w.Code != 403 {
		t.Fatal("CSRF accepted")
	}
	if w := call(a, "POST", "/api/logout", `{}`, cookie, csrf, a.o.origin, "127.0.0.1:18100"); w.Code != 200 {
		t.Fatal("logout failed")
	}
	if w := call(a, "GET", "/api/snapshot", "", cookie, "", "", "127.0.0.1:18100"); w.Code != 401 {
		t.Fatal("logout did not revoke session")
	}
}
func TestCredentialProjectionAndReadOnlyDefault(t *testing.T) {
	u := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testKey {
			t.Error("missing server-side API authorization")
		}
		switch r.URL.Path {
		case "/api/v1/node":
			_, _ = io.WriteString(w, `{"nodes":[{"id":"1","givenName":"device","preAuthKey":{"key":"must-never-be-sent"},"machineKey":"hidden-machine","nodeKey":"hidden-node","discoKey":"hidden-disco","user":{"id":"1","name":"alice","providerId":"private-provider-id"}}]}`)
		case "/api/v1/user":
			_, _ = io.WriteString(w, `{"users":[{"id":"1","name":"alice","providerId":"private-provider-id"}]}`)
		}
	}))
	defer u.Close()
	a := testApp(t, u.URL, false)
	cookie, csrf := authorized(t, a)
	w := call(a, "GET", "/api/snapshot", "", cookie, "", "", "127.0.0.1:18100")
	if w.Code != 200 {
		t.Fatal("snapshot failed")
	}
	for _, s := range []string{testKey, testLogin, "must-never-be-sent", "hidden-machine", "hidden-node", "hidden-disco", "private-provider-id"} {
		if strings.Contains(w.Body.String(), s) {
			t.Fatal("private value exposed")
		}
	}
	if w := call(a, "POST", "/api/machines/1/delete", `{"confirmation":"device"}`, cookie, csrf, a.o.origin, "127.0.0.1:18100"); w.Code != 403 {
		t.Fatal("read-only default bypassed")
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatal("missing browser isolation")
	}
}
func TestMutationAllowlistAndConfirmation(t *testing.T) {
	var actions []string
	u := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			_, _ = io.WriteString(w, `{"node":{"id":"1","givenName":"device"}}`)
			return
		}
		actions = append(actions, r.Method+" "+r.URL.Path)
		_, _ = io.WriteString(w, `{}`)
	}))
	defer u.Close()
	a := testApp(t, u.URL, true)
	cookie, csrf := authorized(t, a)
	for _, v := range []struct {
		path, body string
		status     int
	}{
		{"/api/machines/1/delete", `{"confirmation":"wrong"}`, 409},
		{"/api/machines/1/rename", `{"name":"../../api/v1/user"}`, 400},
		{"/api/machines/abc/delete", `{}`, 400},
		{"/api/machines/1/tags", `{}`, 404},
		{"/api/machines/1/rename", `{"name":"new-name"}`, 200},
		{"/api/machines/1/expire", `{"confirmation":"device"}`, 200},
		{"/api/machines/1/delete", `{"confirmation":"device"}`, 200},
	} {
		w := call(a, "POST", v.path, v.body, cookie, csrf, a.o.origin, "127.0.0.1:18100")
		if w.Code != v.status {
			t.Fatalf("status for %s: %d", v.path, w.Code)
		}
	}
	if strings.Join(actions, "|") != "POST /api/v1/node/1/rename/new-name|POST /api/v1/node/1/expire|DELETE /api/v1/node/1" {
		t.Fatal("unexpected mutation mapping")
	}
}
func TestRedirectAndErrorDoNotLeakCredential(t *testing.T) {
	received := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { received = true }))
	defer target.Close()
	u := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 302) }))
	defer u.Close()
	a := testApp(t, u.URL, false)
	if e := a.upstream("GET", "/api/v1/node", nil, &struct{}{}); e == nil {
		t.Fatal("redirect accepted")
	}
	if received {
		t.Fatal("followed redirect with API credential")
	}
	u.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500); _, _ = io.WriteString(w, testKey) })
	if e := a.upstream("GET", "/api/v1/node", nil, &struct{}{}); e == nil || strings.Contains(e.Error(), testKey) {
		t.Fatal("upstream error handling failed")
	}
}
func TestLoginRateLimit(t *testing.T) {
	u := httptest.NewServer(http.NotFoundHandler())
	defer u.Close()
	a := testApp(t, u.URL, false)
	for i := 0; i < 6; i++ {
		w := call(a, "POST", "/api/login", `{"token":"wrong"}`, "", "", a.o.origin, "127.0.0.1:18100")
		expected := 401
		if i == 5 {
			expected = 429
		}
		if w.Code != expected {
			t.Fatalf("attempt %d status %d", i, w.Code)
		}
	}
}
func TestDemoIsolationConcurrentActions(t *testing.T) {
	a, e := newApp(options{listen: "127.0.0.1:18100", origin: "http://127.0.0.1:18100", demo: true})
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			path, payload, method := "/api/snapshot", "", "GET"
			if i%2 == 0 {
				path = "/api/machines/1/rename"
				payload = fmt.Sprintf(`{"name":"device-%d"}`, i)
				method = "POST"
			}
			w := call(a, method, path, payload, "", "local-demo", a.o.origin, "127.0.0.1:18100")
			if w.Code != 200 {
				t.Errorf("demo status %d", w.Code)
			}
		}(i)
	}
	wg.Wait()
	if a.o.keyFile != "" || a.o.upstream != "" {
		t.Fatal("demo connected to upstream")
	}
}

func TestCorrectTokenSurvivesSharedSourceInvalidAttemptBudget(t *testing.T) {
	u := httptest.NewServer(http.NotFoundHandler())
	defer u.Close()
	a := testApp(t, u.URL, false)
	for i := 0; i < 8; i++ {
		w := call(a, "POST", "/api/login", `{"token":"wrong"}`, "", "", a.o.origin, "127.0.0.1:18100")
		if (i < 5 && w.Code != 401) || (i >= 5 && w.Code != 429) {
			t.Fatalf("invalid attempt %d returned %d", i, w.Code)
		}
	}
	cookie, _ := authorized(t, a)
	if cookie == "" {
		t.Fatal("correct credential locked out by shared source")
	}
	if w := call(a, "POST", "/api/login", `{"token":"wrong"}`, "", "", a.o.origin, "127.0.0.1:18100"); w.Code != 429 {
		t.Fatal("valid login must not erase the invalid-attempt budget")
	}
}

func TestHeadscaleAPIKeyRotationAndFailClosed(t *testing.T) {
	var received []string
	u := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = append(received, r.Header.Get("Authorization"))
		_, _ = io.WriteString(w, `{}`)
	}))
	defer u.Close()
	a := testApp(t, u.URL, false)
	cookie, _ := authorized(t, a)
	if e := a.upstream("GET", "/api/v1/node", nil, nil); e != nil {
		t.Fatal(e)
	}
	rotated := a.o.keyFile + ".replacement"
	if e := os.WriteFile(rotated, []byte("rotated-test-only-api-key"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Rename(rotated, a.o.keyFile); e != nil {
		t.Fatal(e)
	}
	if e := a.upstream("GET", "/api/v1/node", nil, nil); e != nil {
		t.Fatal(e)
	}
	for _, corrupt := range []string{"short", "long-enough-but\nmultiple-lines"} {
		if e := os.WriteFile(a.o.keyFile, []byte(corrupt), 0600); e != nil {
			t.Fatal(e)
		}
		if e := a.upstream("GET", "/api/v1/node", nil, nil); e == nil {
			t.Fatal("malformed replacement credential accepted")
		}
	}
	if e := os.WriteFile(a.o.keyFile, []byte("rotated-test-only-api-key"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(a.o.keyFile, 0644); e != nil {
		t.Fatal(e)
	}
	if e := a.upstream("GET", "/api/v1/node", nil, nil); e == nil {
		t.Fatal("overly permissive replacement credential accepted")
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Cookie", cookie)
	if _, valid := a.auth(r); !valid {
		t.Fatal("API-key rotation incorrectly revoked browser session")
	}
	if e := os.Remove(a.o.keyFile); e != nil {
		t.Fatal(e)
	}
	if e := a.upstream("GET", "/api/v1/node", nil, nil); e == nil {
		t.Fatal("missing credential used cached old key")
	}
	if strings.Join(received, "|") != "Bearer "+testKey+"|Bearer rotated-test-only-api-key" {
		t.Fatal("rotation was not applied, or invalid key reached upstream")
	}
}
