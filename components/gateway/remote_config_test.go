package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRemoteRuleLifecycle(t *testing.T) {
	rule := remoteRule{Version: 1, Gateway: "gateway", Revision: 1, Enabled: true, AllowedUsers: []string{"alice@example.com"}}
	code := 200
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-credential" {
			t.Error("missing credential")
		}
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(rule)
	}))
	defer server.Close()
	reader := newConfigReader(&configSource{URL: server.URL, Gateway: "gateway"})
	reader.client = server.Client()
	read := func(want bool) {
		t.Helper()
		users, err := reader.fetch(context.Background(), "test-credential")
		if want {
			if err != nil || len(users) != 1 || users[0] != "alice@example.com" {
				t.Fatal(users, err)
			}
		} else if len(users) != 0 {
			t.Fatal("access remained open")
		}
	}
	read(true)
	rule.Revision++
	rule.Enabled = false
	read(false)
	rule.Revision++
	rule.Enabled = true
	read(true)
	rule.Revision++
	rule.AllowedUsers = nil
	read(false)
	rule.Revision++
	rule.AllowedUsers = []string{"alice@example.com"}
	read(true)
	code = 503
	read(false)
	code = 200
	read(true)
	rule.Revision--
	read(false)
	rule.Revision++
	rule.AllowedUsers = []string{"other@example.com"}
	read(false)
	rule.Revision++
	rule.Gateway = "wrong"
	read(false)
	rule.Gateway = "gateway"
	rule.AllowedUsers = []string{"*"}
	read(false)
	rule.AllowedUsers = []string{"alice@example.com", "alice@example.com"}
	read(false)
	rule.AllowedUsers = []string{"alice@example.com"}
	rule.Version = 2
	read(false)
}
func TestRemoteTransportFailsClosed(t *testing.T) {
	for _, payload := range []string{`{}`, `{"version":1,"gateway":"g","revision":1,"enabled":true,"allowed_users":["alice@example.com"],"unknown":1}`, `{"version":1,"gateway":"g","revision":1,"enabled":true,"allowed_users":["alice@example.com"]} {}`} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(payload)) }))
		reader := newConfigReader(&configSource{URL: server.URL, Gateway: "g"})
		reader.client = server.Client()
		if users, err := reader.fetch(context.Background(), "token"); err == nil || len(users) != 0 {
			t.Fatal("malformed response accepted")
		}
		server.Close()
	}
	leaked := false
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = true }))
	defer target.Close()
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 302) }))
	defer redirect.Close()
	reader := newConfigReader(&configSource{URL: redirect.URL, Gateway: "g"})
	reader.client.Transport = redirect.Client().Transport
	if _, err := reader.fetch(context.Background(), "token"); err == nil || leaked {
		t.Fatal("redirect accepted")
	}
	reader = newConfigReader(&configSource{URL: redirect.URL, Gateway: "g"})
	if _, err := reader.fetch(context.Background(), "token"); err == nil {
		t.Fatal("untrusted TLS accepted")
	}
	slow := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer slow.Close()
	reader = newConfigReader(&configSource{URL: slow.URL, Gateway: "g"})
	reader.client.Transport = slow.Client().Transport
	reader.client.Timeout = 30 * time.Millisecond
	if _, err := reader.fetch(context.Background(), "token"); err == nil {
		t.Fatal("timeout accepted")
	}
}
func TestRemoteSecretUnavailableDoesNotFallback(t *testing.T) {
	reader := newConfigReader(&configSource{TokenFile: filepath.Join(t.TempDir(), "token")})
	if users := reader.users(context.Background()); len(users) != 0 {
		t.Fatal("missing secret opened gate")
	}
	if err := os.WriteFile(reader.source.TokenFile, []byte("test-credential-long-enough-for-config"), 0644); err != nil {
		t.Fatal(err)
	}
	if users := reader.users(context.Background()); len(users) != 0 {
		t.Fatal("unsafe secret opened gate")
	}
}
func TestRemoteConfigBootstrapValidation(t *testing.T) {
	good := configSource{URL: "https://console.example.com/gateway-config/v1/gateway", Gateway: "gateway", TokenFile: "/secrets/config-token"}
	if err := good.validate(); err != nil {
		t.Fatal(err)
	}
	for _, url := range []string{"http://console.example.com/gateway-config/v1/gateway", "https://user@console.example.com/gateway-config/v1/gateway", "https://console.example.com/gateway-config/v1/other", good.URL + "?", good.URL + "?x=1", good.URL + "#x"} {
		bad := good
		bad.URL = url
		if bad.validate() == nil {
			t.Fatal("unsafe source", url)
		}
	}
}
