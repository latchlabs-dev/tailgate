package main

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const bridgeTestToken = "disposable-bridge-reader-credential-long-enough"

func bridgeFixture(t *testing.T) (*app, string, string, string) {
	t.Helper()
	a := testApp(t, "http://127.0.0.1:1", false)
	a.o.configWrites = true
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	cfg := map[string]any{"state_path": filepath.Join(dir, "bridge.json"), "gateways": []map[string]string{{"id": "test-gateway", "token_file": credential(t, "reader", bridgeTestToken)}, {"id": "other-gateway", "token_file": credential(t, "other-reader", bridgeTestToken+"-other")}}}
	b, _ := json.Marshal(cfg)
	path := credential(t, "registry.json", string(b))
	var err error
	a.bridge, err = loadBridgeService(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.bridge.store.close() })
	cookie, csrf := authorized(t, a)
	return a, cookie, csrf, path
}
func gatewayRead(a *app, id, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "/gateway-config/v1/"+id, nil)
	r.Host = "127.0.0.1:18100"
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	a.handler().ServeHTTP(w, r)
	return w
}
func TestBridgeConfigAuthorizationPersistenceAndConflict(t *testing.T) {
	a, cookie, csrf, path := bridgeFixture(t)
	save := func(payload string) *httptest.ResponseRecorder {
		return call(a, "POST", "/api/bridge-config", payload, cookie, csrf, a.o.origin, "127.0.0.1:18100")
	}
	if r := gatewayRead(a, "test-gateway", bridgeTestToken); r.Code != 200 || !strings.Contains(r.Body.String(), `"enabled":false`) {
		t.Fatal("not initially closed")
	}
	for _, c := range []struct{ id, token string }{{"other-gateway", bridgeTestToken}, {"test-gateway", "bad"}, {"missing", bridgeTestToken}} {
		if r := gatewayRead(a, c.id, c.token); r.Code != 401 {
			t.Fatal("reader scope bypass")
		}
	}
	payload := `{"id":"test-gateway","revision":1,"enabled":true,"allowed_users":["alice@example.com"]}`
	if r := call(a, "POST", "/api/bridge-config", payload, "", csrf, a.o.origin, "127.0.0.1:18100"); r.Code != 401 {
		t.Fatal("unauthenticated write")
	}
	if r := call(a, "POST", "/api/bridge-config", payload, cookie, "bad", a.o.origin, "127.0.0.1:18100"); r.Code != 403 {
		t.Fatal("CSRF bypass")
	}
	if r := call(a, "POST", "/api/bridge-config", payload, cookie, csrf, "https://evil.example", "127.0.0.1:18100"); r.Code != 403 {
		t.Fatal("origin bypass")
	}
	member := session{id: "member", csrf: "member-csrf", email: "member@example.com", member: true, expires: time.Now().Add(time.Hour)}
	a.sessions[member.id] = member
	if r := call(a, "GET", "/api/bridge-config", "", a.sessionCookieName()+"="+member.id, "", "", "127.0.0.1:18100"); r.Code != 403 {
		t.Fatal("member read bypass")
	}
	if r := call(a, "POST", "/api/bridge-config", payload, a.sessionCookieName()+"="+member.id, member.csrf, a.o.origin, "127.0.0.1:18100"); r.Code != 403 {
		t.Fatal("member write bypass")
	}
	a.o.configWrites = false
	if r := save(payload); r.Code != 403 {
		t.Fatal("read-only bypass")
	}
	a.o.configWrites = true
	for _, users := range []string{`["*"]`, `["tag:bridge"]`, `["Alice@example.com"]`, `["alice@example.com","alice@example.com"]`} {
		if r := save(`{"id":"test-gateway","revision":1,"enabled":true,"allowed_users":` + users + `}`); r.Code != 400 {
			t.Fatal("invalid rule accepted", users, r.Code)
		}
	}
	if r := save(payload); r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	if r := save(payload); r.Code != 409 {
		t.Fatal("stale edit accepted")
	}
	if r := gatewayRead(a, "test-gateway", bridgeTestToken); r.Code != 200 || !strings.Contains(r.Body.String(), "alice@example.com") || strings.Contains(r.Body.String(), "audit") {
		t.Fatal("wrong reader projection")
	}
	a.bridge.store.close()
	svc, err := loadBridgeService(path)
	if err != nil {
		t.Fatal(err)
	}
	a.bridge = svc
	if svc.state.Revision != 2 || len(svc.state.Audit) != 1 || svc.state.Audit[0].Rule.AllowedUsers[0] != "alice@example.com" {
		t.Fatal("state/audit not durable")
	}
	if r := save(`{"id":"test-gateway","revision":2,"enabled":false,"allowed_users":[]}`); r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	if r := gatewayRead(a, "test-gateway", bridgeTestToken); !strings.Contains(r.Body.String(), `"enabled":false`) {
		t.Fatal("disable not published")
	}
}
func TestBridgeStorageFailureClosesReader(t *testing.T) {
	a, cookie, csrf, _ := bridgeFixture(t)
	a.bridge.store.path = filepath.Join(t.TempDir(), "missing", "state.json")
	r := call(a, "POST", "/api/bridge-config", `{"id":"test-gateway","revision":1,"enabled":true,"allowed_users":["alice@example.com"]}`, cookie, csrf, a.o.origin, "127.0.0.1:18100")
	if r.Code != 503 || gatewayRead(a, "test-gateway", bridgeTestToken).Code != 503 {
		t.Fatal("storage failure did not block service")
	}
}

func TestBridgeAuditBudgetDoesNotInterruptService(t *testing.T) {
	a, cookie, csrf, _ := bridgeFixture(t)
	rule := bridgeRule{Enabled: true}
	for i := 0; i < 120; i++ {
		rule.AllowedUsers = append(rule.AllowedUsers, fmt.Sprintf("person%d@example.com", i))
	}
	for i := 0; i < 512; i++ {
		a.bridge.state.Audit = append(a.bridge.state.Audit, bridgeAudit{At: "2026-01-01T00:00:00Z", Actor: "admin@example.com", Gateway: "test-gateway", Revision: 1, Rule: rule})
	}
	r := call(a, "POST", "/api/bridge-config", `{"id":"test-gateway","revision":1,"enabled":true,"allowed_users":["alice@example.com"]}`, cookie, csrf, a.o.origin, "127.0.0.1:18100")
	if r.Code != 200 || a.bridge.blocked || len(a.bridge.state.Audit) >= 512 {
		t.Fatal("audit growth blocked configuration", r.Code)
	}
	if r := gatewayRead(a, "test-gateway", bridgeTestToken); r.Code != 200 {
		t.Fatal("audit growth blocked readers")
	}
}
