package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func memberSession(t *testing.T, a *app, email, subject string, member bool) (string, string) {
	t.Helper()
	w := httptest.NewRecorder()
	s, ok := a.issueRoleSession(w, email, subject, time.Now().Add(time.Hour), member)
	if !ok {
		t.Fatal("session not issued")
	}
	c := w.Result().Cookies()[0]
	return c.Name + "=" + c.Value, s.csrf
}
func memberFixture(t *testing.T) (*approvalFixture, string, string, string, string) {
	f := newApprovalFixture(t)
	f.a.google = &googleAuth{admins: map[string]bool{"admin@example.com": true}, memberDomains: map[string]bool{"example.com": true}}
	member, token := memberSession(t, f.a, "alice@example.com", "alice-subject", true)
	admin, adminToken := memberSession(t, f.a, "admin@example.com", "admin-subject", false)
	return f, member, token, admin, adminToken
}
func TestMemberCannotReadInventoryOrApproveAndCannotForgeIdentity(t *testing.T) {
	f, member, csrf, _, _ := memberFixture(t)
	for _, path := range []string{"/api/snapshot", "/api/workflow", "/api/workflow/approve", "/api/requests/review", "/api/machines/1/delete"} {
		method := "GET"
		if strings.Contains(path, "approve") || strings.Contains(path, "review") || strings.Contains(path, "delete") {
			method = "POST"
		}
		w := call(f.a, method, path, `{}`, member, csrf, f.a.o.origin, "127.0.0.1:18100")
		if w.Code != 403 {
			t.Fatalf("member reached %s: %d", path, w.Code)
		}
	}
	for _, payload := range []string{`{"reason":"Work","subject":"bob-subject"}`, `{"reason":"Work","email":"bob@example.com"}`, `{"reason":"Work","status":"approved"}`} {
		if w := call(f.a, "POST", "/api/member/request", payload, member, csrf, f.a.o.origin, "127.0.0.1:18100"); w.Code != 400 {
			t.Fatal("client supplied identity accepted")
		}
	}
	if w := call(f.a, "POST", "/api/member/request", `{"reason":"Work"}`, member, "bad-csrf", f.a.o.origin, "127.0.0.1:18100"); w.Code != 403 {
		t.Fatal("missing CSRF accepted")
	}
	if w := call(f.a, "GET", "/api/member", "", "", "", "", "127.0.0.1:18100"); w.Code != 401 {
		t.Fatal("anonymous request history exposed")
	}
}
func TestCompanyRequestPersistsIsPrivateAndReviewNeverGrantsNetworkAccess(t *testing.T) {
	f, member, csrf, admin, adminCSRF := memberFixture(t)
	submit := func() *httptest.ResponseRecorder {
		return call(f.a, "POST", "/api/member/request", `{"reason":"Need the work dashboard"}`, member, csrf, f.a.o.origin, "127.0.0.1:18100")
	}
	if w := submit(); w.Code != 201 {
		t.Fatalf("submit: %d %s", w.Code, w.Body.String())
	}
	if w := submit(); w.Code != 200 || len(f.a.workflow.state.Requests) != 1 {
		t.Fatal("duplicate request created")
	}
	id := f.a.workflow.state.Requests[0].ID
	other, _ := memberSession(t, f.a, "bob@example.com", "bob-subject", true)
	w := call(f.a, "GET", "/api/member", "", other, "", "", "127.0.0.1:18100")
	if strings.Contains(w.Body.String(), id) || strings.Contains(w.Body.String(), "alice@example.com") {
		t.Fatal("another member's request exposed")
	}
	view, err := f.a.workflowSnapshot(context.Background())
	if err != nil || len(view.Requests) != 1 || view.Requests[0].Email != "alice@example.com" {
		t.Fatal("request absent from administrator queue")
	}
	payload := `{"id":"` + id + `","decision":"approved","note":"Please set up your laptop"}`
	w = call(f.a, "POST", "/api/requests/review", payload, admin, adminCSRF, f.a.o.origin, "127.0.0.1:18100")
	if w.Code != 200 {
		t.Fatalf("review: %d %s", w.Code, w.Body.String())
	}
	if len(f.mutations) != 0 || f.policy != `{"grants":[]}` || f.a.workflow.state.Revision != 0 {
		t.Fatal("company request changed network permissions")
	}
	var stored workflowState
	b, _ := os.ReadFile(f.ledgerPath)
	if json.Unmarshal(b, &stored) != nil || stored.Requests[0].Status != "approved" || stored.Requests[0].Reviewer != "admin@example.com [admin-subject]" {
		t.Fatal("review did not persist")
	}
	w = call(f.a, "GET", "/api/member", "", member, "", "", "127.0.0.1:18100")
	if !strings.Contains(w.Body.String(), `"approved":true`) || strings.Contains(w.Body.String(), "admin@example.com") {
		t.Fatal("wrong member projection")
	}
	w = call(f.a, "POST", "/api/requests/review", payload, admin, adminCSRF, f.a.o.origin, "127.0.0.1:18100")
	if w.Code != 409 {
		t.Fatal("review can be repeated or overwritten")
	}
	// Reload from disk under the same permissions and locking rules as a restart.
	f.a.workflow.store.close()
	store, err := openPrivateState(f.ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	f.a.workflow.store = store
	var reloaded workflowState
	if ok, err := store.read(&reloaded); !ok || err != nil || reloaded.Requests[0].Status != "approved" {
		t.Fatal("request lost at restart")
	}
}
func TestFailedCompanyReviewDoesNotPublishAnApproval(t *testing.T) {
	f, member, csrf, admin, adminCSRF := memberFixture(t)
	call(f.a, "POST", "/api/member/request", `{"reason":"Work"}`, member, csrf, f.a.o.origin, "127.0.0.1:18100")
	id := f.a.workflow.state.Requests[0].ID
	original := f.a.workflow.store.path
	f.a.workflow.store.path = original + "/missing/ledger.json"
	w := call(f.a, "POST", "/api/requests/review", `{"id":"`+id+`","decision":"approved"}`, admin, adminCSRF, f.a.o.origin, "127.0.0.1:18100")
	f.a.workflow.store.path = original
	if w.Code != 503 || f.a.workflow.state.Requests[0].Status != "pending" {
		t.Fatal("failed write published approval")
	}
}
func TestMemberGoogleFlowAcceptsCompanyAccountWithoutAdminElevation(t *testing.T) {
	f := newGoogleFixture(t)
	workflow := newApprovalFixture(t)
	f.a.workflow = workflow.a.workflow
	f.a.google.memberDomains = map[string]bool{"example.com": true}
	f.mode = "unapproved-email"
	w := call(f.a, "GET", "/auth/google/member/start", "", "", "", "", "admin.example.com")
	u, _ := url.Parse(w.Header().Get("Location"))
	if w.Code != 303 {
		t.Fatalf("member login start %d", w.Code)
	}
	flow := f.a.google.flows[u.Query().Get("state")]
	if !flow.member {
		t.Fatal("member purpose not bound to OAuth state")
	}
	f.nonce, f.verifier = flow.nonce, flow.verifier
	c := w.Result().Cookies()[0]
	w = f.callback(u.Query().Get("state"), c.Name+"="+c.Value)
	if w.Code != 303 || w.Header().Get("Location") != "/start" || sessionCookie(w) == nil {
		t.Fatalf("company account denied: %d %s", w.Code, w.Header().Get("Location"))
	}
	member := sessionCookie(w)
	s := f.a.sessions[member.Value]
	if member.MaxAge < int(googleSessionTTL.Seconds())-5 || member.MaxAge > int(googleSessionTTL.Seconds()) || time.Until(s.expires) < googleSessionTTL-5*time.Second || time.Until(s.expires) > googleSessionTTL {
		t.Fatal("company session did not receive the eight-hour lifetime")
	}
	if !s.member || f.a.google.allowed(s.email) || len(f.a.google.identities.Accounts) != 0 {
		t.Fatal("company login elevated or consumed an administrator pin")
	}
	w = call(f.a, "GET", "/api/snapshot", "", member.Name+"="+member.Value, "", "", "admin.example.com")
	if w.Code != 403 {
		t.Fatal("signed company session reached administrator data")
	}
	// A member query cannot loosen the admin verifier or create a member purpose.
	state, binding := f.start(t)
	w = f.callback(state, binding)
	assertGoogleRejection(t, w)
}
func TestMemberGoogleRequiresVerifiedCompanyDomainAndUnchangedTokenValidation(t *testing.T) {
	f := newGoogleFixture(t)
	f.a.google.memberDomains = map[string]bool{"example.com": true}
	for _, mode := range []string{"valid", "unverified", "wrong-domain", "missing-domain", "wrong-audience", "bad-nonce"} {
		claims := f.claims("member-nonce")
		claims["email"] = "member@example.com"
		switch mode {
		case "unverified":
			claims["email_verified"] = false
		case "wrong-domain":
			claims["email"] = "member@elsewhere.example"
			claims["hd"] = "elsewhere.example"
		case "missing-domain":
			claims["hd"] = ""
		case "wrong-audience":
			claims["aud"] = "other-client"
		case "bad-nonce":
			claims["nonce"] = "wrong"
		}
		token := f.sign(t, map[string]string{"alg": "RS256", "kid": "test-key"}, claims)
		_, err := f.a.google.validateRoleIDToken(context.Background(), token, "member-nonce", true)
		if (err == nil) != (mode == "valid") {
			t.Fatalf("wrong token result for %s", mode)
		}
	}
	f.a.google.memberDomains = nil
	s, cookie := memberSession(t, f.a, "member@example.com", "member-subject", true)
	w := call(f.a, http.MethodGet, "/api/member", "", s, cookie, "", "admin.example.com")
	if w.Code != 401 {
		t.Fatal("removed company domain kept its session")
	}
}
