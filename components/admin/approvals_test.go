package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type approvalFixture struct {
	mu           sync.Mutex
	nodes        []approvalNode
	policy       string
	mutations    []string
	failFinal    bool
	failDeny     bool
	ledgerPath   string
	ledgerSeen   bool
	a            *app
	cookie, csrf string
}

func newApprovalFixture(t *testing.T) *approvalFixture {
	t.Helper()
	f := &approvalFixture{policy: `{"grants":[]}`, ledgerPath: privateFilename(t, "approvals.json")}
	for i, id := range []string{"1", "2"} {
		n := approvalNode{node: node{ID: id, Name: "device-" + id, GivenName: "device-" + id, IPs: []string{"100.64.0." + id}, Expiry: time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)}, MachineKey: "mkey:test-key-" + id}
		n.UserIdentity.user = user{ID: id, Email: []string{"alice@example.com", "bob@example.com"}[i], Provider: "oidc"}
		n.UserIdentity.ProviderID = "https://accounts.google.com/subject-" + id
		f.nodes = append(f.nodes, n)
	}
	server := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	b, _ := json.Marshal(map[string]any{"state_path": f.ledgerPath, "allowed_domains": []string{"example.com"}})
	config := credential(t, "workflow.json", string(b))
	headscale := credential(t, "headscale.json", `{"policy":{"mode":"database"}}`)
	a, err := newApp(options{listen: "127.0.0.1:18100", origin: "http://127.0.0.1:18100", upstream: server.URL, keyFile: credential(t, "api", testKey), loginFile: credential(t, "login", testLogin), configFile: headscale, workflowFile: config, accessWrites: true, writes: true})
	if err != nil {
		t.Fatal(err)
	}
	f.a = a
	t.Cleanup(a.workflow.store.close)
	f.cookie, f.csrf = authorized(t, a)
	return f
}
func (f *approvalFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+testKey {
		w.WriteHeader(401)
		return
	}
	switch {
	case r.URL.Path == "/api/v1/node" && r.Method == "GET":
		respond(w, 200, map[string]any{"nodes": f.nodes})
	case r.URL.Path == "/api/v1/user":
		respond(w, 200, map[string]any{"users": []user{}})
	case r.URL.Path == "/api/v1/policy" && r.Method == "GET":
		respond(w, 200, map[string]string{"policy": f.policy})
	case r.URL.Path == "/api/v1/policy/check":
		respond(w, 200, map[string]any{})
	case r.URL.Path == "/api/v1/policy" && r.Method == "PUT":
		var p struct {
			Policy string `json:"policy"`
		}
		_ = json.NewDecoder(r.Body).Decode(&p)
		var v compiledPolicy
		_ = json.Unmarshal([]byte(p.Policy), &v)
		if f.failDeny && len(v.Grants) == 0 {
			w.WriteHeader(503)
			return
		}
		if f.failFinal && len(v.Grants) > 0 {
			f.failFinal = false
			w.WriteHeader(503)
			return
		}
		f.mutations = append(f.mutations, "policy")
		f.policy = p.Policy
		respond(w, 200, map[string]string{"policy": p.Policy})
	case strings.HasSuffix(r.URL.Path, "/tags") && r.Method == "POST":
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/node/"), "/tags")
		var input struct {
			Tags []string `json:"tags"`
		}
		_ = json.NewDecoder(r.Body).Decode(&input)
		var policy compiledPolicy
		_ = json.Unmarshal([]byte(f.policy), &policy)
		if len(input.Tags) != 1 {
			w.WriteHeader(400)
			return
		}
		if owners, ok := policy.TagOwners[input.Tags[0]]; !ok || len(owners) != 0 {
			w.WriteHeader(400)
			return
		}
		var ledger workflowState
		b, _ := os.ReadFile(f.ledgerPath)
		_ = json.Unmarshal(b, &ledger)
		receipt, ok := ledger.Receipts[id]
		identityRecorded := receipt.Original.Email != "" && receipt.ProviderID != ""
		if receipt.Workload {
			identityRecorded = receipt.Original.Email == "" && receipt.ProviderID == "" && receipt.EnrollmentTag != "" && receipt.Fingerprint != ""
		}
		if !ok || !identityRecorded || receipt.Tag != input.Tags[0] || ledger.Pending == "" {
			w.WriteHeader(500)
			return
		}
		f.ledgerSeen = true
		for i, n := range f.nodes {
			if n.ID == id {
				f.nodes[i].Tags = input.Tags
				f.nodes[i].UserIdentity.user = user{ID: "0", DisplayName: "TaggedDevices"}
				f.nodes[i].UserIdentity.ProviderID = ""
				f.mutations = append(f.mutations, "tag:"+id)
				respond(w, 200, map[string]any{})
				return
			}
		}
		w.WriteHeader(404)
	case strings.HasPrefix(r.URL.Path, "/api/v1/node/") && r.Method == "GET":
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/node/")
		for _, n := range f.nodes {
			if n.ID == id {
				respond(w, 200, map[string]any{"node": n})
				return
			}
		}
		w.WriteHeader(404)
	case strings.HasPrefix(r.URL.Path, "/api/v1/node/") && r.Method == "DELETE":
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/node/")
		f.mutations = append(f.mutations, "delete:"+id)
		for i, n := range f.nodes {
			if n.ID == id {
				f.nodes = append(f.nodes[:i], f.nodes[i+1:]...)
				respond(w, 200, map[string]any{})
				return
			}
		}
		w.WriteHeader(404)
	default:
		w.WriteHeader(404)
	}
}
func (f *approvalFixture) request(action string, input any) *httptest.ResponseRecorder {
	b, _ := json.Marshal(input)
	return call(f.a, "POST", "/api/workflow/"+action, string(b), f.cookie, f.csrf, f.a.o.origin, "127.0.0.1:18100")
}
func fixturePlan() accessPlan {
	return accessPlan{Devices: []string{"1", "2"}, Teams: []accessTeam{{Name: "developers", Devices: []string{"1"}}}, Grants: []accessGrant{{Team: "developers", Destinations: []string{"2"}, Ports: []string{"tcp:443"}}}}
}
func (f *approvalFixture) propose(t *testing.T, p accessPlan) string {
	t.Helper()
	v, err := f.a.workflowSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r := f.request("propose", map[string]any{"revision": v.Revision, "inventory": v.Inventory, "plan": p, "comment": "Approved company workflow"})
	if r.Code != 200 {
		t.Fatalf("propose %d %s", r.Code, r.Body.String())
	}
	return f.a.workflow.state.Proposals[len(f.a.workflow.state.Proposals)-1].ID
}
func (f *approvalFixture) approve(t *testing.T) {
	t.Helper()
	id := f.propose(t, fixturePlan())
	r := f.request("approve", map[string]string{"id": id})
	if r.Code != 200 {
		t.Fatalf("approve %d %s", r.Code, r.Body.String())
	}
}

func TestApprovalIsExplicitDurableAndUsesOnlyUnclaimableNodeTags(t *testing.T) {
	f := newApprovalFixture(t)
	id := f.propose(t, fixturePlan())
	if len(f.mutations) != 0 || f.a.workflow.state.Revision != 0 {
		t.Fatal("proposal changed network access")
	}
	r := f.request("approve", map[string]string{"id": id})
	if r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	if !f.ledgerSeen || strings.Join(f.mutations, ",") != "policy,tag:1,tag:2,policy" {
		t.Fatalf("unsafe transition order: %v", f.mutations)
	}
	var p compiledPolicy
	_ = json.Unmarshal([]byte(f.policy), &p)
	if len(p.Grants) != 1 || p.Grants[0].Src[0] != f.a.workflow.state.Receipts["1"].Tag || p.Grants[0].Dst[0] != f.a.workflow.state.Receipts["2"].Tag {
		t.Fatal("policy did not use exact approval tags")
	}
	for _, owners := range p.TagOwners {
		if len(owners) != 0 {
			t.Fatal("ordinary users may claim tags")
		}
	}
	if strings.Contains(f.policy, "100.64.") || strings.Contains(f.policy, "@example.com") {
		t.Fatal("reusable IP or identity selectors leaked into policy")
	}
	var saved workflowState
	data, _ := os.ReadFile(f.ledgerPath)
	if json.Unmarshal(data, &saved) != nil || saved.Pending != "" || saved.Receipts["1"].ProviderID == "" || saved.Receipts["1"].Original.Email != "alice@example.com" || saved.Proposals[0].Status != "approved" {
		t.Fatal("original identity and committed state missing")
	}
	view, _ := f.a.workflowSnapshot(context.Background())
	if view.Owners["1"].Email != "alice@example.com" {
		t.Fatal("upstream tagged owner erased UI receipt")
	}
}
func TestApprovalStaleOwnerKeyAndRevisionCannotGainAccess(t *testing.T) {
	for _, kind := range []string{"owner", "key", "revision"} {
		t.Run(kind, func(t *testing.T) {
			f := newApprovalFixture(t)
			id := f.propose(t, fixturePlan())
			f.mu.Lock()
			switch kind {
			case "owner":
				f.nodes[0].UserIdentity.Email = "mallory@example.com"
			case "key":
				f.nodes[0].MachineKey = "replacement-key"
			case "revision":
				f.a.workflow.state.Revision++
			}
			f.mu.Unlock()
			r := f.request("approve", map[string]string{"id": id})
			if r.Code != 409 || len(f.mutations) != 0 {
				t.Fatal("stale proposal granted access")
			}
		})
	}
}
func TestApprovalRejectsUntrustedIdentityWildcardPortsAndUnapprovedDestinations(t *testing.T) {
	for _, kind := range []string{"issuer", "domain", "tagged", "wildcard", "range", "destination"} {
		t.Run(kind, func(t *testing.T) {
			f := newApprovalFixture(t)
			p := fixturePlan()
			switch kind {
			case "issuer":
				f.nodes[0].UserIdentity.ProviderID = "https://evil.example/subject"
			case "domain":
				f.nodes[0].UserIdentity.Email = "alice@outside.example"
			case "tagged":
				f.nodes[0].Tags = []string{"tag:existing"}
			case "wildcard":
				p.Grants[0].Ports = []string{"*"}
			case "range":
				p.Grants[0].Ports = []string{"tcp:1-65535"}
			case "destination":
				p.Devices = []string{"1"}
				p.Teams[0].Devices = []string{"1"}
			}
			nodes, _ := f.a.approvalInventory(context.Background())
			if validatePlan(&p, nodes, f.a.workflow) == nil {
				t.Fatal("unreviewable access accepted")
			}
			if len(f.mutations) != 0 {
				t.Fatal("validation changed access")
			}
		})
	}
}
func TestApprovalFailureAfterTaggingForcesVerifiedDenyAllAndBlocks(t *testing.T) {
	f := newApprovalFixture(t)
	id := f.propose(t, fixturePlan())
	f.failFinal = true
	r := f.request("approve", map[string]string{"id": id})
	if r.Code != 409 || f.a.workflow.state.Blocked == "" {
		t.Fatal("failed final policy was reported as success")
	}
	var p compiledPolicy
	_ = json.Unmarshal([]byte(f.policy), &p)
	if len(p.Grants) != 0 {
		t.Fatal("uncertain transition retained grants")
	}
	if f.a.workflow.state.Receipts["1"].Original.Email == "" {
		t.Fatal("ownership lost during failed transition")
	}
	r = f.request("reconcile", map[string]any{})
	if r.Code != 200 || f.a.workflow.state.Blocked != "" || len(f.a.workflow.state.Plan.Devices) != 0 {
		t.Fatal("explicit deny-all reconciliation failed")
	}
}
func TestRevocationWithdrawsSourceAndDestinationBeforeDeletion(t *testing.T) {
	for _, id := range []string{"1", "2"} {
		t.Run(id, func(t *testing.T) {
			f := newApprovalFixture(t)
			f.approve(t)
			f.mutations = nil
			r := call(f.a, "POST", "/api/machines/"+id+"/delete", `{"confirmation":"device-`+id+`"}`, f.cookie, f.csrf, f.a.o.origin, "127.0.0.1:18100")
			if r.Code != 200 {
				t.Fatal(r.Body.String())
			}
			if strings.Join(f.mutations, ",") != "policy,delete:"+id {
				t.Fatal("node deleted before grants removed")
			}
			var p compiledPolicy
			_ = json.Unmarshal([]byte(f.policy), &p)
			if len(p.Grants) != 0 {
				t.Fatal("revoked source/destination remained authorized")
			}
		})
	}
}
func TestWrongDeviceConfirmationDoesNotWithdrawAccess(t *testing.T) {
	f := newApprovalFixture(t)
	f.approve(t)
	f.mutations = nil
	r := call(f.a, "POST", "/api/machines/1/delete", `{"confirmation":"wrong"}`, f.cookie, f.csrf, f.a.o.origin, "127.0.0.1:18100")
	if r.Code != 409 || len(f.mutations) != 0 {
		t.Fatal("wrong confirmation changed access")
	}
}
func TestExpiryKeyDriftAndTagReassignmentWithdrawAllGrants(t *testing.T) {
	for _, kind := range []string{"key", "expiry", "reassigned"} {
		t.Run(kind, func(t *testing.T) {
			f := newApprovalFixture(t)
			f.approve(t)
			switch kind {
			case "key":
				f.nodes[0].MachineKey = "changed"
			case "expiry":
				r := f.a.workflow.state.Receipts["1"]
				r.Expiry = time.Now().Add(-time.Second).UTC().Format(time.RFC3339)
				f.a.workflow.state.Receipts["1"] = r
				f.nodes[0].Expiry = ""
			case "reassigned":
				copy := f.nodes[0]
				copy.ID = "3"
				copy.MachineKey = "unapproved-key"
				f.nodes = append(f.nodes, copy)
			}
			err := f.a.reconcileWorkflow(context.Background(), false, "system")
			if err == nil || f.a.workflow.state.Blocked == "" {
				t.Fatal("drift did not block access")
			}
			var p compiledPolicy
			_ = json.Unmarshal([]byte(f.policy), &p)
			if len(p.Grants) != 0 {
				t.Fatal("drift retained grants")
			}
		})
	}
}
func TestWorkflowRejectsAllowAllBootstrapAndOutOfBandPolicyChanges(t *testing.T) {
	f := newApprovalFixture(t)
	f.policy = `{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}],"grants":[]}`
	id := f.propose(t, fixturePlan())
	r := f.request("approve", map[string]string{"id": id})
	if r.Code != 409 || len(f.mutations) != 0 {
		t.Fatal("unmanaged bootstrap policy overwritten or accepted")
	}
	f.policy = `{"grants":[]}`
	f.approve(t)
	f.policy = `{"grants":[{"src":["*"],"dst":["*"],"ip":["*"]}]}`
	if f.a.reconcileWorkflow(context.Background(), false, "system") == nil {
		t.Fatal("external policy drift unreported")
	}
	var p compiledPolicy
	_ = json.Unmarshal([]byte(f.policy), &p)
	if len(p.Grants) != 0 {
		t.Fatal("external policy drift not denied")
	}
}
func TestWorkflowBootstrapRequiresExplicitEmptyGrantArray(t *testing.T) {
	for _, raw := range []string{`{}`, `{"grants":null}`, `{"grants":{}}`, `{"grants":[] ,"acls":[]}`} {
		t.Run(raw, func(t *testing.T) {
			f := newApprovalFixture(t)
			f.policy = raw
			id := f.propose(t, fixturePlan())
			r := f.request("approve", map[string]string{"id": id})
			if r.Code != 409 || len(f.mutations) != 0 {
				t.Fatalf("unsafe bootstrap %s: %d", raw, r.Code)
			}
		})
	}
}
func TestUnverifiedDenialRetriesAfterUpstreamRecovery(t *testing.T) {
	f := newApprovalFixture(t)
	f.approve(t)
	receipt := f.a.workflow.state.Receipts["1"]
	receipt.Expiry = time.Now().Add(-time.Second).UTC().Format(time.RFC3339)
	f.a.workflow.state.Receipts["1"] = receipt
	f.failDeny = true
	if f.a.reconcileWorkflow(context.Background(), false, "system") == nil || f.a.workflow.state.Blocked == "" || f.a.workflow.state.DenialVerified {
		t.Fatal("failed denial was reported as verified")
	}
	var p compiledPolicy
	_ = json.Unmarshal([]byte(f.policy), &p)
	if len(p.Grants) == 0 {
		t.Fatal("fixture did not preserve old grants during failure")
	}
	f.failDeny = false
	_ = f.a.reconcileWorkflow(context.Background(), false, "system")
	_ = json.Unmarshal([]byte(f.policy), &p)
	if len(p.Grants) != 0 || !f.a.workflow.state.DenialVerified || f.a.workflow.state.Blocked == "" {
		t.Fatal("recovery did not verify deny-all while keeping changes blocked")
	}
	audits := len(f.a.workflow.state.Audit)
	if f.a.reconcileWorkflow(context.Background(), false, "system") != nil || len(f.a.workflow.state.Audit) != audits {
		t.Fatal("verified blocked polling generated repeated mutations or audit spam")
	}
}
func TestGoogleMemberIdentifierAcceptsOnlyExactOfficialIssuers(t *testing.T) {
	for _, id := range []string{"https://accounts.google.com/123456", "accounts.google.com/123456"} {
		if !googleMemberIdentity(id) {
			t.Fatal("valid Google identifier rejected")
		}
	}
	for _, id := range []string{"https://accounts.google.com/", "https://accounts.google.com.evil.test/123", "https://accounts.google.com/123/456", "accounts.google.com/123?evil=1", "http://accounts.google.com/123"} {
		if googleMemberIdentity(id) {
			t.Fatalf("unsafe identifier accepted %s", id)
		}
	}
}
func TestWorkflowSnapshotsRemainDetachedFromConcurrentProposalUpdates(t *testing.T) {
	f := newApprovalFixture(t)
	id := f.propose(t, fixturePlan())
	snapshot, err := f.a.workflowSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_, _ = json.Marshal(snapshot)
		}
	}()
	r := f.request("reject", map[string]string{"id": id})
	if r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	wg.Wait()
	if snapshot.Proposals[0].Status != "pending" {
		t.Fatal("a captured snapshot was mutated by a later request")
	}
}
func TestWorkflowCSRFAndReadOnlyPreventWrites(t *testing.T) {
	f := newApprovalFixture(t)
	v, _ := f.a.workflowSnapshot(context.Background())
	b, _ := json.Marshal(map[string]any{"revision": v.Revision, "inventory": v.Inventory, "plan": fixturePlan()})
	r := call(f.a, "POST", "/api/workflow/propose", string(b), f.cookie, "wrong", f.a.o.origin, "127.0.0.1:18100")
	if r.Code != 403 || len(f.a.workflow.state.Proposals) != 0 {
		t.Fatal("CSRF bypass")
	}
	f.a.o.accessWrites = false
	r = f.request("propose", json.RawMessage(b))
	if r.Code != 403 {
		t.Fatal("read-only bypass")
	}
}
func TestWorkflowSnapshotNeverReturnsProviderOrMachineCredentials(t *testing.T) {
	f := newApprovalFixture(t)
	f.approve(t)
	r := call(f.a, "GET", "/api/snapshot", "", f.cookie, "", f.a.o.origin, "127.0.0.1:18100")
	if r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	for _, secret := range []string{"machineKey", "providerId", "provider_id", "subject-1", "mkey:test-key"} {
		if strings.Contains(r.Body.String(), secret) {
			t.Fatalf("private receipt leaked %s", secret)
		}
	}
}
func TestOperationsProjectionBoundsAndFreshness(t *testing.T) {
	p := credential(t, "operations.json", `{"generated_at":"2020-01-01T00:00:00Z","checks":[{"name":"Backup","status":"pass","message":"Verified"}]}`)
	_ = os.Chmod(p, 0644)
	s := readOperations(p)
	if len(s.Checks) != 2 || s.Checks[1].Status != "warning" {
		t.Fatal("stale projection not identified")
	}
	_ = os.WriteFile(p, []byte(`{"generated_at":"2020-01-01T00:00:00Z","checks":[{"name":"Backup","status":"unknown","message":"secret"}]}`), 0644)
	if strings.Contains(readOperations(p).Checks[0].Message, "secret") {
		t.Fatal("unvalidated projection forwarded")
	}
	_ = os.Chmod(p, 0666)
	if readOperations(p).Checks[0].Status != "warning" {
		t.Fatal("writable projection accepted")
	}
}
func TestInterruptedApprovalRetainsIdentityAndRequiresDenyAllReconciliation(t *testing.T) {
	f := newApprovalFixture(t)
	f.approve(t)
	w := f.a.workflow
	w.state.Pending = "interrupted"
	if w.store.write(w.state) != nil {
		t.Fatal("save")
	}
	w.store.close()
	config := credential(t, "workflow-reopen.json", `{"state_path":"`+f.ledgerPath+`","allowed_domains":["example.com"]}`)
	reopened, err := loadWorkflow(config)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.store.close()
	f.a.workflow = reopened
	if reopened.state.Blocked == "" || reopened.state.Receipts["1"].ProviderID == "" {
		t.Fatal("interrupted ownership mapping lost")
	}
	r := f.request("reconcile", map[string]any{})
	if r.Code != 200 {
		b, _ := io.ReadAll(r.Result().Body)
		t.Fatal(string(b))
	}
}
func TestUnsafeRestoredReceiptCannotCompileWildcardSelectors(t *testing.T) {
	f := newApprovalFixture(t)
	f.approve(t)
	w := f.a.workflow
	w.store.close()
	receipt := w.state.Receipts["1"]
	receipt.Tag = "*"
	w.state.Receipts["1"] = receipt
	b, _ := json.Marshal(w.state)
	if os.WriteFile(f.ledgerPath, b, 0600) != nil {
		t.Fatal("fixture write")
	}
	config := credential(t, "restored.json", `{"state_path":"`+f.ledgerPath+`","allowed_domains":["example.com"]}`)
	if reopened, err := loadWorkflow(config); err == nil {
		reopened.store.close()
		t.Fatal("unsafe restored selector accepted")
	}
}

func TestWorkflowSnapshotEmptyCollectionsAreArraysWithoutChangingLedger(t *testing.T) {
	f := newApprovalFixture(t)
	// A legacy empty ledger and a first company request both lack policy proposals.
	for _, withRequest := range []bool{false, true} {
		w := f.a.workflow
		w.mu.Lock()
		w.state.Proposals = nil
		w.state.Audit = nil
		w.state.Requests = nil
		if withRequest {
			w.state.Requests = []companyRequest{{ID: randomToken(), Subject: "member-subject", Email: "member@example.com", Reason: "Work", Status: "pending", CreatedAt: time.Now().UTC().Format(time.RFC3339)}}
		}
		before, _ := json.Marshal(w.state)
		w.mu.Unlock()
		view, err := f.a.workflowSnapshot(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(view)
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil {
			t.Fatal("bad workflow projection")
		}
		for _, name := range []string{"devices", "proposals", "audit", "requests"} {
			if len(fields[name]) == 0 || fields[name][0] != '[' {
				t.Fatalf("%s is not an array: %s", name, fields[name])
			}
		}
		w.mu.Lock()
		after, _ := json.Marshal(w.state)
		w.mu.Unlock()
		if string(before) != string(after) {
			t.Fatal("normalizing the view changed durable approval state")
		}
	}
}
