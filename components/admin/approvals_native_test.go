package main

// Optional real-wire qualification. No Google login or live deployment is used.
// TAILGATE_TEST_HEADSCALE must name the already-downloaded, hash-locked native
// binary. Fictitious Google provider IDs are injected only into a stopped,
// disposable SQLite database; OAuth verification has separate signed-JWT tests.
import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

type nativeApprovalLab struct {
	t                 *testing.T
	binary, root, cfg string
	url, apiKey       string
	log               *os.File
	process           *exec.Cmd
}

func nativeCommand(t *testing.T, binary string, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, binary, args...).CombinedOutput()
	if err != nil {
		// CLI errors may contain keys: report only the bounded operation name.
		operation := filepath.Base(binary)
		if operation == "headscale" && len(args) > 1 {
			operation += "/" + args[1]
		}
		t.Fatalf("disposable native command failed (%s)", operation)
	}
	return bytes.TrimSpace(b)
}

func nativeFreePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("cannot allocate disposable loopback port")
	}
	defer l.Close()
	return l.Addr().String()
}

func (l *nativeApprovalLab) cli(args ...string) []byte {
	l.t.Helper()
	return nativeCommand(l.t, l.binary, append([]string{"--config=" + l.cfg}, args...)...)
}

func (l *nativeApprovalLab) start() {
	l.t.Helper()
	l.process = exec.Command(l.binary, "--config="+l.cfg, "serve")
	l.process.Stdout, l.process.Stderr = l.log, l.log
	if l.process.Start() != nil {
		l.t.Fatal("disposable Headscale startup failed")
	}
	client := &http.Client{Timeout: time.Second}
	for i := 0; i < 100; i++ {
		res, err := client.Get(l.url + "/health")
		if err == nil {
			res.Body.Close()
			if res.StatusCode == 200 {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	l.t.Fatal("disposable Headscale readiness failed")
}

func (l *nativeApprovalLab) stop() {
	if l.process == nil {
		return
	}
	_ = l.process.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- l.process.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = l.process.Process.Kill()
		<-done
	}
	l.process = nil
}

func nativeApprovalFixture(t *testing.T) (*nativeApprovalLab, *app, string, string) {
	t.Helper()
	binary := os.Getenv("TAILGATE_TEST_HEADSCALE")
	if binary == "" {
		t.Skip("set TAILGATE_TEST_HEADSCALE to the hash-locked native binary")
	}
	binary, err := filepath.Abs(binary)
	if err != nil {
		t.Fatal("invalid native binary reference")
	}
	repository, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal("repository path unavailable")
	}
	var lock struct {
		Components map[string]struct {
			Artifacts map[string]struct {
				SHA256 string `json:"sha256"`
			} `json:"artifacts"`
		} `json:"components"`
	}
	b, err := os.ReadFile(filepath.Join(repository, "versions.lock.json"))
	if err != nil || json.Unmarshal(b, &lock) != nil {
		t.Fatal("native artifact lock unavailable")
	}
	b, err = os.ReadFile(binary)
	if err != nil {
		t.Fatal("locked native binary unavailable")
	}
	sum := sha256.Sum256(b)
	expected := lock.Components["headscale"].Artifacts[runtime.GOOS+"_"+runtime.GOARCH].SHA256
	if expected == "" || hex.EncodeToString(sum[:]) != expected {
		t.Fatal("native binary is not the locked platform artifact")
	}
	// macOS Unix sockets have a short pathname limit. testing.TempDir embeds
	// this long test name and can exceed it before Headscale binds the socket.
	root, err := os.MkdirTemp("", "tg-native-")
	if err != nil || os.Chmod(root, 0700) != nil {
		t.Fatal("private disposable directory unavailable")
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	listen := nativeFreePort(t)
	script := `import json,sys
from pathlib import Path
sys.path.insert(0,str(Path(sys.argv[1])/'tools'))
from tailgate import read_json,render
repo,root=Path(sys.argv[1]),Path(sys.argv[2])
bundle=root/'bundle';render(read_json(repo/'examples/pilot.json'),bundle)
c=read_json(bundle/'headscale.json');c.pop('oidc')
c.update(server_url='https://'+sys.argv[3],listen_addr=sys.argv[3],metrics_listen_addr=sys.argv[4],grpc_listen_addr=sys.argv[5],unix_socket=str(root/'headscale.sock'))
c['policy']={'mode':'database'};c['prefixes']['allocation']='sequential'
c['noise']['private_key_path']=str(root/'noise.key');c['database']['sqlite']['path']=str(root/'db.sqlite')
c['dns']['extra_records_path']=str(bundle/'records.json')
c['derp']['server'].update(stun_listen_addr=sys.argv[6],private_key_path=str(root/'derp.key'),ipv4='127.0.0.1')
p=root/'headscale.json';p.write_text(json.dumps(c));p.chmod(0o600)
`
	_ = nativeCommand(t, "python3", "-c", script, repository, root, listen, nativeFreePort(t), nativeFreePort(t), nativeFreePort(t))
	log, err := os.OpenFile(filepath.Join(root, "private-runtime.log"), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal("private disposable log unavailable")
	}
	l := &nativeApprovalLab{t: t, binary: binary, root: root, cfg: filepath.Join(root, "headscale.json"), url: "http://" + listen, log: log}
	t.Cleanup(func() { l.stop(); log.Close() })
	l.cli("configtest")
	l.start()
	l.apiKey = string(l.cli("apikeys", "create", "--expiration=10m"))
	apiPath := credential(t, "native-api", l.apiKey)
	operator := &app{o: options{upstream: l.url, keyFile: apiPath}, client: &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	if err := operator.upstream("PUT", "/api/v1/policy", map[string]string{"policy": `{"grants":[]}`}, nil); err != nil {
		t.Fatal("native database deny-all initialization failed")
	}
	for _, item := range []struct{ name, email string }{{"alice-native", "alice@example.com"}, {"bob-native", "bob@example.com"}, {"pending-native", "pending@example.com"}} {
		l.cli("users", "create", item.name, "--email="+item.email)
		auth := "hskey-authreq-" + randomToken()[:24]
		l.cli("debug", "create-node", "--user="+item.name, "--name="+item.name, "--key="+auth)
		l.cli("auth", "register", "--user="+item.name, "--auth-id="+auth)
	}
	l.stop()
	// The API cannot create provider IDs. This is model injection, not OIDC
	// enrollment. SQLite is touched only while this disposable server is stopped.
	seed := `import sqlite3,sys
db=sqlite3.connect(sys.argv[1])
for email,subject in [('alice@example.com','test-native-alice'),('bob@example.com','test-native-bob'),('pending@example.com','test-native-pending')]:
 db.execute("UPDATE users SET provider='oidc',provider_identifier=? WHERE email=?",('https://accounts.google.com/'+subject,email))
db.commit();db.close()
`
	_ = nativeCommand(t, "python3", "-c", seed, filepath.Join(root, "db.sqlite"))
	l.start()
	gc := googleConfig{ClientID: googleTestID, ClientSecretFile: credential(t, "native-google-secret", googleTestSecret), AdminEmails: []string{"alice@example.com"}, IdentityStoreFile: privateFilename(t, "native-admin-identities.json")}
	b, _ = json.Marshal(gc)
	googlePath := credential(t, "native-google.json", string(b))
	wc, _ := json.Marshal(map[string]any{"state_path": privateFilename(t, "native-approvals.json"), "allowed_domains": []string{"example.com"}})
	a, err := newApp(options{listen: "127.0.0.1:18100", origin: "https://admin.example.com", upstream: l.url, keyFile: apiPath, googleFile: googlePath, configFile: l.cfg, workflowFile: credential(t, "native-workflow.json", string(wc)), writes: true, accessWrites: true})
	if err != nil {
		t.Fatal("native workflow initialization failed")
	}
	t.Cleanup(a.workflow.store.close)
	t.Cleanup(a.google.identityStore.close)
	// This is the same post-verified-Google session shape as signed OAuth tests;
	// the native test does not contact Google or claim actual browser enrollment.
	w := httptest.NewRecorder()
	s, ok := a.issueSession(w, "alice@example.com", "test-native-admin", time.Now().Add(time.Hour))
	if !ok {
		t.Fatal("test administrator session unavailable")
	}
	return l, a, a.sessionCookieName() + "=" + s.id, s.csrf
}

func TestLockedNativeApprovalRoundTrip(t *testing.T) {
	l, a, cookie, csrf := nativeApprovalFixture(t)
	request := func(action string, value any) *httptest.ResponseRecorder {
		b, _ := json.Marshal(value)
		return call(a, "POST", "/api/workflow/"+action, string(b), cookie, csrf, a.o.origin, "admin.example.com")
	}
	ctx := context.Background()
	nodes, err := a.approvalInventory(ctx)
	if err != nil || len(nodes) != 3 {
		t.Fatal("real API inventory did not decode")
	}
	byEmail := map[string]approvalNode{}
	for _, n := range nodes {
		byEmail[n.UserIdentity.Email] = n
		if ok, _ := a.workflow.eligible(n); !ok {
			t.Fatal("fictitious Google model was not eligible through real wire types")
		}
	}
	src, dst, pending := byEmail["alice@example.com"], byEmail["bob@example.com"], byEmail["pending@example.com"]
	if len(src.IPs) != 2 || len(dst.IPs) != 2 {
		t.Fatal("native dual-stack fixture unavailable")
	}
	view, err := a.workflowSnapshot(ctx)
	if err != nil {
		t.Fatal("native workflow snapshot failed")
	}
	plan := accessPlan{Devices: []string{src.ID, dst.ID}, Teams: []accessTeam{{Name: "developers", Devices: []string{src.ID}}}, Grants: []accessGrant{{Team: "developers", Destinations: []string{dst.ID}, Ports: []string{"tcp:443"}}}}
	if r := request("propose", map[string]any{"revision": view.Revision, "inventory": view.Inventory, "plan": plan}); r.Code != 200 {
		t.Fatal("real native proposal failed")
	}
	policy, _ := a.currentPolicy(ctx)
	if len(a.workflow.state.Receipts) != 0 || !strings.Contains(policy, `"grants":[]`) {
		t.Fatal("proposal mutated native access")
	}
	id := a.workflow.state.Proposals[0].ID
	if r := request("approve", map[string]string{"id": id}); r.Code != 200 {
		t.Fatal("real native staged approval failed")
	}
	policy, err = a.currentPolicy(ctx)
	if err != nil {
		t.Fatal("real policy readback unavailable")
	}
	var compiled compiledPolicy
	if json.Unmarshal([]byte(policy), &compiled) != nil || len(compiled.Grants) != 1 || compiled.Grants[0].Src[0] != a.workflow.state.Receipts[src.ID].Tag || compiled.Grants[0].Dst[0] != a.workflow.state.Receipts[dst.ID].Tag {
		t.Fatal("real native policy did not retain exact tag grants")
	}
	for _, owners := range compiled.TagOwners {
		if len(owners) != 0 {
			t.Fatal("native approval tags were claimable")
		}
	}
	nodes, _ = a.approvalInventory(ctx)
	for _, n := range nodes {
		if n.ID == pending.ID {
			if len(n.Tags) != 0 || n.UserIdentity.ProviderID == "" {
				t.Fatal("unapproved native device changed")
			}
			continue
		}
		r := a.workflow.state.Receipts[n.ID]
		if len(n.Tags) != 1 || n.Tags[0] != r.Tag || n.UserIdentity.ProviderID != "" || r.ProviderID == "" || r.Original.Email == "" {
			t.Fatal("native owner conversion lost durable attribution")
		}
	}
	// Model Headscale's documented OIDC reauthentication result in stopped,
	// disposable state, then exercise repair through the real API.
	l.stop()
	reauth := `import sqlite3,sys
with sqlite3.connect(sys.argv[1]) as db:
 db.execute("UPDATE nodes SET tags='[]', user_id=? WHERE id=?",(sys.argv[2],sys.argv[3]))
`
	_ = nativeCommand(t, "python3", "-c", reauth, filepath.Join(l.root, "db.sqlite"), src.UserIdentity.ID, src.ID)
	l.start()
	if err := a.reconcileWorkflow(ctx, false, "system"); err != nil {
		t.Fatalf("native reauthentication repair failed: %v", err)
	}
	repaired, err := a.approvalInventory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range repaired {
		if n.ID == src.ID && (len(n.Tags) != 1 || n.Tags[0] != a.workflow.state.Receipts[src.ID].Tag) {
			t.Fatal("native tag not restored")
		}
	}
	afterRepair, _ := a.currentPolicy(ctx)
	beforeHash, _ := canonicalPolicy(policy)
	afterHash, _ := canonicalPolicy(afterRepair)
	if beforeHash != afterHash {
		t.Fatal("reauthentication changed grants")
	}
	// Real policy-check evaluates both address families and both allow/deny
	// cases. It validates packet-filter compilation, not transmitted traffic.
	var tested map[string]any
	_ = json.Unmarshal([]byte(policy), &tested)
	tested["tests"] = []map[string]any{{"src": src.IPs[0], "accept": []string{dst.IPs[0] + ":443"}, "deny": []string{dst.IPs[0] + ":22"}}, {"src": src.IPs[1], "accept": []string{"[" + dst.IPs[1] + "]:443"}}, {"src": pending.IPs[0], "deny": []string{dst.IPs[0] + ":443"}}}
	testPolicy, _ := json.Marshal(tested)
	if a.upstream("POST", "/api/v1/policy/check", map[string]string{"policy": string(testPolicy)}, nil) != nil {
		t.Fatal("native allow/deny packet-filter compilation failed")
	}
	if r := request("revoke", map[string]string{"id": src.ID}); r.Code != 200 {
		t.Fatal("native exact-device revocation failed")
	}
	policy, _ = a.currentPolicy(ctx)
	_ = json.Unmarshal([]byte(policy), &compiled)
	if len(compiled.Grants) != 0 || slices.Contains(a.workflow.state.Plan.Devices, src.ID) {
		t.Fatal("native revocation retained access")
	}
	// Delete through the UI after revocation and prove the other native devices
	// are intact. This never operates on the machine's original Tailscale client.
	r := call(a, "POST", "/api/machines/"+src.ID+"/delete", `{"confirmation":"`+src.GivenName+`"}`, cookie, csrf, a.o.origin, "admin.example.com")
	if r.Code != 200 {
		t.Fatal("native revoked-device deletion failed")
	}
	nodes, err = a.approvalInventory(ctx)
	if err != nil || len(nodes) != 2 {
		t.Fatal("native exact deletion changed unrelated inventory")
	}
	for _, n := range nodes {
		if n.ID == src.ID {
			t.Fatal("native deleted device remained")
		}
	}
	_ = l // Cleanup stops the native controller and removes its private state.
}

func TestLockedNativeTaggedWorkloadApproval(t *testing.T) {
	l, a, cookie, csrf := nativeApprovalFixture(t)
	ctx := context.Background()
	nodes, err := a.approvalInventory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	byEmail := map[string]approvalNode{}
	for _, n := range nodes {
		byEmail[n.UserIdentity.Email] = n
	}
	src, dst := byEmail["alice@example.com"], byEmail["bob@example.com"]
	if err = a.putPolicy(ctx, `{"tagOwners":{"tag:example-server":[]},"grants":[]}`); err != nil {
		t.Fatal(err)
	}
	l.cli("nodes", "tag", "--identifier", dst.ID, "--tags", "tag:example-server")
	nodes, err = a.approvalInventory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.ID == dst.ID {
			dst = n
		}
	}
	if dst.UserIdentity.ProviderID != "" || dst.UserIdentity.Email != "" {
		t.Fatal("native tagging did not produce a workload identity")
	}
	a.workflow.workloads = map[string]workloadPin{dst.ID: {ID: dst.ID, Fingerprint: nodeFingerprint(dst), Tag: "tag:example-server", Expiry: time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)}}
	view, err := a.workflowSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	plan := accessPlan{Devices: []string{src.ID, dst.ID}, Teams: []accessTeam{{Name: "operators", Devices: []string{src.ID}}}, Grants: []accessGrant{{Team: "operators", Destinations: []string{dst.ID}, Ports: []string{"tcp:22"}}}}
	b, _ := json.Marshal(map[string]any{"revision": view.Revision, "inventory": view.Inventory, "plan": plan})
	if r := call(a, "POST", "/api/workflow/propose", string(b), cookie, csrf, a.o.origin, "admin.example.com"); r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	id := a.workflow.state.Proposals[0].ID
	b, _ = json.Marshal(map[string]string{"id": id})
	if r := call(a, "POST", "/api/workflow/approve", string(b), cookie, csrf, a.o.origin, "admin.example.com"); r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	if err = a.reconcileWorkflow(ctx, false, "system"); err != nil {
		t.Fatal(err)
	}
	policy, err := a.currentPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var compiled compiledPolicy
	_ = json.Unmarshal([]byte(policy), &compiled)
	if len(compiled.Grants) != 1 || len(compiled.Grants[0].IP) != 1 || compiled.Grants[0].IP[0] != "tcp:22" || !a.workflow.state.Receipts[dst.ID].Workload {
		t.Fatal("native workload approval did not retain exact SSH grant")
	}
}
