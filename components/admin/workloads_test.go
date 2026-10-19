package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func pinFixtureWorkload(f *approvalFixture) workloadPin {
	f.nodes[1].Tags = []string{"tag:example-server"}
	f.nodes[1].UserIdentity.user = user{ID: "0", DisplayName: "Tagged Devices"}
	f.nodes[1].UserIdentity.ProviderID = ""
	pin := workloadPin{ID: "2", Fingerprint: nodeFingerprint(f.nodes[1]), Tag: "tag:example-server", Expiry: time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)}
	f.a.workflow.workloads = map[string]workloadPin{"2": pin}
	return pin
}

func TestPinnedWorkloadApprovalAndWithdrawal(t *testing.T) {
	f := newApprovalFixture(t)
	pin := pinFixtureWorkload(f)
	plan := fixturePlan()
	plan.Grants[0].Ports = []string{"tcp:22"}
	id := f.propose(t, plan)
	if r := f.request("approve", map[string]string{"id": id}); r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	r := f.a.workflow.state.Receipts["2"]
	if !r.Workload || r.EnrollmentTag != pin.Tag || r.Original.Email != "" || r.ProviderID != "" || r.Expiry != pin.Expiry {
		t.Fatal("workload receipt fabricated human ownership or lost its pin")
	}
	if len(f.nodes[1].Tags) != 1 || f.nodes[1].Tags[0] != r.Tag {
		t.Fatal("workload enrollment tag was not replaced by unique approval tag")
	}
	if err := f.a.reconcileWorkflow(context.Background(), false, "system"); err != nil {
		t.Fatal(err)
	}
	delete(f.a.workflow.workloads, "2")
	if err := f.a.reconcileWorkflow(context.Background(), false, "system"); err == nil {
		t.Fatal("removed workload pin retained access")
	}
	var policy compiledPolicy
	_ = json.Unmarshal([]byte(f.policy), &policy)
	if len(policy.Grants) != 0 {
		t.Fatal("withdrawal did not remove grants")
	}
}

func TestWorkloadPinsRejectKeyTagAndIdentityDrift(t *testing.T) {
	for _, change := range []string{"key", "tag", "identity", "expiry"} {
		t.Run(change, func(t *testing.T) {
			f := newApprovalFixture(t)
			pinFixtureWorkload(f)
			switch change {
			case "key":
				f.nodes[1].MachineKey = "mkey:replacement"
			case "tag":
				f.nodes[1].Tags = []string{"tag:other-server"}
			case "identity":
				f.nodes[1].UserIdentity.Email = "other@example.com"
			case "expiry":
				p := f.a.workflow.workloads["2"]
				p.Expiry = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
				f.a.workflow.workloads["2"] = p
			}
			if err := validatePlan(ptrPlan(fixturePlan()), f.nodes, f.a.workflow); err == nil {
				t.Fatal("changed workload was eligible")
			}
			if len(f.mutations) != 0 {
				t.Fatal("validation mutated controller")
			}
		})
	}
}
func ptrPlan(p accessPlan) *accessPlan { return &p }

func TestOperatorReviewRequiresFreshInventoryAndPreservesState(t *testing.T) {
	f := newApprovalFixture(t)
	pinFixtureWorkload(f)
	request := operatorRequest{Actor: "operator:test", Plan: fixturePlan(), Comment: "Explicitly reviewed SSH"}
	b, _ := json.Marshal(request)
	path := credential(t, "operator.json", string(b))
	before, _ := json.Marshal(f.a.workflow.state)
	var out bytes.Buffer
	if err := f.a.operatorApproval(path, false, &out); err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(f.a.workflow.state)
	if !bytes.Equal(before, after) || len(f.mutations) != 0 {
		t.Fatal("review mutated access or ledger")
	}
	if err := f.a.operatorApproval(path, true, &out); err == nil {
		t.Fatal("unreviewed inventory was applied")
	}
	request.Revision = f.a.workflow.state.Revision
	request.Inventory = inventoryDigest(f.nodes)
	b, _ = json.Marshal(request)
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.a.operatorApproval(path, true, &out); err != nil {
		t.Fatal(err)
	}
	if f.a.workflow.state.Proposals[0].Status != "approved" {
		t.Fatal("operator bypassed durable proposal workflow")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if err := f.a.operatorApproval(path, false, &out); err == nil {
		t.Fatal("public operator request accepted")
	}
}

func TestOperatorRestoresValidPlanAfterVerifiedInventoryWithdrawal(t *testing.T) {
	f := newApprovalFixture(t)
	f.approve(t)
	f.nodes = append(f.nodes, enrolledCompanyNode("3", "another@example.com", "subject-3"))
	plan := fixturePlan()
	plan.Devices = append(plan.Devices, "3")
	id := f.propose(t, plan)
	if r := f.request("approve", map[string]string{"id": id}); r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	// A newly approved node loses its tag. The monitor withdraws every grant,
	// while the two earlier nodes and their exact grant remain eligible.
	f.nodes[2].Tags = nil
	if err := f.a.reconcileWorkflow(context.Background(), false, "system"); err == nil {
		t.Fatal("changed inventory did not withdraw access")
	}
	w := f.a.workflow
	if w.state.Blocked == "" || !w.state.DenialVerified || len(w.state.Plan.Devices) != 0 || len(w.state.Receipts) != 3 {
		t.Fatal("expected blocked, verified deny-all with retained receipts")
	}
	request := operatorRequest{Actor: "operator:restore", Revision: w.state.Revision, Inventory: inventoryDigest(f.nodes), Plan: fixturePlan(), Comment: "Restore unaffected exact grant after verified denial", Reconcile: true}
	b, _ := json.Marshal(request)
	path := credential(t, "restore-operator.json", string(b))
	var out bytes.Buffer
	if err := f.a.operatorApproval(path, false, &out); err != nil {
		t.Fatal(err)
	}
	if w.state.Blocked == "" || len(w.state.Plan.Devices) != 0 {
		t.Fatal("review changed blocked state")
	}
	if err := f.a.operatorApproval(path, true, &out); err != nil {
		t.Fatal(err)
	}
	if w.state.Blocked != "" || w.state.DenialVerified || len(w.state.Plan.Devices) != 2 || len(w.state.Plan.Grants) != 1 || w.state.Proposals[len(w.state.Proposals)-1].Status != "approved" {
		t.Fatalf("operator restore did not apply exact plan: %+v", w.state)
	}
	request.Reconcile = true
	request.Revision = w.state.Revision
	request.Inventory = inventoryDigest(f.nodes)
	b, _ = json.Marshal(request)
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.a.operatorApproval(path, true, &out); err == nil {
		t.Fatal("operator reconciled an unblocked workflow")
	}
}

func TestWorkloadReceiptReload(t *testing.T) {
	f := newApprovalFixture(t)
	pin := pinFixtureWorkload(f)
	f.approve(t)
	configBytes, _ := json.Marshal(map[string]any{"state_path": f.ledgerPath, "allowed_domains": []string{"example.com"}, "workloads": []workloadPin{pin}})
	config := credential(t, "workload-config.json", string(configBytes))
	f.a.workflow.store.close()
	w, err := loadWorkflow(config)
	if err != nil {
		t.Fatal(err)
	}
	defer w.store.close()
	if ok, reason := w.eligible(f.nodes[1]); !ok {
		t.Fatal(reason)
	}
	w.store.close()
	pin.Expiry = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	configBytes, _ = json.Marshal(map[string]any{"state_path": f.ledgerPath, "allowed_domains": []string{"example.com"}, "workloads": []workloadPin{pin}})
	if err = os.WriteFile(config, configBytes, 0600); err != nil {
		t.Fatal(err)
	}
	w, err = loadWorkflow(config)
	if err != nil {
		t.Fatal("expired pins prevented monitor startup", err)
	}
	defer w.store.close()
	f.a.workflow = w
	if err = f.a.reconcileWorkflow(context.Background(), false, "system"); err == nil {
		t.Fatal("expired pin did not trigger withdrawal")
	}
	var policy compiledPolicy
	_ = json.Unmarshal([]byte(f.policy), &policy)
	if len(policy.Grants) != 0 {
		t.Fatal("expired pin retained grants after restart")
	}
}
