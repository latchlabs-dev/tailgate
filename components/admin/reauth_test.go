package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestReauthenticationRestoresOnlyOriginalApprovedIdentity(t *testing.T) {
	for _, tc := range []struct {
		name    string
		change  func(*approvalNode, *workflow)
		allowed bool
	}{
		{"same identity", func(n *approvalNode, w *workflow) {}, true},
		{"different machine", func(n *approvalNode, w *workflow) { n.MachineKey = "new-machine" }, false},
		{"different subject", func(n *approvalNode, w *workflow) { n.UserIdentity.ProviderID = "https://accounts.google.com/other" }, false},
		{"different email", func(n *approvalNode, w *workflow) { n.UserIdentity.Email = "other@example.com" }, false},
		{"different user", func(n *approvalNode, w *workflow) { n.UserIdentity.ID = "other" }, false},
		{"foreign tag", func(n *approvalNode, w *workflow) { n.Tags = []string{"tag:other"} }, false},
		{"expired device", func(n *approvalNode, w *workflow) { n.Expiry = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339) }, false},
		{"expired approval", func(n *approvalNode, w *workflow) {
			r := w.state.Receipts[n.ID]
			r.Expiry = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
			w.state.Receipts[n.ID] = r
		}, false},
		{"excluded", func(n *approvalNode, w *workflow) {
			w.state.AutoExcluded = map[string]string{n.ID: nodeFingerprint(*n)}
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newApprovalFixture(t)
			original := f.nodes[0].UserIdentity
			p := fixturePlan()
			id := f.propose(t, p)
			if r := f.request("approve", map[string]any{"id": id}); r.Code != 200 {
				t.Fatal(r.Body.String())
			}
			before := f.policy
			f.nodes[0].Tags = nil
			f.nodes[0].UserIdentity = original
			tc.change(&f.nodes[0], f.a.workflow)
			err := f.a.reconcileWorkflow(context.Background(), false, "system")
			if err != nil && tc.allowed {
				t.Fatal(err)
			}
			if tc.allowed {
				if f.a.workflow.state.Blocked != "" || len(f.nodes[0].Tags) != 1 || f.policy != before {
					t.Fatal("safe reauth did not preserve access")
				}
				if f.a.workflow.state.Pending != "" {
					t.Fatal("pending restoration remains")
				}
			} else if f.a.workflow.state.Blocked == "" {
				t.Fatal("unsafe identity was accepted")
			}
		})
	}
}

func TestOperatorCanReviewAndRestoreBlockedReauthentication(t *testing.T) {
	f := newApprovalFixture(t)
	original := f.nodes[0].UserIdentity
	f.approve(t)
	f.nodes[0].Tags = nil
	f.nodes[0].UserIdentity = original
	_ = f.a.blockWorkflow("Existing release paused after reauthentication")
	req := operatorRequest{Actor: "operator:test", Plan: fixturePlan(), Reconcile: true, RestoreReauthenticated: true}
	b, _ := json.Marshal(req)
	path := credential(t, "restore.json", string(b))
	var output bytes.Buffer
	if err := f.a.operatorApproval(path, false, &output); err != nil {
		t.Fatal(err)
	}
	if len(f.nodes[0].Tags) != 0 {
		t.Fatal("review mutated approval tags")
	}
	var review struct {
		Revision  uint64 `json:"revision"`
		Inventory string `json:"inventory"`
	}
	if json.Unmarshal(output.Bytes(), &review) != nil {
		t.Fatal("invalid review")
	}
	req.Revision = review.Revision
	req.Inventory = review.Inventory
	b, _ = json.Marshal(req)
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := f.a.operatorApproval(path, true, &output); err != nil {
		t.Fatal(err)
	}
	if f.a.workflow.state.Blocked != "" || len(f.a.workflow.state.Plan.Grants) != 1 || len(f.nodes[0].Tags) != 1 {
		t.Fatal("reviewed recovery incomplete")
	}
}
