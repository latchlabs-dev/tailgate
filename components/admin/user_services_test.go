package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"slices"
	"testing"
)

func proposeUserService(t *testing.T, f *approvalFixture, ids []string) string {
	t.Helper()
	v, err := f.a.workflowSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r := f.request("service-propose", map[string]any{"destination_id": "2", "port": "tcp:443", "user_ids": ids, "revision": v.Revision, "inventory": v.Inventory})
	if r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	var response struct {
		ID string `json:"proposal_id"`
	}
	json.Unmarshal(r.Body.Bytes(), &response)
	return response.ID
}
func planHasSource(plan accessPlan, device, dst, port string) bool {
	for _, g := range plan.Grants {
		if slices.Contains(g.Destinations, dst) && slices.Contains(g.Ports, port) {
			for _, team := range plan.Teams {
				if team.Name == g.Team && slices.Contains(team.Devices, device) {
					return true
				}
			}
		}
	}
	return false
}
func TestUserServiceGrantPersistsAndFollowsApprovedDevices(t *testing.T) {
	f := newApprovalFixture(t)
	f.approve(t)
	alice := permissionIdentity("accounts.google.com/subject-1")
	before := f.policy
	id := proposeUserService(t, f, []string{alice})
	if f.policy != before || len(f.a.workflow.state.UserAccess) != 0 {
		t.Fatal("review mutated permissions")
	}
	if r := f.request("approve", map[string]string{"id": id}); r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	// A different Google subject with the same email must never inherit a grant.
	f.mu.Lock()
	device := f.nodes[0]
	device.ID = "3"
	device.MachineKey = "new-device"
	device.Tags = nil
	device.UserIdentity.user = user{ID: "1", Email: "alice@example.com", Provider: "oidc"}
	device.UserIdentity.ProviderID = "accounts.google.com/subject-1"
	f.nodes = append(f.nodes, device)
	impostor := device
	impostor.ID = "4"
	impostor.MachineKey = "impostor"
	impostor.UserIdentity.ProviderID = "accounts.google.com/different-subject"
	f.nodes = append(f.nodes, impostor)
	f.mu.Unlock()
	plan := copyPlan(f.a.workflow.state.Plan)
	plan.Devices = append(plan.Devices, "3", "4")
	id = f.propose(t, plan)
	if r := f.request("approve", map[string]string{"id": id}); r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	if !planHasSource(f.a.workflow.state.Plan, "3", "2", "tcp:443") || planHasSource(f.a.workflow.state.Plan, "4", "2", "tcp:443") {
		t.Fatal("subject-bound device inheritance failed")
	}
	id = proposeUserService(t, f, []string{})
	if r := f.request("approve", map[string]string{"id": id}); r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	if planHasSource(f.a.workflow.state.Plan, "1", "2", "tcp:443") || planHasSource(f.a.workflow.state.Plan, "3", "2", "tcp:443") {
		t.Fatal("revoke left access")
	}
	// Legacy/device requests cannot restore an explicit user-service revocation.
	plan = copyPlan(f.a.workflow.state.Plan)
	plan.Teams = append(plan.Teams, accessTeam{Name: "legacy", Devices: []string{"1"}})
	plan.Grants = append(plan.Grants, accessGrant{Team: "legacy", Destinations: []string{"2"}, Ports: []string{"tcp:443"}})
	id = f.propose(t, plan)
	if r := f.request("approve", map[string]string{"id": id}); r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	if planHasSource(f.a.workflow.state.Plan, "1", "2", "tcp:443") {
		t.Fatal("legacy grant bypassed user revoke")
	}
	var saved workflowState
	if ok, err := f.a.workflow.store.read(&saved); err != nil || !ok || len(saved.UserAccess) != 1 || len(saved.UserAccess[0].Users) != 0 {
		t.Fatal("revocation not durable", err)
	}
}

func TestUserServiceRevokeSurvivesAutomaticCompanyAdmission(t *testing.T) {
	f := newApprovalFixture(t)
	f.approve(t)
	id := proposeUserService(t, f, []string{})
	if r := f.request("approve", map[string]string{"id": id}); r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	f.a.workflow.state.Requests = []companyRequest{{ID: randomToken(), Subject: "subject-1", Email: "alice@example.com", Status: "approved", AutoAccess: &companyAccess{Service: "App", DestinationID: "2", Port: "tcp:443"}}}
	f.mu.Lock()
	device := f.nodes[0]
	device.ID = "3"
	device.MachineKey = "future-device"
	device.Tags = nil
	device.UserIdentity.user = user{ID: "1", Email: "alice@example.com", Provider: "oidc"}
	device.UserIdentity.ProviderID = "accounts.google.com/subject-1"
	f.nodes = append(f.nodes, device)
	f.mu.Unlock()
	if err := f.a.admitApprovedCompanyDevices(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(f.a.workflow.state.Plan.Devices, "3") {
		t.Fatal("future device not admitted")
	}
	if planHasSource(f.a.workflow.state.Plan, "1", "2", "tcp:443") || planHasSource(f.a.workflow.state.Plan, "3", "2", "tcp:443") {
		t.Fatal("automatic enrollment restored revoked access")
	}
}
func TestUserServiceCompilerPreservesWorkloadsAndOtherEndpoints(t *testing.T) {
	f := newApprovalFixture(t)
	f.approve(t)
	w := f.a.workflow
	nodes, _ := f.a.approvalInventory(context.Background())
	plan := copyPlan(w.state.Plan)
	plan.Devices = append(plan.Devices, "9")
	plan.Teams = append(plan.Teams, accessTeam{Name: "infra", Devices: []string{"9"}})
	plan.Grants = append(plan.Grants, accessGrant{Team: "infra", Destinations: []string{"2"}, Ports: []string{"tcp:443", "tcp:22"}})
	plan.Grants[0].Ports = append(plan.Grants[0].Ports, "tcp:22")
	result := compileUserServices(plan, []userServiceAccess{{Destination: "2", Port: "tcp:443", Users: []string{}}}, nodes, w)
	if planHasSource(result, "1", "2", "tcp:443") || !planHasSource(result, "1", "2", "tcp:22") || !planHasSource(result, "9", "2", "tcp:443") || !planHasSource(result, "9", "2", "tcp:22") {
		t.Fatal("unrelated/workload access changed")
	}
}

func TestOperatorUserMigrationIsExplicitReviewedAndDurable(t *testing.T) {
	f := newApprovalFixture(t)
	f.approve(t)
	request := operatorRequest{Actor: "operator:test", MigrateUserServices: true}
	b, _ := json.Marshal(request)
	path := credential(t, "user-migration.json", string(b))
	var out bytes.Buffer
	before, _ := json.Marshal(f.a.workflow.state)
	if err := f.a.operatorApproval(path, false, &out); err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(f.a.workflow.state)
	if !bytes.Equal(before, after) {
		t.Fatal("migration review mutated state")
	}
	if err := f.a.operatorApproval(path, true, &out); err == nil {
		t.Fatal("stale migration applied")
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
	if len(f.a.workflow.state.UserAccess) != 1 || !slices.Contains(f.a.workflow.state.UserAccess[0].Users, permissionIdentity("accounts.google.com/subject-1")) {
		t.Fatal("migration lost original owner")
	}
}

func TestUserServiceReconciliationDoesNotReapplyUnchangedPolicy(t *testing.T) {
	f := newApprovalFixture(t)
	f.approve(t)
	plan := copyPlan(f.a.workflow.state.Plan)
	plan.Grants = append(plan.Grants, accessGrant{Team: "developers", Destinations: []string{"2"}, Ports: []string{"tcp:22", "tcp:8443"}})
	id := f.propose(t, plan)
	if r := f.request("approve", map[string]string{"id": id}); r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	id = proposeUserService(t, f, []string{permissionIdentity("accounts.google.com/subject-1")})
	if r := f.request("approve", map[string]string{"id": id}); r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	before := f.a.workflow.state.Revision
	for i := 0; i < 2; i++ {
		if err := f.a.admitApprovedCompanyDevices(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if before != f.a.workflow.state.Revision {
		t.Fatal("unchanged user policy was reapplied")
	}
}
