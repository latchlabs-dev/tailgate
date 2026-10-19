package main

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"
)

func enrolledCompanyNode(id, email, subject string) approvalNode {
	n := approvalNode{node: node{ID: id, Name: "work-" + id, GivenName: "work-" + id, IPs: []string{"100.64.0." + id}, Expiry: time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)}, MachineKey: "mkey:work-" + id}
	n.UserIdentity.user = user{ID: id, Email: email, Provider: "oidc"}
	n.UserIdentity.ProviderID = "https://accounts.google.com/" + subject
	return n
}

func approvedCompanyRequest(email, subject string, access *companyAccess) companyRequest {
	return companyRequest{ID: randomToken(), Subject: subject, Email: email, Reason: "Work", Status: "approved", CreatedAt: time.Now().UTC().Format(time.RFC3339), AutoAccess: access}
}

func runAutomaticAdmission(t *testing.T, f *approvalFixture) {
	t.Helper()
	f.a.workflow.mu.Lock()
	defer f.a.workflow.mu.Unlock()
	if err := f.a.admitApprovedCompanyDevices(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestApprovedCompanySubjectAutomaticallyAdmitsCurrentAndLaterDevices(t *testing.T) {
	f := newApprovalFixture(t)
	f.a.workflow.state.Requests = []companyRequest{approvedCompanyRequest("alice@example.com", "subject-1", nil)}
	f.nodes = append(f.nodes, enrolledCompanyNode("3", "alice@example.com", "subject-1"))
	f.nodes = append(f.nodes, enrolledCompanyNode("4", "alice@example.com", "different-subject"))
	runAutomaticAdmission(t, f)
	if !slices.Equal(f.a.workflow.state.Plan.Devices, []string{"1", "3"}) || len(f.a.workflow.state.Plan.Grants) != 0 || len(f.a.workflow.state.Receipts) != 2 {
		t.Fatalf("wrong automatic device set: %+v", f.a.workflow.state.Plan)
	}
	if len(f.a.workflow.state.Proposals) != 1 || f.a.workflow.state.Proposals[0].Status != "approved" {
		t.Fatal("automatic device admission did not use reviewed policy transaction")
	}
	f.nodes = append(f.nodes, enrolledCompanyNode("5", "alice@example.com", "subject-1"))
	runAutomaticAdmission(t, f)
	if !slices.Equal(f.a.workflow.state.Plan.Devices, []string{"1", "3", "5"}) || len(f.a.workflow.state.Receipts) != 3 {
		t.Fatalf("later enrollment was not approved: %+v", f.a.workflow.state.Plan)
	}
	member, _ := memberSession(t, f.a, "alice@example.com", "subject-1", true)
	f.a.google = &googleAuth{memberDomains: map[string]bool{"example.com": true}}
	r := call(f.a, "GET", "/api/member", "", member, "", "", "127.0.0.1:18100")
	var view struct {
		Devices []struct{ Name, Status string } `json:"devices"`
	}
	if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &view) != nil || len(view.Devices) != 3 {
		t.Fatalf("member devices missing or leaked: %d %s", r.Code, r.Body.String())
	}
	for _, device := range view.Devices {
		if device.Status != "approved" {
			t.Fatalf("unexpected device status: %+v", device)
		}
	}
}

func TestAutomaticCompanyServiceGrantIsExactAndPreservesExistingPolicy(t *testing.T) {
	f := newApprovalFixture(t)
	f.approve(t)
	prior := f.a.workflow.state.Plan.Grants[0]
	f.a.workflow.state.Requests = []companyRequest{approvedCompanyRequest("alice@example.com", "subject-1", &companyAccess{Service: "Satellite", DestinationID: "2", Port: "tcp:8443"})}
	f.nodes = append(f.nodes, enrolledCompanyNode("3", "alice@example.com", "subject-1"))
	runAutomaticAdmission(t, f)
	plan := f.a.workflow.state.Plan
	if len(plan.Grants) != 2 || !slices.Contains(plan.Devices, "3") || !slices.ContainsFunc(plan.Grants, func(g accessGrant) bool {
		return g.Team == prior.Team && slices.Equal(g.Ports, prior.Ports) && slices.Equal(g.Destinations, prior.Destinations)
	}) {
		t.Fatalf("existing policy changed: %+v", plan)
	}
	var compiled compiledPolicy
	if json.Unmarshal([]byte(f.policy), &compiled) != nil || len(compiled.Grants) != 2 {
		t.Fatal("service policy missing")
	}
	sources := []string{f.a.workflow.state.Receipts["1"].Tag, f.a.workflow.state.Receipts["3"].Tag}
	slices.Sort(sources)
	destination := f.a.workflow.state.Receipts["2"].Tag
	if !slices.ContainsFunc(compiled.Grants, func(g compiledGrant) bool {
		return slices.Equal(g.Src, sources) && slices.Equal(g.Dst, []string{destination}) && slices.Equal(g.IP, []string{"tcp:8443"})
	}) {
		t.Fatalf("wrong automatic service grant: %+v", compiled.Grants)
	}
}

func TestApprovedCompanyServiceAppliesToAnAlreadyAdmittedDevice(t *testing.T) {
	f := newApprovalFixture(t)
	f.approve(t)
	f.a.workflow.state.Requests = []companyRequest{approvedCompanyRequest("alice@example.com", "subject-1", &companyAccess{Service: "Satellite", DestinationID: "2", Port: "tcp:8443"})}
	runAutomaticAdmission(t, f)
	if len(f.a.workflow.state.Plan.Grants) != 2 || len(f.a.workflow.state.Plan.Devices) != 2 {
		t.Fatalf("existing approved device did not receive service: %+v", f.a.workflow.state.Plan)
	}
}

func TestUnapprovedOrMismatchedCompanyIdentityDoesNotAutoAdmit(t *testing.T) {
	f := newApprovalFixture(t)
	f.a.workflow.state.Requests = []companyRequest{{ID: randomToken(), Subject: "subject-1", Email: "alice@example.com", Reason: "Work", Status: "pending", CreatedAt: time.Now().UTC().Format(time.RFC3339)}}
	runAutomaticAdmission(t, f)
	if len(f.a.workflow.state.Plan.Devices) != 0 || len(f.mutations) != 0 {
		t.Fatal("pending company request admitted a device")
	}
	f.a.workflow.state.Requests[0].Status = "approved"
	f.nodes[0].UserIdentity.ProviderID = "https://accounts.google.com/other-subject"
	runAutomaticAdmission(t, f)
	if len(f.a.workflow.state.Plan.Devices) != 0 || len(f.mutations) != 0 {
		t.Fatal("email-only match admitted a device")
	}
}

func TestRevokedCompanyAccessWithdrawsDevicesAndStopsLaterAdmission(t *testing.T) {
	f := newApprovalFixture(t)
	f.approve(t)
	f.a.workflow.state.Requests = []companyRequest{approvedCompanyRequest("alice@example.com", "subject-1", &companyAccess{Service: "Satellite", DestinationID: "2", Port: "tcp:8443"})}
	f.nodes = append(f.nodes, enrolledCompanyNode("3", "alice@example.com", "subject-1"))
	runAutomaticAdmission(t, f)
	id := f.a.workflow.state.Requests[0].ID
	r := call(f.a, "POST", "/api/requests/review", `{"id":"`+id+`","decision":"revoked"}`, f.cookie, f.csrf, f.a.o.origin, "127.0.0.1:18100")
	if r.Code != 200 {
		t.Fatalf("company revoke: %d %s", r.Code, r.Body.String())
	}
	if f.a.workflow.state.Requests[0].Status != "revoked" || f.a.workflow.state.Requests[0].AutoAccess != nil || !slices.Equal(f.a.workflow.state.Plan.Devices, []string{"2"}) || len(f.a.workflow.state.Plan.Grants) != 0 {
		t.Fatalf("company devices or service retained: %+v", f.a.workflow.state.Plan)
	}
	f.nodes = append(f.nodes, enrolledCompanyNode("4", "alice@example.com", "subject-1"))
	runAutomaticAdmission(t, f)
	if len(f.a.workflow.state.Plan.Devices) != 1 {
		t.Fatal("revoked identity was readmitted")
	}
}
