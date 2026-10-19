package main

import (
	"context"
	"encoding/json"
	"testing"
)

func TestServiceCatalogDoesNotGrantAccessAndUsesRevisionGuard(t *testing.T) {
	f := newApprovalFixture(t)
	f.approve(t)
	before := f.policy
	v, err := f.a.workflowSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{"revision": v.Revision, "inventory": v.Inventory, "service": serviceDefinition{Name: "Internal dashboard", Destination: "2", Port: "tcp:8443"}}
	if r := f.request("service-save", payload); r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	if f.policy != before {
		t.Fatal("saving a service changed access")
	}
	if len(f.a.workflow.state.Services) != 1 {
		t.Fatal("service not saved")
	}
	if r := f.request("service-save", payload); r.Code != 409 {
		t.Fatal("stale revision accepted")
	}
	v, err = f.a.workflowSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Services) != 2 {
		t.Fatalf("expected saved and existing granted endpoints, got %+v", v.Services)
	}
	b, _ := json.Marshal(f.a.workflow.state)
	var saved workflowState
	if json.Unmarshal(b, &saved) != nil || len(saved.Services) != 1 {
		t.Fatal("catalog missing from durable state")
	}
}
func TestServiceCatalogRejectsInvalidEndpointsAndReadOnlyChanges(t *testing.T) {
	for _, service := range []serviceDefinition{
		{Name: "Wildcard", Destination: "2", Port: "tcp:*"},
		{Name: "Range", Destination: "2", Port: "tcp:1-100"},
		{Name: "Too high", Destination: "2", Port: "tcp:65536"},
		{Name: "Zero", Destination: "2", Port: "tcp:0"},
		{Name: "Bad host", Destination: "100.64.0.1", Port: "tcp:443"},
		{Name: "", Destination: "2", Port: "tcp:443"},
	} {
		if validateServices([]serviceDefinition{service}) == nil {
			t.Fatalf("accepted %+v", service)
		}
	}
	f := newApprovalFixture(t)
	f.approve(t)
	f.a.o.accessWrites = false
	if r := f.request("service-save", map[string]any{}); r.Code != 403 {
		t.Fatal("read-only catalog mutation allowed")
	}
}
