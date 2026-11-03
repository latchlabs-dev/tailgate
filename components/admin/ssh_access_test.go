package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func sshFixture() (*workflow, accessPlan) {
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	w := &workflow{sshAccess: []sshAccessPin{{Source: "1", Destination: "2", SourceFingerprint: a, DestinationFingerprint: b, User: "operator"}}, state: workflowState{Receipts: map[string]deviceReceipt{"1": {Tag: "tag:tailgate-" + strings.Repeat("a", 32), Fingerprint: a}, "2": {Tag: "tag:tailgate-" + strings.Repeat("b", 32), Fingerprint: b}}}}
	p := accessPlan{Devices: []string{"1", "2"}, Teams: []accessTeam{{Name: "operators", Devices: []string{"1"}}}, Grants: []accessGrant{{Team: "operators", Destinations: []string{"2"}, Ports: []string{"tcp:22"}}}}
	return w, p
}
func TestSSHAccessRequiresExactApprovedNetworkEdge(t *testing.T) {
	for _, scenario := range []string{"allowed", "withdrawn", "wrong-port", "identity-drift", "deny-all"} {
		t.Run(scenario, func(t *testing.T) {
			w, p := sshFixture()
			switch scenario {
			case "withdrawn":
				p.Grants = nil
			case "wrong-port":
				p.Grants[0].Ports = []string{"tcp:443"}
			case "identity-drift":
				r := w.state.Receipts["1"]
				r.Fingerprint = strings.Repeat("c", 64)
				w.state.Receipts["1"] = r
			case "deny-all":
				p = emptyPlan()
			}
			raw, err := w.compileAccess(p)
			if err != nil {
				t.Fatal(err)
			}
			var v compiledPolicy
			if err = json.Unmarshal([]byte(raw), &v); err != nil {
				t.Fatal(err)
			}
			if scenario == "allowed" {
				if len(v.SSH) != 1 || v.SSH[0].Users[0] != "operator" || v.SSH[0].Src[0] != w.state.Receipts["1"].Tag {
					t.Fatal("missing exact SSH rule")
				}
			} else if len(v.SSH) != 0 {
				t.Fatal("SSH survived withdrawal or identity change")
			}
		})
	}
}
func TestSSHAccessRejectsWildcardAccounts(t *testing.T) {
	w, _ := sshFixture()
	for _, u := range []string{"*", "autogroup:nonroot", "alice@example.com", "a b", "-bad", "root"} {
		p := w.sshAccess[0]
		p.User = u
		if validateSSHAccess([]sshAccessPin{p}) == nil {
			t.Fatalf("accepted account %q", u)
		}
	}
}
func TestNativeSSHAccessPolicy(t *testing.T) {
	_, a, _, _ := nativeApprovalFixture(t)
	w, p := sshFixture()
	raw, err := w.compileAccess(p)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.putPolicy(context.Background(), raw); err != nil {
		t.Fatal("native controller rejected exact tagged SSH policy:", err)
	}
}
func TestSSHAccessActionValidation(t *testing.T) {
	w, _ := sshFixture()
	for _, c := range []struct {
		action, period string
		ok             bool
	}{{"", "", true}, {"accept", "", true}, {"check", "", true}, {"check", "12h", true}, {"accept", "12h", false}, {"check", "30s", false}, {"check", "200h", false}, {"check", "soon", false}, {"deny", "", false}} {
		p := w.sshAccess[0]
		p.Action, p.CheckPeriod = c.action, c.period
		if (validateSSHAccess([]sshAccessPin{p}) == nil) != c.ok {
			t.Fatalf("action %q period %q: want ok=%v", c.action, c.period, c.ok)
		}
	}
}
func TestSSHAccessCheckModeCompiles(t *testing.T) {
	w, p := sshFixture()
	w.sshAccess[0].Action = "check"
	raw, err := w.compileAccess(p)
	if err != nil {
		t.Fatal(err)
	}
	var v compiledPolicy
	if err = json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatal(err)
	}
	if len(v.SSH) != 1 || v.SSH[0].Action != "check" || v.SSH[0].CheckPeriod != defaultCheckPeriod {
		t.Fatalf("check rule not compiled: %+v", v.SSH)
	}
}
func TestSSHAccessStatusExplainsActivation(t *testing.T) {
	w, p := sshFixture()
	if s := w.sshAccessUnder(p); len(s) != 1 || !s[0].Active || s[0].Action != "accept" {
		t.Fatalf("expected active pin: %+v", s)
	}
	p.Grants = nil
	if s := w.sshAccessUnder(p); len(s) != 1 || s[0].Active || s[0].Reason == "" {
		t.Fatalf("expected inactive pin with reason: %+v", s)
	}
}
func TestNativeSSHCheckPolicy(t *testing.T) {
	_, a, _, _ := nativeApprovalFixture(t)
	w, p := sshFixture()
	w.sshAccess[0].Action = "check"
	raw, err := w.compileAccess(p)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.putPolicy(context.Background(), raw); err != nil {
		t.Fatal("native controller rejected check-mode SSH policy:", err)
	}
}
