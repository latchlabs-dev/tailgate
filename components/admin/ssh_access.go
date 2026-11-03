package main

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"time"
)

// SSH pins authorize a specific host account between approved device identities.
// They never create a network grant and disappear when that grant is withdrawn.
// Because a pin re-activates whenever a plan restores the matching tcp:22 grant,
// every view of a plan or proposal reports which pins that plan would activate.
type sshAccessPin struct {
	Source                 string `json:"source_id"`
	Destination            string `json:"destination_id"`
	SourceFingerprint      string `json:"source_fingerprint"`
	DestinationFingerprint string `json:"destination_fingerprint"`
	User                   string `json:"user"`
	// Action is "accept" (default) or "check". Check requires a fresh
	// Google re-authentication through the controller every CheckPeriod.
	Action      string `json:"action,omitempty"`
	CheckPeriod string `json:"check_period,omitempty"`
}
type compiledSSH struct {
	Action      string   `json:"action"`
	Src         []string `json:"src"`
	Dst         []string `json:"dst"`
	Users       []string `json:"users"`
	CheckPeriod string   `json:"checkPeriod,omitempty"`
}

// sshAccessStatus is the reviewer-facing description of one pin under a plan.
type sshAccessStatus struct {
	Source      string `json:"source_id"`
	Destination string `json:"destination_id"`
	User        string `json:"user"`
	Action      string `json:"action"`
	CheckPeriod string `json:"check_period,omitempty"`
	Active      bool   `json:"active"`
	Reason      string `json:"reason,omitempty"`
}

var sshAccount = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

const defaultCheckPeriod = "12h"

func validateSSHAccess(pins []sshAccessPin) error {
	if len(pins) > 128 {
		return errors.New("too many SSH access pins")
	}
	seen := map[sshAccessPin]bool{}
	for _, p := range pins {
		if !idPattern.MatchString(p.Source) || !idPattern.MatchString(p.Destination) || p.Source == p.Destination || !sha256Hex.MatchString(p.SourceFingerprint) || !sha256Hex.MatchString(p.DestinationFingerprint) || !sshAccount.MatchString(p.User) || p.User == "root" || seen[p] {
			return errors.New("invalid SSH access pin")
		}
		switch p.Action {
		case "", "accept":
			if p.CheckPeriod != "" {
				return errors.New("SSH check_period requires action check")
			}
		case "check":
			if p.CheckPeriod != "" {
				d, err := time.ParseDuration(p.CheckPeriod)
				if err != nil || d < time.Minute || d > 168*time.Hour {
					return errors.New("SSH check_period must be between 1m and 168h")
				}
			}
		default:
			return errors.New("SSH action must be accept or check")
		}
		seen[p] = true
	}
	return nil
}

func (p sshAccessPin) action() (string, string) {
	if p.Action != "check" {
		return "accept", ""
	}
	if p.CheckPeriod == "" {
		return "check", defaultCheckPeriod
	}
	return "check", p.CheckPeriod
}

// sshAccessUnder reports, for every configured pin, whether plan activates it.
func (w *workflow) sshAccessUnder(plan accessPlan) []sshAccessStatus {
	return w.sshAccessWith(plan, w.state.Receipts)
}

// sshAccessProjected previews a pending plan using the receipts applyProposal
// would create for not-yet-approved devices, so the preview cannot under-report.
func (w *workflow) sshAccessProjected(plan accessPlan, nodes []approvalNode) []sshAccessStatus {
	receipts := make(map[string]deviceReceipt, len(w.state.Receipts))
	for id, r := range w.state.Receipts {
		receipts[id] = r
	}
	for _, n := range nodes {
		if _, ok := receipts[n.ID]; !ok && slices.Contains(plan.Devices, n.ID) {
			receipts[n.ID] = deviceReceipt{ID: n.ID, Fingerprint: nodeFingerprint(n)}
		}
	}
	return w.sshAccessWith(plan, receipts)
}

func (w *workflow) sshAccessWith(plan accessPlan, receipts map[string]deviceReceipt) []sshAccessStatus {
	out := make([]sshAccessStatus, 0, len(w.sshAccess))
	for _, pin := range w.sshAccess {
		action, period := pin.action()
		s := sshAccessStatus{Source: pin.Source, Destination: pin.Destination, User: pin.User, Action: action, CheckPeriod: period}
		src, srcOK := receipts[pin.Source]
		dst, dstOK := receipts[pin.Destination]
		switch {
		case !srcOK || src.Fingerprint != pin.SourceFingerprint:
			s.Reason = "source device identity does not match pin"
		case !dstOK || dst.Fingerprint != pin.DestinationFingerprint:
			s.Reason = "destination device identity does not match pin"
		case !slices.Contains(plan.Devices, pin.Source) || !slices.Contains(plan.Devices, pin.Destination):
			s.Reason = "device not approved in plan"
		default:
			s.Reason = "no tcp:22 grant from a team containing the source"
			for _, grant := range plan.Grants {
				if !slices.Contains(grant.Destinations, pin.Destination) || !slices.Contains(grant.Ports, "tcp:22") {
					continue
				}
				for _, team := range plan.Teams {
					if team.Name == grant.Team && slices.Contains(team.Devices, pin.Source) {
						s.Active, s.Reason = true, ""
					}
				}
			}
		}
		out = append(out, s)
	}
	return out
}

func (w *workflow) compileAccess(plan accessPlan) (string, error) {
	raw, err := compileAccess(plan, w.state.Receipts)
	if err != nil || len(w.sshAccess) == 0 {
		return raw, err
	}
	var policy compiledPolicy
	if err = json.Unmarshal([]byte(raw), &policy); err != nil {
		return "", err
	}
	for i, s := range w.sshAccessUnder(plan) {
		if !s.Active {
			continue
		}
		pin := w.sshAccess[i]
		policy.SSH = append(policy.SSH, compiledSSH{Action: s.Action, CheckPeriod: s.CheckPeriod, Src: []string{w.state.Receipts[pin.Source].Tag}, Dst: []string{w.state.Receipts[pin.Destination].Tag}, Users: []string{pin.User}})
	}
	b, err := json.MarshalIndent(policy, "", "  ")
	return string(b), err
}

// syncSSHAccess applies SSH pin configuration changes to the already-approved
// plan. Pins live in root-owned config, so removing one must revoke it without
// waiting for the next plan approval. Only the SSH section may differ; any
// other divergence is left to the existing guards.
func (a *app) syncSSHAccess(ctx context.Context) error {
	w := a.workflow
	desired, err := w.compileAccess(w.state.Plan)
	if err != nil {
		return err
	}
	h, err := canonicalPolicy(desired)
	if err != nil || h == w.state.PolicyHash {
		return err
	}
	live, err := a.currentPolicy(ctx)
	if err != nil {
		return err
	}
	liveRest, ok1 := policyWithoutSSH(live)
	desiredRest, ok2 := policyWithoutSSH(desired)
	if !ok1 || !ok2 || liveRest != desiredRest {
		return nil
	}
	if err = a.putPolicy(ctx, desired); err != nil {
		return err
	}
	w.state.PolicyHash = h
	w.state.Revision++
	w.record("system", "SSH access configuration applied", "")
	return w.store.write(w.state)
}

func policyWithoutSSH(raw string) (string, bool) {
	var v map[string]any
	if json.Unmarshal([]byte(raw), &v) != nil {
		return "", false
	}
	delete(v, "ssh")
	return digest(v), true
}
