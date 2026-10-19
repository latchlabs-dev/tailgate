package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

func googleSubject(providerID string) string {
	for _, prefix := range []string{"https://accounts.google.com/", "accounts.google.com/"} {
		if subject, ok := strings.CutPrefix(providerID, prefix); ok && googleMemberSubject.MatchString(subject) {
			return subject
		}
	}
	return ""
}

// Company approval is tied to the signed Google subject used for the request,
// not an email selector that a different account could later claim.
func (w *workflow) approvedRequestForIdentity(email, providerID string) *companyRequest {
	subject := googleSubject(providerID)
	if subject == "" {
		return nil
	}
	for i := range w.state.Requests {
		r := &w.state.Requests[i]
		if r.Status == "approved" && r.Subject == subject && r.Email == email {
			return r
		}
	}
	return nil
}

func copyPlan(p accessPlan) accessPlan {
	result := accessPlan{Devices: append([]string{}, p.Devices...), Teams: make([]accessTeam, len(p.Teams)), Grants: make([]accessGrant, len(p.Grants))}
	for i, team := range p.Teams {
		result.Teams[i] = accessTeam{Name: team.Name, Devices: append([]string{}, team.Devices...)}
	}
	for i, grant := range p.Grants {
		result.Grants[i] = accessGrant{Team: grant.Team, Destinations: append([]string{}, grant.Destinations...), Ports: append([]string{}, grant.Ports...)}
	}
	return result
}

func addCompanyService(plan *accessPlan, request companyRequest, deviceID string) error {
	if request.AutoAccess == nil {
		return nil
	}
	access := request.AutoAccess
	if !slices.Contains(plan.Devices, access.DestinationID) {
		return errors.New("approved service destination is unavailable")
	}
	team := "company-" + digest(request.ID)[:24]
	teamIndex := -1
	for i := range plan.Teams {
		if plan.Teams[i].Name == team {
			teamIndex = i
			break
		}
	}
	if teamIndex < 0 {
		plan.Teams = append(plan.Teams, accessTeam{Name: team, Devices: []string{deviceID}})
	} else if !slices.Contains(plan.Teams[teamIndex].Devices, deviceID) {
		plan.Teams[teamIndex].Devices = append(plan.Teams[teamIndex].Devices, deviceID)
	}
	for _, grant := range plan.Grants {
		if grant.Team != team {
			continue
		}
		if len(grant.Destinations) != 1 || grant.Destinations[0] != access.DestinationID || len(grant.Ports) != 1 || grant.Ports[0] != access.Port {
			return errors.New("automatic service grant differs from the approved company request")
		}
		return nil
	}
	plan.Grants = append(plan.Grants, accessGrant{Team: team, Destinations: []string{access.DestinationID}, Ports: []string{access.Port}})
	return nil
}

// Called under workflow.mu only after normal policy/inventory reconciliation.
// Each addition uses the same exact-node proposal, receipt, tag and read-back
// transaction as an administrator's manual device approval.
func (a *app) admitApprovedCompanyDevices(ctx context.Context) error {
	w := a.workflow
	if w.state.Blocked != "" || w.state.Pending != "" {
		return nil
	}
	nodes, err := a.approvalInventory(ctx)
	if err != nil {
		return err
	}
	slices.SortFunc(nodes, func(a, b approvalNode) int { return strings.Compare(a.ID, b.ID) })
	plan := copyPlan(w.state.Plan)
	before := digest(plan)
	newDevices := 0
	for _, node := range nodes {
		if ok, _ := w.eligible(node); !ok {
			continue
		}
		if receipt, prior := w.state.Receipts[node.ID]; prior {
			if slices.Contains(plan.Devices, node.ID) {
				if request := w.approvedRequestForIdentity(receipt.Original.Email, receipt.ProviderID); request != nil {
					if err := addCompanyService(&plan, *request, node.ID); err != nil {
						return err
					}
				}
			}
			continue
		}
		if newDevices == 16 || slices.Contains(plan.Devices, node.ID) {
			continue
		}
		if fingerprint, excluded := w.state.AutoExcluded[node.ID]; excluded && fingerprint == nodeFingerprint(node) {
			continue
		}
		request := w.approvedRequestForIdentity(node.UserIdentity.Email, node.UserIdentity.ProviderID)
		if request == nil {
			continue
		}
		plan.Devices = append(plan.Devices, node.ID)
		if err := addCompanyService(&plan, *request, node.ID); err != nil {
			return err
		}
		newDevices++
	}
	if len(w.state.UserAccess) > 0 {
		plan = compileUserServices(plan, w.state.UserAccess, nodes, w)
	}
	if digest(plan) == before {
		return nil
	}
	if err := validatePlan(&plan, nodes, w); err != nil {
		return err
	}
	previous, err := json.Marshal(w.state)
	if err != nil {
		return err
	}
	if len(w.state.Proposals) >= 128 {
		pruned := []accessProposal{}
		for _, proposal := range w.state.Proposals {
			if proposal.Status == "pending" {
				pruned = append(pruned, proposal)
			}
		}
		if len(pruned) >= 128 {
			return errors.New("pending proposal limit reached")
		}
		w.state.Proposals = pruned
	}
	id := randomToken()
	w.state.Proposals = append(w.state.Proposals, accessProposal{ID: id, Revision: w.state.Revision, Inventory: inventoryDigest(nodes), Plan: plan, Comment: "Automatic device admission for approved company requests", Status: "pending", CreatedAt: time.Now().UTC().Format(time.RFC3339), Actor: "system:company-approval"})
	w.record("system:company-approval", "proposed", id)
	if err := w.store.write(w.state); err != nil {
		_ = json.Unmarshal(previous, &w.state)
		return err
	}
	if err := a.applyProposal(ctx, id, "system:company-approval"); err != nil {
		if w.state.Blocked == "" && w.state.Pending == "" {
			for i := range w.state.Proposals {
				if w.state.Proposals[i].ID == id {
					w.state.Proposals[i].Status = "failed"
					break
				}
			}
			w.record("system:company-approval", "failed", id)
			if persistErr := w.store.write(w.state); persistErr != nil {
				return fmt.Errorf("automatic approval failed and its failure could not be saved: %w", persistErr)
			}
		}
		return err
	}
	return nil
}
