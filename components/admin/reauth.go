package main

import (
	"context"
	"errors"
	"slices"
)

// OIDC reauthentication deliberately converts a tagged Headscale node back to
// user ownership. Restore only an existing, unexpired exact-machine approval
// after the original Google identity has authenticated again. Never repair a
// different tag, key, account, workload, exclusion or revoked company request.
func (w *workflow) reauthProjection(plan accessPlan, nodes []approvalNode) ([]approvalNode, []string) {
	projected := append([]approvalNode{}, nodes...)
	ids := []string{}
	for i, n := range projected {
		r, exists := w.state.Receipts[n.ID]
		if !exists || !slices.Contains(plan.Devices, n.ID) || r.Workload || len(n.Tags) != 0 ||
			r.Fingerprint != nodeFingerprint(n) || expiredAt(r.Expiry) || expiredAt(n.Expiry) ||
			n.UserIdentity.Provider != "oidc" || n.UserIdentity.ID != r.Original.ID ||
			n.UserIdentity.Email != r.Original.Email || googleSubject(n.UserIdentity.ProviderID) == "" ||
			googleSubject(n.UserIdentity.ProviderID) != googleSubject(r.ProviderID) {
			continue
		}
		if _, excluded := w.state.AutoExcluded[n.ID]; excluded {
			continue
		}
		revoked := false
		for _, request := range w.state.Requests {
			if request.Subject == googleSubject(r.ProviderID) && request.Email == r.Original.Email && (request.Status == "revoked" || request.Status == "rejected") {
				revoked = true
			}
		}
		if revoked {
			continue
		}
		projected[i].Tags = []string{r.Tag}
		ids = append(ids, n.ID)
	}
	return projected, ids
}

func (a *app) restoreReauthenticated(ctx context.Context, plan accessPlan, nodes []approvalNode, who string) ([]approvalNode, error) {
	w := a.workflow
	projected, ids := w.reauthProjection(plan, nodes)
	if len(ids) == 0 {
		return nodes, nil
	}
	checked := copyPlan(plan)
	if err := validatePlan(&checked, projected, w); err != nil {
		return nil, err
	}
	if err := a.policyGuard(ctx); err != nil {
		return nil, err
	}
	if w.state.Pending != "" {
		return nil, errors.New("another approval transition is pending")
	}
	w.state.Pending = "reauth-" + randomToken()
	w.record(who, "reauthentication tag restoration started", "")
	if err := w.store.write(w.state); err != nil {
		return nil, err
	}
	for _, id := range ids {
		// Recheck the original identity immediately before each privileged mutation.
		current, err := a.approvalInventory(ctx)
		if err != nil {
			return nil, a.failReauthentication("Reauthentication inventory could not be verified")
		}
		_, safe := w.reauthProjection(plan, current)
		if !slices.Contains(safe, id) {
			return nil, a.failReauthentication("Reauthentication identity changed during restoration")
		}
		if err = a.upstreamContext(ctx, "POST", "/api/v1/node/"+id+"/tags", map[string][]string{"tags": {w.state.Receipts[id].Tag}}, nil); err != nil {
			return nil, a.failReauthentication("Reauthentication approval tag could not be restored")
		}
		w.record(who, "restored approval tag for device "+id, "")
	}
	result, err := a.approvalInventory(ctx)
	if err == nil {
		err = validatePlan(&checked, result, w)
	}
	if err != nil {
		return nil, a.failReauthentication("Reauthentication tag readback failed")
	}
	w.state.Pending = ""
	w.state.Revision++
	if err = w.store.write(w.state); err != nil {
		return nil, a.failReauthentication("Reauthentication receipt could not be saved")
	}
	return result, nil
}

func (a *app) failReauthentication(reason string) error {
	if err := a.blockWorkflow(reason); err != nil {
		return err
	}
	return errors.New(reason)
}
