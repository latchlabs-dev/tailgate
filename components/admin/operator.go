package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"strings"
	"time"
)

// This mode has no HTTP listener. It requires existing private administrator
// credentials and exclusive state locks; the public administrator must be stopped.
type operatorRequest struct {
	MigrateUserServices    bool       `json:"migrate_user_services"`
	Actor                  string     `json:"actor"`
	Revision               uint64     `json:"revision"`
	Inventory              string     `json:"inventory"`
	Plan                   accessPlan `json:"plan"`
	Comment                string     `json:"comment"`
	Reconcile              bool       `json:"reconcile"`
	RestoreReauthenticated bool       `json:"restore_reauthenticated"`
}

func (a *app) operatorApproval(path string, apply bool, out io.Writer) error {
	if a.workflow == nil || !a.o.accessWrites || a.o.demo {
		return errors.New("operator approval requires the real enabled workflow")
	}
	info, err := os.Lstat(path)
	if err != nil || !ownedPrivate(info, false) {
		return errors.New("operator request must be private and owned by this process")
	}
	b, err := readBounded(path)
	if err != nil || uniqueJSON(b) != nil {
		return errors.New("invalid operator request")
	}
	var request operatorRequest
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if d.Decode(&request) != nil || !regexp.MustCompile(`^operator:[a-zA-Z0-9._-]{1,64}$`).MatchString(request.Actor) || len(request.Comment) > 512 {
		return errors.New("invalid operator request")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	w := a.workflow
	w.mu.Lock()
	defer w.mu.Unlock()
	nodes, err := a.approvalInventory(ctx)
	if err != nil {
		return err
	}
	var userAccess []userServiceAccess
	if request.MigrateUserServices {
		if w.state.Blocked != "" || w.state.Pending != "" {
			return errors.New("restore workflow before migrating user permissions")
		}
		userAccess = w.effectiveUserAccess(nodes)
		if err = validateUserAccess(userAccess); err != nil {
			return err
		}
		request.Plan = compileUserServices(w.state.Plan, userAccess, nodes, w)
	}
	if !request.MigrateUserServices && len(w.state.UserAccess) > 0 {
		request.Plan = compileUserServices(request.Plan, w.state.UserAccess, nodes, w)
	}
	validationNodes := nodes
	if request.RestoreReauthenticated {
		validationNodes, _ = w.reauthProjection(request.Plan, nodes)
	}
	if err = validatePlan(&request.Plan, validationNodes, w); err != nil {
		return err
	}
	inventory := inventoryDigest(nodes)
	if !apply {
		return json.NewEncoder(out).Encode(map[string]any{"revision": w.state.Revision, "inventory": inventory, "plan": request.Plan, "user_access": userAccess, "blocked": w.state.Blocked, "apply": false})
	}
	if request.Revision != w.state.Revision || request.Inventory != inventory {
		return errors.New("operator request inventory or revision changed; review again")
	}
	if request.RestoreReauthenticated {
		nodes, err = a.restoreReauthenticated(ctx, request.Plan, nodes, request.Actor)
		if err != nil {
			return err
		}
		inventory = inventoryDigest(nodes)
	}
	if request.Reconcile {
		bootstrap := len(w.state.Receipts) == 0 && len(w.state.Plan.Devices) == 0 && len(w.state.Plan.Grants) == 0
		if !bootstrap {
			if w.state.Blocked == "" && w.state.Pending == "" {
				return errors.New("operator reconciliation requires a blocked approval workflow")
			}
			if !w.state.DenialVerified || w.state.Pending != "" || len(w.state.Plan.Devices) != 0 || len(w.state.Plan.Grants) != 0 {
				return errors.New("operator recovery requires verified deny-all and an empty current plan")
			}
		}
		if err = a.reconcileWorkflow(ctx, true, request.Actor); err != nil {
			return err
		}
	}
	if w.state.Blocked != "" || w.state.Pending != "" {
		return errors.New("workflow is blocked; explicit reconciliation is required")
	}
	if len(w.state.Proposals) >= 128 {
		return errors.New("pending proposal limit reached")
	}
	id := randomToken()
	w.state.Proposals = append(w.state.Proposals, accessProposal{ID: id, Revision: w.state.Revision, Inventory: inventory, Plan: request.Plan, UserAccess: userAccess, Comment: request.Comment, Status: "pending", CreatedAt: time.Now().UTC().Format(time.RFC3339), Actor: request.Actor})
	w.record(request.Actor, "proposed", id)
	if err = w.store.write(w.state); err != nil {
		return err
	}
	if err = a.applyProposal(ctx, id, request.Actor); err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(map[string]any{"revision": w.state.Revision, "proposal": id, "status": "approved", "plan": w.state.Plan})
}
