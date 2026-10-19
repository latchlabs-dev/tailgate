package main

import (
	"context"
	"errors"
	"slices"
	"strings"
)

// IDs bind permissions to the verified Google subject, never a reusable email.
type userServiceAccess struct {
	Destination string   `json:"destination_id"`
	Port        string   `json:"port"`
	Users       []string `json:"user_ids"`
}
type permissionUser struct {
	ID       string              `json:"id"`
	Email    string              `json:"email"`
	Name     string              `json:"name"`
	Devices  []string            `json:"device_ids"`
	Services []serviceDefinition `json:"services"`
}

func permissionIdentity(provider string) string {
	subject := googleSubject(provider)
	if subject == "" {
		return ""
	}
	return digest("google-subject:" + subject)
}
func (w *workflow) nodePermissionIdentity(n approvalNode) string {
	if r, ok := w.state.Receipts[n.ID]; ok {
		if r.Workload || r.Fingerprint != nodeFingerprint(n) {
			return ""
		}
		return permissionIdentity(r.ProviderID)
	}
	if n.UserIdentity.Provider != "oidc" {
		return ""
	}
	return permissionIdentity(n.UserIdentity.ProviderID)
}
func (w *workflow) permissionUsers(nodes []approvalNode) []permissionUser {
	users := map[string]*permissionUser{}
	for _, r := range w.state.Requests {
		if r.Status == "approved" {
			id := permissionIdentity("accounts.google.com/" + r.Subject)
			users[id] = &permissionUser{ID: id, Email: r.Email, Name: r.Email, Devices: []string{}, Services: []serviceDefinition{}}
		}
	}
	for _, receipt := range w.state.Receipts {
		if receipt.Workload {
			continue
		}
		id := permissionIdentity(receipt.ProviderID)
		assigned := false
		for _, access := range w.state.UserAccess {
			if slices.Contains(access.Users, id) {
				assigned = true
				break
			}
		}
		if assigned && users[id] == nil {
			name := receipt.Original.DisplayName
			if name == "" {
				name = receipt.Original.Email
			}
			users[id] = &permissionUser{ID: id, Email: receipt.Original.Email, Name: name, Devices: []string{}, Services: []serviceDefinition{}}
		}
	}
	for _, n := range nodes {
		id := w.nodePermissionIdentity(n)
		if id == "" {
			continue
		}
		original := n.UserIdentity.user
		if r, ok := w.state.Receipts[n.ID]; ok {
			original = r.Original
		}
		if _, exists := users[id]; !exists {
			if ok, _ := w.eligible(n); !ok && !slices.Contains(w.state.Plan.Devices, n.ID) {
				continue
			}
			name := original.DisplayName
			if name == "" {
				name = original.Email
			}
			users[id] = &permissionUser{ID: id, Email: original.Email, Name: name, Devices: []string{}, Services: []serviceDefinition{}}
		}
		if slices.Contains(w.state.Plan.Devices, n.ID) {
			users[id].Devices = append(users[id].Devices, n.ID)
		}
	}
	access := w.effectiveUserAccess(nodes)
	for _, s := range serviceInventory(w.state) {
		for _, grant := range access {
			if grant.Destination == s.Destination && grant.Port == s.Port {
				for _, id := range grant.Users {
					if u := users[id]; u != nil {
						u.Services = append(u.Services, s)
					}
				}
			}
		}
	}
	result := []permissionUser{}
	for _, u := range users {
		slices.Sort(u.Devices)
		result = append(result, *u)
	}
	slices.SortFunc(result, func(a, b permissionUser) int { return strings.Compare(a.Email+a.ID, b.Email+b.ID) })
	return result
}

// Legacy edges are projected as user intent until an explicit migration/review.
func (w *workflow) effectiveUserAccess(nodes []approvalNode) []userServiceAccess {
	result := []userServiceAccess{}
	ids := map[string]string{}
	for _, n := range nodes {
		ids[n.ID] = w.nodePermissionIdentity(n)
	}
	for _, s := range serviceInventory(w.state) {
		entry := userServiceAccess{Destination: s.Destination, Port: s.Port, Users: []string{}}
		managed := false
		for _, saved := range w.state.UserAccess {
			if saved.Destination == s.Destination && saved.Port == s.Port {
				entry.Users = append(entry.Users, saved.Users...)
				managed = true
				break
			}
		}
		if !managed {
			for _, g := range w.state.Plan.Grants {
				if slices.Contains(g.Destinations, s.Destination) && slices.Contains(g.Ports, s.Port) {
					for _, team := range w.state.Plan.Teams {
						if team.Name == g.Team {
							for _, device := range team.Devices {
								if id := ids[device]; id != "" && !slices.Contains(entry.Users, id) {
									entry.Users = append(entry.Users, id)
								}
							}
						}
					}
				}
			}
		}
		slices.Sort(entry.Users)
		result = append(result, entry)
	}
	return result
}
func compileUserServices(plan accessPlan, access []userServiceAccess, nodes []approvalNode, w *workflow) accessPlan {
	result := accessPlan{Devices: append([]string{}, plan.Devices...), Teams: []accessTeam{}, Grants: []accessGrant{}}
	endpoints := map[string]map[string]bool{}
	definitions := map[string]userServiceAccess{}
	for _, g := range plan.Grants {
		for _, dst := range g.Destinations {
			for _, port := range g.Ports {
				key := dst + "/" + port
				if endpoints[key] == nil {
					endpoints[key] = map[string]bool{}
					definitions[key] = userServiceAccess{Destination: dst, Port: port}
				}
				for _, team := range plan.Teams {
					if team.Name == g.Team {
						for _, device := range team.Devices {
							endpoints[key][device] = true
						}
					}
				}
			}
		}
	}
	identities := map[string]string{}
	for _, n := range nodes {
		identities[n.ID] = w.nodePermissionIdentity(n)
	}
	for _, entry := range access {
		key := entry.Destination + "/" + entry.Port
		if !slices.Contains(plan.Devices, entry.Destination) {
			delete(endpoints, key)
			continue
		}
		if endpoints[key] == nil {
			endpoints[key] = map[string]bool{}
		}
		definitions[key] = entry
		for device := range endpoints[key] {
			if identities[device] != "" {
				delete(endpoints[key], device)
			}
		}
		for _, device := range plan.Devices {
			if id := identities[device]; id != "" && slices.Contains(entry.Users, id) {
				endpoints[key][device] = true
			}
		}
	}
	keys := []string{}
	for key := range endpoints {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	teams := map[string]bool{}
	for _, key := range keys {
		devices := []string{}
		for device := range endpoints[key] {
			devices = append(devices, device)
		}
		slices.Sort(devices)
		if len(devices) == 0 {
			continue
		}
		name := "users-" + digest(devices)[:24]
		if !teams[name] {
			result.Teams = append(result.Teams, accessTeam{Name: name, Devices: devices})
			teams[name] = true
		}
		entry := definitions[key]
		result.Grants = append(result.Grants, accessGrant{Team: name, Destinations: []string{entry.Destination}, Ports: []string{entry.Port}})
	}
	slices.Sort(result.Devices)
	slices.SortFunc(result.Teams, func(a, b accessTeam) int { return strings.Compare(a.Name, b.Name) })
	slices.SortFunc(result.Grants, func(a, b accessGrant) int { return strings.Compare(digest(a), digest(b)) })
	return result
}
func validateUserAccess(access []userServiceAccess) error {
	if len(access) > 128 {
		return errors.New("user service limit reached")
	}
	seen := map[string]bool{}
	for _, entry := range access {
		s := serviceDefinition{Name: "service", Destination: entry.Destination, Port: entry.Port}
		if validateServices([]serviceDefinition{s}) != nil || seen[serviceKey(s)] || len(entry.Users) > 512 {
			return errors.New("invalid user service permissions")
		}
		seen[serviceKey(s)] = true
		ids := map[string]bool{}
		for _, id := range entry.Users {
			if !sha256Hex.MatchString(id) || ids[id] {
				return errors.New("invalid permission identity")
			}
			ids[id] = true
		}
	}
	return nil
}
func (a *app) servicePermissionPlan(ctx context.Context, destination, port string, ids []string, revision uint64, inventory string) (accessPlan, []userServiceAccess, error) {
	w := a.workflow
	nodes, err := a.approvalInventory(ctx)
	if err != nil {
		return accessPlan{}, nil, err
	}
	if revision != w.state.Revision || inventory != inventoryDigest(nodes) {
		return accessPlan{}, nil, errors.New("inventory or revision changed; refresh before proposing")
	}
	known := map[string]bool{}
	for _, u := range w.permissionUsers(nodes) {
		known[u.ID] = true
	}
	for _, id := range ids {
		if !known[id] {
			return accessPlan{}, nil, errors.New("choose a verified user")
		}
	}
	access := w.effectiveUserAccess(nodes)
	found := false
	for i, s := range access {
		if s.Destination == destination && s.Port == port {
			access[i].Users = append([]string{}, ids...)
			found = true
		}
	}
	if !found {
		return accessPlan{}, nil, errors.New("choose a saved service")
	}
	if err = validateUserAccess(access); err != nil {
		return accessPlan{}, nil, err
	}
	return compileUserServices(w.state.Plan, access, nodes, w), access, nil
}
