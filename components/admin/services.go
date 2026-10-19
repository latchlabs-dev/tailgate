package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

type serviceDefinition struct {
	Name        string `json:"name"`
	Destination string `json:"destination_id"`
	Port        string `json:"port"`
}

func serviceKey(s serviceDefinition) string { return s.Destination + "/" + s.Port }
func validateServices(services []serviceDefinition) error {
	if len(services) > 128 {
		return errors.New("service catalog limit reached")
	}
	seen := map[string]bool{}
	for _, s := range services {
		m := exactPort.FindStringSubmatch(s.Port)
		port := 0
		if len(m) == 3 {
			_, _ = fmt.Sscanf(m[2], "%d", &port)
		}
		if !idPattern.MatchString(s.Destination) || len(m) != 3 || port < 1 || port > 65535 || len(s.Name) > 80 || strings.TrimSpace(s.Name) == "" || strings.ContainsAny(s.Name, "\x00\r\n") || seen[serviceKey(s)] {
			return errors.New("service requires a unique destination, name and concrete TCP/UDP port")
		}
		seen[serviceKey(s)] = true
	}
	return nil
}
func serviceInventory(state workflowState) []serviceDefinition {
	result := append([]serviceDefinition{}, state.Services...)
	seen := map[string]bool{}
	for _, s := range result {
		seen[serviceKey(s)] = true
	}
	for _, entry := range state.UserAccess {
		s := serviceDefinition{Name: strings.ToUpper(strings.ReplaceAll(entry.Port, ":", " ")), Destination: entry.Destination, Port: entry.Port}
		if !seen[serviceKey(s)] {
			result = append(result, s)
			seen[serviceKey(s)] = true
		}
	}
	for _, g := range state.Plan.Grants {
		for _, destination := range g.Destinations {
			for _, port := range g.Ports {
				s := serviceDefinition{Name: strings.ToUpper(strings.ReplaceAll(port, ":", " ")), Destination: destination, Port: port}
				if !seen[serviceKey(s)] {
					result = append(result, s)
					seen[serviceKey(s)] = true
				}
			}
		}
	}
	slices.SortFunc(result, func(a, b serviceDefinition) int { return strings.Compare(a.Name+serviceKey(a), b.Name+serviceKey(b)) })
	return result
}
func (a *app) saveService(ctx context.Context, service serviceDefinition, revision uint64, inventory, who string) error {
	w := a.workflow
	if w.state.Blocked != "" || w.state.Pending != "" {
		return errors.New("restore network access before changing services")
	}
	nodes, err := a.approvalInventory(ctx)
	if err != nil {
		return err
	}
	if revision != w.state.Revision || inventory != inventoryDigest(nodes) {
		return errors.New("inventory or revision changed; refresh before saving")
	}
	if !slices.Contains(w.state.Plan.Devices, service.Destination) {
		return errors.New("choose an approved destination device")
	}
	checked := copyPlan(w.state.Plan)
	if err = validatePlan(&checked, nodes, w); err != nil {
		return err
	}
	if err = a.policyGuard(ctx); err != nil {
		return err
	}
	services := append([]serviceDefinition{}, w.state.Services...)
	found := false
	service.Name = strings.TrimSpace(service.Name)
	for i, s := range services {
		if serviceKey(s) == serviceKey(service) {
			services[i] = service
			found = true
		}
	}
	if !found {
		services = append(services, service)
	}
	if err = validateServices(services); err != nil {
		return err
	}
	before, _ := json.Marshal(w.state)
	w.state.Services = services
	w.state.Revision++
	w.record(who, "saved service "+service.Name, "")
	if err = w.store.write(w.state); err != nil {
		_ = json.Unmarshal(before, &w.state)
		return err
	}
	return nil
}
