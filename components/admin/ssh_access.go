package main

import (
	"encoding/json"
	"errors"
	"regexp"
	"slices"
)

// SSH pins authorize a specific host account between approved device identities.
// They never create a network grant and disappear when that grant is withdrawn.
type sshAccessPin struct {
	Source                 string `json:"source_id"`
	Destination            string `json:"destination_id"`
	SourceFingerprint      string `json:"source_fingerprint"`
	DestinationFingerprint string `json:"destination_fingerprint"`
	User                   string `json:"user"`
}
type compiledSSH struct {
	Action string   `json:"action"`
	Src    []string `json:"src"`
	Dst    []string `json:"dst"`
	Users  []string `json:"users"`
}

var sshAccount = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

func validateSSHAccess(pins []sshAccessPin) error {
	if len(pins) > 128 {
		return errors.New("too many SSH access pins")
	}
	seen := map[sshAccessPin]bool{}
	for _, p := range pins {
		if !idPattern.MatchString(p.Source) || !idPattern.MatchString(p.Destination) || p.Source == p.Destination || !sha256Hex.MatchString(p.SourceFingerprint) || !sha256Hex.MatchString(p.DestinationFingerprint) || !sshAccount.MatchString(p.User) || seen[p] {
			return errors.New("invalid SSH access pin")
		}
		seen[p] = true
	}
	return nil
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
	for _, pin := range w.sshAccess {
		src, ok := w.state.Receipts[pin.Source]
		if !ok || src.Fingerprint != pin.SourceFingerprint {
			continue
		}
		dst, ok := w.state.Receipts[pin.Destination]
		if !ok || dst.Fingerprint != pin.DestinationFingerprint {
			continue
		}
		if !slices.Contains(plan.Devices, pin.Source) || !slices.Contains(plan.Devices, pin.Destination) {
			continue
		}
		allowed := false
		for _, grant := range plan.Grants {
			if !slices.Contains(grant.Destinations, pin.Destination) || !slices.Contains(grant.Ports, "tcp:22") {
				continue
			}
			for _, team := range plan.Teams {
				if team.Name == grant.Team && slices.Contains(team.Devices, pin.Source) {
					allowed = true
				}
			}
		}
		if allowed {
			policy.SSH = append(policy.SSH, compiledSSH{Action: "accept", Src: []string{src.Tag}, Dst: []string{dst.Tag}, Users: []string{pin.User}})
		}
	}
	b, err := json.MarshalIndent(policy, "", "  ")
	return string(b), err
}
