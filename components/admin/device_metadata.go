package main

import (
	"encoding/json"
	"os"
	"strings"
	"time"
)

// The web process never needs access to the controller database or raw Hostinfo.
type deviceMetadata struct {
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	OSVersion    string `json:"osVersion"`
	Model        string `json:"model"`
	Architecture string `json:"architecture"`
	Version      string `json:"version"`
}

func applyDeviceMetadata(path string, nodes []node) {
	if path == "" {
		return
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return
	}
	b, err := readBounded(path)
	var projection struct {
		CollectedAt string                    `json:"collectedAt"`
		Nodes       map[string]deviceMetadata `json:"nodes"`
	}
	if err != nil || uniqueJSON(b) != nil || json.Unmarshal(b, &projection) != nil {
		return
	}
	t, err := time.Parse(time.RFC3339, projection.CollectedAt)
	if err != nil || time.Since(t) > 5*time.Minute || t.After(time.Now().Add(time.Minute)) {
		return
	}
	for i := range nodes {
		n := &nodes[i]
		m, ok := projection.Nodes[n.ID]
		if !ok || m.Hostname != n.Name {
			continue
		}
		valid := true
		for _, s := range []string{m.Hostname, m.OS, m.OSVersion, m.Model, m.Architecture, m.Version} {
			if len(s) > 256 || strings.ContainsAny(s, "\x00\r\n") {
				valid = false
			}
		}
		if !valid {
			continue
		}
		n.OS, n.OSVersion, n.Model, n.Architecture, n.Version = m.OS, m.OSVersion, m.Model, m.Architecture, m.Version
		n.MetadataCollectedAt = projection.CollectedAt
	}
}
