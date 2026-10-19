package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDeviceMetadataProjection(t *testing.T) {
	for _, tc := range []struct {
		name     string
		age      time.Duration
		hostname string
		mode     os.FileMode
		model    string
		valid    bool
	}{
		{"current", 0, "localhost", 0600, "iPhone14,7", true},
		{"stale", -6 * time.Minute, "localhost", 0600, "iPhone14,7", false},
		{"future", 2 * time.Minute, "localhost", 0600, "iPhone14,7", false},
		{"different device", 0, "other", 0600, "iPhone14,7", false},
		{"writable", 0, "localhost", 0666, "iPhone14,7", false},
		{"invalid field", 0, "localhost", 0600, "bad\nmodel", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, _ := json.Marshal(map[string]any{"collectedAt": time.Now().Add(tc.age).UTC().Format(time.RFC3339), "nodes": map[string]any{"12": map[string]string{"hostname": tc.hostname, "os": "iOS", "osVersion": "18.0", "model": tc.model, "architecture": "arm64", "version": "1.0", "nodeKey": "secret"}}})
			path := credential(t, "metadata.json", string(payload))
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatal(err)
			}
			nodes := []node{{ID: "12", Name: "localhost"}, {ID: "13", Name: "other"}}
			applyDeviceMetadata(path, nodes)
			if (nodes[0].Model != "") != tc.valid {
				t.Fatalf("unexpected metadata: %+v", nodes[0])
			}
			if nodes[1].Model != "" {
				t.Fatal("joined wrong node")
			}
			b, _ := json.Marshal(nodes)
			if strings.Contains(string(b), "secret") {
				t.Fatal("leaked extra field")
			}
		})
	}
}
