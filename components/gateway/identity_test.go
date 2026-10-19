package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func identityFixture(t *testing.T) (Config, clientStatus) {
	t.Helper()
	c := fixture()
	c.AllowedUsers = []string{"alice@example.com"}
	var s clientStatus
	if err := json.Unmarshal([]byte(`{"BackendState":"Running","Peer":{"nodekey:a":{"ID":"n1","UserID":7,"InNetworkMap":true,"TailscaleIPs":["100.64.0.9","fd7a:115c:a1e0::9"]},"nodekey:b":{"ID":"n2","UserID":8,"InNetworkMap":true,"TailscaleIPs":["100.64.0.10"]}},"User":{"7":{"ID":7,"LoginName":"alice@example.com"},"8":{"ID":8,"LoginName":"bob@example.com"}}}`), &s); err != nil {
		t.Fatal(err)
	}
	return c, s
}

func TestIdentityAllowlist(t *testing.T) {
	c, s := identityFixture(t)
	ips, err := allowedSources(c, s, time.Now())
	if err != nil || strings.Join(ips, ",") != "100.64.0.9" {
		t.Fatalf("got %v %v", ips, err)
	}
	for _, test := range []struct {
		name   string
		change func(*Config, *clientStatus)
	}{
		{"missing allowlist", func(c *Config, s *clientStatus) { c.AllowedUsers = nil }},
		{"unlisted user", func(c *Config, s *clientStatus) { c.AllowedUsers = []string{"charlie@example.com"} }},
		{"stopped", func(c *Config, s *clientStatus) { s.BackendState = "Stopped" }},
		{"unhealthy", func(c *Config, s *clientStatus) { s.Health = []string{"control unavailable"} }},
		{"missing user", func(c *Config, s *clientStatus) { delete(s.User, 7) }},
		{"wrong user id", func(c *Config, s *clientStatus) { s.User[7] = userProfile{ID: 8, LoginName: "alice@example.com"} }},
		{"removed peer", func(c *Config, s *clientStatus) { s.Peer["nodekey:a"].InNetworkMap = false }},
		{"missing node id", func(c *Config, s *clientStatus) { s.Peer["nodekey:a"].ID = "" }},
		{"tagged device", func(c *Config, s *clientStatus) { s.Peer["nodekey:a"].Tags = []string{"tag:server"} }},
		{"shared device", func(c *Config, s *clientStatus) { s.Peer["nodekey:a"].ShareeNode = true }},
		{"different sharer", func(c *Config, s *clientStatus) { s.Peer["nodekey:a"].AltSharerUserID = 8 }},
		{"expired", func(c *Config, s *clientStatus) { s.Peer["nodekey:a"].Expired = true }},
		{"elapsed key expiry", func(c *Config, s *clientStatus) {
			past := time.Now().Add(-time.Second)
			s.Peer["nodekey:a"].KeyExpiry = &past
		}},
		{"ip reassigned", func(c *Config, s *clientStatus) { s.Peer["nodekey:a"].UserID = 8 }},
		{"destination pool source", func(c *Config, s *clientStatus) { s.Peer["nodekey:a"].TailscaleIPs = []string{"100.80.0.8"} }},
		{"lan source", func(c *Config, s *clientStatus) { s.Peer["nodekey:a"].TailscaleIPs = []string{"192.168.1.5"} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, s := identityFixture(t)
			test.change(&c, &s)
			ips, err := allowedSources(c, s, time.Now())
			if err != nil || len(ips) != 0 {
				t.Fatalf("got %v %v", ips, err)
			}
		})
	}
	// Duplicate addresses are ambiguous even if the other owner is unlisted.
	s.Peer["nodekey:b"].TailscaleIPs = []string{"100.64.0.9"}
	if ips, err := allowedSources(c, s, time.Now()); err == nil || len(ips) != 0 {
		t.Fatal("ambiguous identity accepted")
	}
}

// Use the upstream wire text independently of the production constant so a
// change in the exception cannot silently change this regression's input.
func TestHealthWarningAuthorization(t *testing.T) {
	const routeWarning = "Some peers are advertising routes but --accept-routes is false"
	for _, test := range []struct {
		name   string
		health []string
		allow  bool
	}{
		{"healthy", nil, true},
		{"expected route warning", []string{routeWarning}, true},
		{"control failure", []string{"control unavailable"}, false},
		{"warning then failure", []string{routeWarning, "control unavailable"}, false},
		{"failure then warning", []string{"control unavailable", routeWarning}, false},
		{"unknown warning", []string{"unrecognized health condition"}, false},
		{"similar warning", []string{routeWarning + "; control unavailable"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, s := identityFixture(t)
			s.Health = test.health
			ips, err := allowedSources(c, s, time.Now())
			want := ""
			if test.allow {
				want = "100.64.0.9"
			}
			if err != nil || strings.Join(ips, ",") != want {
				t.Fatalf("got %v %v; want %q", ips, err, want)
			}
			// Ignoring this warning must never grant unlisted or tagged devices.
			c.AllowedUsers = nil
			ips, err = allowedSources(c, s, time.Now())
			if err != nil || len(ips) != 0 {
				t.Fatalf("empty allowlist opened: %v %v", ips, err)
			}
			c.AllowedUsers = []string{"alice@example.com"}
			s.Peer["nodekey:a"].Tags = []string{"tag:server"}
			ips, err = allowedSources(c, s, time.Now())
			if err != nil || len(ips) != 0 {
				t.Fatalf("tagged identity admitted: %v %v", ips, err)
			}
		})
	}
}

func TestAllowlistConfiguration(t *testing.T) {
	for _, users := range [][]string{{"*"}, {"*@example.com"}, {"group:staff"}, {"tag:server"}, {"alice@example.com", "alice@example.com"}, {"Alice@example.com"}, {"alice@example.com\n"}, {"alice@example.com; -j ACCEPT"}} {
		c := fixture()
		c.AllowedUsers = users
		if c.validate() == nil {
			t.Fatalf("unsafe allowlist accepted %q", users)
		}
	}
	c := fixture()
	c.Role = "tailgate"
	c.AllowedUsers = []string{"alice@example.com"}
	if c.validate() == nil {
		t.Fatal("allowlist on wrong gateway accepted")
	}
}

func TestFirewallIdentityRevocation(t *testing.T) {
	c := fixture()
	closed := firewall(c, "eth0", true)
	if strings.Contains(closed, "-A FORWARD") || strings.Contains(closed, "--dport 53 -j ACCEPT") {
		t.Fatal("empty allowlist opened bridge")
	}
	open := firewall(c, "eth0", true, "100.64.0.9")
	if strings.Contains(open, "100.64.0.0/10") {
		t.Fatal("wildcard source escaped allowlist")
	}
	for _, direction := range []string{"-s 100.64.0.9 -d 100.80.0.0/16", "-s 100.80.0.0/16 -d 100.64.0.9"} {
		if !strings.Contains(open, direction) {
			t.Fatal("missing source/destination gate", direction)
		}
	}
	for _, proto := range []string{"udp", "tcp"} {
		guard := "-A INPUT -i tailscale0 -p " + proto + " --dport 53 -j DROP"
		if strings.Index(open, guard) > strings.Index(open, "-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT") {
			t.Fatal("established DNS bypasses allowlist")
		}
		if !strings.Contains(closed, "-A OUTPUT -o tailscale0 -p "+proto+" --sport 53 -j DROP") {
			t.Fatal("inflight DNS reply permitted")
		}
	}
	if strings.Contains(firewall(c, "eth0", false, "100.64.0.9"), "100.64.0.9") {
		t.Fatal("inactive firewall retains allowed user")
	}
}
