package main

import (
	"errors"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// These fields mirror the pinned official client's ipnstate.Status. Identity
// comes exclusively from its root-only local socket and authenticated netmap,
// never from DNS, a packet-supplied email, hostname, or a static source-IP list.
type peerStatus struct {
	ID              string
	UserID          int64
	TailscaleIPs    []string
	Tags            []string
	AltSharerUserID int64
	ShareeNode      bool
	InNetworkMap    bool
	Expired         bool
	KeyExpiry       *time.Time
}

type userProfile struct {
	ID        int64
	LoginName string
}

func validLogin(s string) bool {
	if len(s) > 254 || s != strings.ToLower(s) || strings.Count(s, "@") != 1 {
		return false
	}
	parts := strings.Split(s, "@")
	if parts[0] == "" || len(parts[0]) > 64 || !strings.Contains(parts[1], ".") {
		return false
	}
	for _, r := range parts[0] {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || strings.ContainsRune("._+-", r)) {
			return false
		}
	}
	for _, part := range strings.Split(parts[1], ".") {
		if !label.MatchString(part) {
			return false
		}
	}
	return true
}

// The pinned Tailscale 1.102.5 client reports this informational warning because
// we intentionally disable route acceptance. Other subnet routers do not make
// its authenticated peer identities unhealthy. Match only the exact upstream
// health/healthmsg.WarnAcceptRoutesOff text; unknown/changed warnings stay closed.
const expectedRoutesOffWarning = "Some peers are advertising routes but --accept-routes is false"

func allowedSources(c Config, s clientStatus, now time.Time) ([]string, error) {
	// An empty/missing allowlist always means closed, including with allow-all
	// hosted ACLs. All health messages except the expected route warning close it.
	if c.Role != "hosted" || len(c.AllowedUsers) == 0 || s.BackendState != "Running" {
		return nil, nil
	}
	for _, warning := range s.Health {
		if warning != expectedRoutesOffWarning {
			return nil, nil
		}
	}
	users := map[string]bool{}
	for _, u := range c.AllowedUsers {
		users[u] = true
	}
	pool := netip.MustParsePrefix(c.Pool)
	cgnat := netip.MustParsePrefix("100.64.0.0/10")
	seen := map[netip.Addr]bool{}
	var sources []string
	for _, peer := range s.Peer {
		if peer == nil || !peer.InNetworkMap {
			continue
		}
		u, exists := s.User[peer.UserID]
		eligible := exists && peer.UserID > 0 && u.ID == peer.UserID && peer.ID != "" &&
			users[strings.ToLower(u.LoginName)] && len(peer.Tags) == 0 && !peer.ShareeNode &&
			peer.AltSharerUserID == 0 && !peer.Expired &&
			(peer.KeyExpiry == nil || peer.KeyExpiry.IsZero() || now.Before(*peer.KeyExpiry))
		for _, raw := range peer.TailscaleIPs {
			a, err := netip.ParseAddr(raw)
			if err != nil {
				return nil, errors.New("invalid peer address; forwarding closed")
			}
			if !a.Is4() {
				continue
			}
			if seen[a] {
				return nil, errors.New("ambiguous peer address; forwarding closed")
			}
			seen[a] = true
			if eligible && cgnat.Contains(a) && !pool.Contains(a) {
				sources = append(sources, a.String())
			}
		}
	}
	if len(sources) > 4096 {
		return nil, errors.New("too many allowed devices; forwarding closed")
	}
	sort.Strings(sources)
	return sources, nil
}
