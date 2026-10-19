package main

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

var iface = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,15}$`)

// Rules replace ONLY the namespace owned by this PID-1 container. Both official
// clients run with netfilter-mode=off: independent default-drop chains replace
// their CGNAT anti-spoof rules, which otherwise reject this transit path.
func firewall(c Config, transit string, active bool, sources ...string) string {
	if !iface.MatchString(transit) {
		panic("invalid interface")
	}
	for _, source := range sources {
		a, err := netip.ParseAddr(source)
		if err != nil || !a.Is4() || !netip.MustParsePrefix("100.64.0.0/10").Contains(a) || netip.MustParsePrefix(c.Pool).Contains(a) {
			panic("invalid authorized source")
		}
	}
	var b strings.Builder
	b.WriteString("*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n-F INPUT\n-F FORWARD\n-F OUTPUT\n")
	b.WriteString("-A INPUT -i lo -j ACCEPT\n-A INPUT -m conntrack --ctstate INVALID -j DROP\n")
	// Do not allow a forged established packet on the transit interface.
	fmt.Fprintf(&b, "-A INPUT -i %s ! -s %s -j DROP\n", transit, c.TransitPeer)
	if c.Role == "hosted" {
		// Check every DNS packet before the generic established-flow accept.
		// Removing a user must also stop previously established TCP/UDP sessions
		// and responses still in flight, not merely prevent new connections.
		for _, proto := range []string{"udp", "tcp"} {
			if active {
				for _, source := range sources {
					fmt.Fprintf(&b, "-A INPUT -i tailscale0 -s %s -p %s --dport 53 -j ACCEPT\n", source, proto)
					fmt.Fprintf(&b, "-A OUTPUT -o tailscale0 -d %s -p %s --sport 53 -j ACCEPT\n", source, proto)
				}
			}
			fmt.Fprintf(&b, "-A INPUT -i tailscale0 -p %s --dport 53 -j DROP\n", proto)
			fmt.Fprintf(&b, "-A OUTPUT -o tailscale0 -p %s --sport 53 -j DROP\n", proto)
		}
	}
	b.WriteString("-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n")
	fmt.Fprintf(&b, "-A INPUT ! -i %s -p udp --dport 41641 -j ACCEPT\n", transit)
	if active {
		if c.Role == "hosted" {
			for _, source := range sources {
				fmt.Fprintf(&b, "-A FORWARD -i tailscale0 -o %s -s %s -d %s -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT\n", transit, source, c.Pool)
				fmt.Fprintf(&b, "-A FORWARD -i %s -o tailscale0 -s %s -d %s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n", transit, c.Pool, source)
			}
		} else {
			for _, proto := range []string{"udp", "tcp"} {
				fmt.Fprintf(&b, "-A INPUT -i %s -s %s -d %s -p %s --dport 5353 -j ACCEPT\n", transit, c.TransitPeer, c.TransitAddress, proto)
			}
			fmt.Fprintf(&b, "-A FORWARD -i %s -o tailscale0 -s %s -d %s -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT\n", transit, c.TransitPeer, c.Pool)
			fmt.Fprintf(&b, "-A FORWARD -i tailscale0 -o %s -s %s -d %s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n", transit, c.Pool, c.TransitPeer)
		}
	}
	// Preserve Docker's embedded DNS DNAT rules in OUTPUT/POSTROUTING.
	// Only our dedicated NAT chain is replaced with --noflush.
	b.WriteString("COMMIT\n*nat\n:TG_GATEWAY - [0:0]\n-F TG_GATEWAY\n")
	if active {
		if c.Role == "hosted" {
			for _, source := range sources {
				fmt.Fprintf(&b, "-A TG_GATEWAY -o %s -s %s -d %s -j SNAT --to-source %s\n", transit, source, c.Pool, c.TransitAddress)
			}
		} else {
			fmt.Fprintf(&b, "-A TG_GATEWAY -o tailscale0 -s %s -d %s -j MASQUERADE\n", c.TransitPeer, c.Pool)
		}
	}
	b.WriteString("COMMIT\n")
	return b.String()
}

const ipv6Firewall = "*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n-A INPUT -i lo -j ACCEPT\n-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\nCOMMIT\n"
