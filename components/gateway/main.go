package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func command(input string, name string, args ...string) ([]byte, error) {
	return timedCommand(15*time.Second, input, name, args...)
}

func timedCommand(timeout time.Duration, input string, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	b, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s failed", name)
	} // Never log keys, status, or daemon output.
	return b, nil
}

func ts(args ...string) ([]byte, error) {
	return command("", "tailscale", append([]string{"--socket=/run/tailscale/tailscaled.sock"}, args...)...)
}

type clientStatus struct {
	BackendState string
	TailscaleIPs []string
	Health       []string
	Peer         map[string]*peerStatus
	User         map[int64]userProfile
}

func status() (clientStatus, error) {
	var s clientStatus
	b, e := timedCommand(3*time.Second, "", "tailscale", "--socket=/run/tailscale/tailscaled.sock", "status", "--json")
	if e != nil {
		return s, e
	}
	e = json.Unmarshal(b, &s)
	return s, e
}

func findTransit(c Config) (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, i := range interfaces {
		addresses, _ := i.Addrs()
		for _, a := range addresses {
			p, e := netip.ParsePrefix(a.String())
			if e == nil && p.Addr().String() == c.TransitAddress && p.Bits() == 29 && iface.MatchString(i.Name) {
				return i.Name, nil
			}
		}
	}
	return "", errors.New("configured /29 transit interface not present")
}

func run(c Config) error {
	// A root process on the host must never flush the host firewall. The only
	// supported runtime is a dedicated container with this executable as PID 1.
	if os.Getpid() != 1 || os.Geteuid() != 0 {
		return errors.New("run as root PID 1 in a dedicated network container; never use host networking or host PID mode")
	}
	transit, err := findTransit(c)
	if err != nil {
		return err
	}
	remote := newConfigReader(c.ConfigService)
	var sources []string
	apply := func(active bool) error {
		_, e := command(firewall(c, transit, active, sources...), "iptables-nft-restore", "--noflush", "--wait", "5")
		return e
	}
	if err = apply(false); err != nil {
		return err
	}
	if _, err = command("", "iptables-nft", "-t", "nat", "-C", "POSTROUTING", "-j", "TG_GATEWAY"); err != nil {
		if _, err = command("", "iptables-nft", "-t", "nat", "-A", "POSTROUTING", "-j", "TG_GATEWAY"); err != nil {
			return err
		}
	}
	if _, err = command(ipv6Firewall, "ip6tables-nft-restore", "--wait", "5"); err != nil {
		return err
	}
	defer apply(false)
	os.Remove("/run/gateway-ready")
	if err = os.MkdirAll("/run/tailscale", 0700); err != nil {
		return err
	}
	if err = os.MkdirAll("/state", 0700); err != nil {
		return err
	}
	if err = os.Chmod("/state", 0700); err != nil {
		return err
	}
	if c.Role == "hosted" {
		if _, err = command("", "ip", "route", "replace", c.Pool, "via", c.TransitPeer, "dev", transit); err != nil {
			return err
		}
		if _, err = command("", "ip", "rule", "add", "pref", "100", "to", c.Pool, "lookup", "main"); err != nil {
			return err
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	daemon := exec.Command("tailscaled", "--state=/state/tailscaled.state", "--socket=/run/tailscale/tailscaled.sock", "--tun=tailscale0", "--port=41641")
	// Upstream logs can include enrollment URLs and credentials. Operators use
	// the local client socket for enrollment/status; don't stream daemon logs.
	if err = daemon.Start(); err != nil {
		return errors.New("could not start official client")
	}
	done := make(chan error, 1)
	go func() { done <- daemon.Wait() }()
	defer func() {
		_ = apply(false)
		_ = daemon.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(4 * time.Second):
			_ = daemon.Process.Kill()
		}
	}()
	for n := 0; n < 50; n++ {
		if _, err = status(); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return nil
		case <-done:
			return errors.New("official client stopped")
		case <-time.After(100 * time.Millisecond):
		}
	}
	args := []string{"up", "--timeout=10s", "--login-server=" + c.LoginServer, "--hostname=" + c.Hostname, "--accept-dns=false", "--accept-routes=false", "--netfilter-mode=off", "--snat-subnet-routes=false", "--ssh=false"}
	if c.Role == "hosted" {
		args = append(args, "--advertise-routes="+c.Pool)
	} else {
		args = append(args, "--advertise-routes=")
	}
	if c.AuthKeyFile != "" {
		args = append(args, "--auth-key=file:"+c.AuthKeyFile)
	}
	// NeedsLogin is expected on first start without a key. The enrollment URL
	// remains available through `tailscale status --json` inside this container.
	_, upErr := ts(args...)
	s, err := status()
	if err != nil {
		return err
	}
	if upErr != nil && (s.BackendState != "NeedsLogin" || c.AuthKeyFile != "") {
		return errors.New("client configuration failed")
	}
	active := false
	defer os.Remove("/run/gateway-ready")
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-done:
			return errors.New("official client stopped")
		case <-time.After(time.Second):
		}
		// Fetch before evaluating identities. Failed reads replace the allowlist
		// with empty; never fall back to local rules or a last-known allow grant.
		if remote != nil {
			c.AllowedUsers = remote.users(ctx)
			if len(c.AllowedUsers) == 0 && len(sources) != 0 {
				sources = nil
				if err = apply(active); err != nil {
					return err
				}
			}
		}
		s, err = status()
		if err != nil || s.BackendState != "Running" {
			if active {
				return errors.New("client lost readiness; forwarding closed")
			}
			continue
		}
		var ip string
		pool := netip.MustParsePrefix(c.Pool)
		for _, v := range s.TailscaleIPs {
			a, e := netip.ParseAddr(v)
			if e == nil && a.Is4() {
				ip = v
			}
		}
		a, e := netip.ParseAddr(ip)
		if e != nil || !netip.MustParsePrefix("100.64.0.0/10").Contains(a) || (c.Role == "tailgate") != pool.Contains(a) {
			return errors.New("client IPv4 conflicts with configured separate pools")
		}
		if !active {
			sources, err = allowedSources(c, s, time.Now())
			if err != nil {
				return err
			}
			listen, upstream := c.TransitAddress+":5353", "100.100.100.100:53"
			if c.Role == "hosted" {
				listen, upstream = ip+":53", c.TransitPeer+":5353"
			}
			dns, err := startDNS(ctx, listen, upstream, c.Domain)
			if err != nil {
				return err
			}
			defer dns.Close()
			if err = apply(true); err != nil {
				return err
			}
			if err = os.WriteFile("/run/gateway-ready", []byte(ip+"\n"), 0600); err != nil {
				return err
			}
			fmt.Println("gateway ready: " + c.Role + " IPv4 route and restricted DNS")
			active = true
		} else {
			b, _ := os.ReadFile("/run/gateway-ready")
			if strings.TrimSpace(string(b)) != ip {
				return errors.New("client address changed; restart required")
			}
			next, e := allowedSources(c, s, time.Now())
			if e != nil {
				return e
			}
			if strings.Join(next, ",") != strings.Join(sources, ",") {
				sources = next
				if err = apply(true); err != nil {
					return err
				}
				fmt.Printf("bridge authorization refreshed: %d permitted source devices\n", len(sources))
			}
		}
	}
}

func main() {
	config := flag.String("config", "/config/gateway.json", "configuration file")
	check := flag.Bool("check", false, "validate configuration without changing state")
	flag.Parse()
	c, err := readConfig(*config)
	if err == nil && !*check {
		err = run(c)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
