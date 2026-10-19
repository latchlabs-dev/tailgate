package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// Each instance exclusively owns a disposable container network namespace.
// No keys are embedded in configuration. AuthKeyFile is an optional mounted secret.
type Config struct {
	Role           string        `json:"role"`
	Hostname       string        `json:"hostname"`
	LoginServer    string        `json:"login_server"`
	Pool           string        `json:"destination_pool"`
	Domain         string        `json:"dns_domain"`
	TransitAddress string        `json:"transit_address"`
	TransitPeer    string        `json:"transit_peer"`
	AuthKeyFile    string        `json:"auth_key_file,omitempty"`
	AllowedUsers   []string      `json:"allowed_users,omitempty"`
	ConfigService  *configSource `json:"config_service,omitempty"`
}

var label = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func readConfig(path string) (Config, error) {
	var c Config
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 16385))
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return c, err
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return c, errors.New("trailing configuration")
	}
	return c, c.validate()
}

func (c Config) validate() error {
	if c.Role != "hosted" && c.Role != "tailgate" {
		return errors.New("role must be hosted or tailgate")
	}
	if c.ConfigService != nil {
		if c.Role != "hosted" || len(c.AllowedUsers) != 0 {
			return errors.New("remote rules require hosted role and no local allowed_users")
		}
		if err := c.ConfigService.validate(); err != nil {
			return err
		}
	}
	if len(c.AllowedUsers) > 256 || (c.Role != "hosted" && len(c.AllowedUsers) != 0) {
		return errors.New("allowed_users is limited to 256 hosted user accounts")
	}
	seen := map[string]bool{}
	for _, user := range c.AllowedUsers {
		if !validLogin(user) || seen[user] {
			return errors.New("allowed_users requires unique lowercase account emails; no groups, wildcards or tags")
		}
		seen[user] = true
	}
	if !label.MatchString(c.Hostname) {
		return errors.New("invalid hostname")
	}
	u, err := url.Parse(c.LoginServer)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("login_server must be an HTTPS origin")
	}
	p, err := netip.ParsePrefix(c.Pool)
	cgnat := netip.MustParsePrefix("100.64.0.0/10")
	if err != nil || !p.Addr().Is4() || p != p.Masked() || p.Bits() < 16 || p.Bits() > 24 || !cgnat.Contains(p.Addr()) {
		return errors.New("destination_pool must be a canonical CGNAT IPv4 /16 through /24")
	}
	for _, reserved := range []string{"100.100.0.0/24", "100.100.100.0/24", "100.115.92.0/23"} {
		if p.Overlaps(netip.MustParsePrefix(reserved)) {
			return errors.New("destination pool overlaps reserved client addresses")
		}
	}
	a, e1 := netip.ParseAddr(c.TransitAddress)
	b, e2 := netip.ParseAddr(c.TransitPeer)
	if e1 != nil || e2 != nil || !a.Is4() || !b.Is4() || !a.IsPrivate() || !b.IsPrivate() || a == b || netip.PrefixFrom(a, 29).Masked() != netip.PrefixFrom(b, 29).Masked() {
		return errors.New("transit addresses must be distinct private IPv4 addresses in the same /29")
	}
	for _, ip := range []netip.Addr{a, b} {
		v := ip.As4()[3] & 7
		if v == 0 || v == 7 {
			return errors.New("transit address is a network or broadcast address")
		}
	}
	if c.Domain != strings.ToLower(c.Domain) || len(c.Domain) > 253 || len(strings.Split(c.Domain, ".")) < 2 {
		return errors.New("invalid DNS domain")
	}
	for _, part := range strings.Split(c.Domain, ".") {
		if !label.MatchString(part) {
			return errors.New("invalid DNS domain")
		}
	}
	if c.AuthKeyFile != "" && c.AuthKeyFile != "/secrets/auth-key" {
		return errors.New("auth_key_file must be /secrets/auth-key")
	}
	return nil
}
