package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// The console and gateway readers share this durable, revisioned config service.
// Reader credentials are scoped to one gateway and never authorize panel writes.
type bridgeRule struct {
	Enabled      bool     `json:"enabled"`
	AllowedUsers []string `json:"allowed_users"`
}
type bridgeAudit struct {
	At       string     `json:"at"`
	Actor    string     `json:"actor"`
	Gateway  string     `json:"gateway"`
	Revision uint64     `json:"revision"`
	Rule     bridgeRule `json:"rule"`
}
type bridgeState struct {
	Version  int                   `json:"version"`
	Revision uint64                `json:"revision"`
	Gateways map[string]bridgeRule `json:"gateways"`
	Audit    []bridgeAudit         `json:"audit"`
}
type bridgeService struct {
	mu      sync.Mutex
	store   *privateState
	tokens  map[string][32]byte
	state   bridgeState
	blocked bool
}

var bridgeID = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
var bridgeLocal = regexp.MustCompile(`^[a-z0-9._+-]{1,64}$`)
var bridgeLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func validateBridgeRule(rule bridgeRule) error {
	if len(rule.AllowedUsers) > 256 {
		return errors.New("at most 256 accounts are supported")
	}
	seen := map[string]bool{}
	for _, u := range rule.AllowedUsers {
		parts := strings.Split(u, "@")
		if len(u) > 254 || len(parts) != 2 || !bridgeLocal.MatchString(parts[0]) || !strings.Contains(parts[1], ".") || seen[u] {
			return errors.New("use unique lowercase account emails, without groups or wildcards")
		}
		for _, label := range strings.Split(parts[1], ".") {
			if !bridgeLabel.MatchString(label) {
				return errors.New("invalid account domain")
			}
		}
		seen[u] = true
	}
	return nil
}
func emptyBridgeState(ids []string) bridgeState {
	s := bridgeState{Version: 1, Revision: 1, Gateways: map[string]bridgeRule{}, Audit: []bridgeAudit{}}
	for _, id := range ids {
		s.Gateways[id] = bridgeRule{AllowedUsers: []string{}}
	}
	return s
}
func loadBridgeService(path string) (*bridgeService, error) {
	var config struct {
		StatePath string `json:"state_path"`
		Gateways  []struct {
			ID        string `json:"id"`
			TokenFile string `json:"token_file"`
		} `json:"gateways"`
	}
	info, err := os.Lstat(path)
	if err != nil || !trustedWorkloadConfig(info) {
		return nil, errors.New("configuration registry must be private and trusted")
	}
	b, err := readBounded(path)
	if err != nil || uniqueJSON(b) != nil {
		return nil, errors.New("invalid configuration registry")
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if d.Decode(&config) != nil || d.Decode(&struct{}{}) != io.EOF || len(config.Gateways) == 0 || len(config.Gateways) > 64 {
		return nil, errors.New("invalid configuration registry")
	}
	svc := &bridgeService{tokens: map[string][32]byte{}}
	var ids []string
	for _, g := range config.Gateways {
		if !bridgeID.MatchString(g.ID) {
			return nil, errors.New("invalid gateway ID")
		}
		if _, ok := svc.tokens[g.ID]; ok {
			return nil, errors.New("duplicate gateway ID")
		}
		token, err := secret(g.TokenFile, 32)
		if err != nil {
			return nil, err
		}
		hash := sha256.Sum256([]byte(token))
		for _, existing := range svc.tokens {
			if hash == existing {
				return nil, errors.New("gateway reader credentials must be unique")
			}
		}
		svc.tokens[g.ID] = hash
		ids = append(ids, g.ID)
	}
	svc.store, err = openPrivateState(config.StatePath)
	if err != nil {
		return nil, err
	}
	ok, err := svc.store.read(&svc.state)
	if err == nil && !ok {
		svc.state = emptyBridgeState(ids)
		err = svc.store.write(svc.state)
	}
	if err == nil {
		if svc.state.Version != 1 || svc.state.Revision == 0 || len(svc.state.Gateways) != len(ids) || len(svc.state.Audit) > 512 {
			err = errors.New("invalid configuration state")
		}
		for _, id := range ids {
			rule, ok := svc.state.Gateways[id]
			if !ok || validateBridgeRule(rule) != nil {
				err = errors.New("gateway registry and state differ or contain invalid rules")
			}
		}
	}
	if err != nil {
		svc.store.close()
		return nil, err
	}
	return svc, nil
}
func (a *app) gatewayConfig(w http.ResponseWriter, r *http.Request) {
	svc := a.bridge
	if svc == nil || a.o.demo || r.Method != "GET" {
		fail(w, 404, "Configuration unavailable")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/gateway-config/v1/")
	expected, ok := svc.tokens[id]
	provided := sha256.Sum256([]byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")))
	if !ok || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || subtle.ConstantTimeCompare(expected[:], provided[:]) != 1 {
		fail(w, 401, "Invalid gateway credential")
		return
	}
	svc.mu.Lock()
	defer svc.mu.Unlock()
	if svc.blocked {
		fail(w, 503, "Configuration unavailable")
		return
	}
	rule := svc.state.Gateways[id]
	respond(w, 200, struct {
		Version  int    `json:"version"`
		Gateway  string `json:"gateway"`
		Revision uint64 `json:"revision"`
		bridgeRule
	}{1, id, svc.state.Revision, rule})
}
func (a *app) bridgeConfig(w http.ResponseWriter, r *http.Request, s session) {
	svc := a.bridge
	if svc == nil {
		fail(w, 503, "Configuration service has not been installed")
		return
	}
	svc.mu.Lock()
	defer svc.mu.Unlock()
	if svc.blocked {
		fail(w, 503, "Configuration storage needs operator recovery; bridge reads are closed")
		return
	}
	writes := a.o.configWrites || a.o.demo
	if r.Method == "GET" {
		respond(w, 200, struct {
			bridgeState
			Writes bool `json:"writes"`
		}{svc.state, writes})
		return
	}
	if !writes {
		fail(w, 403, "Access changes are disabled")
		return
	}
	var req struct {
		ID       string `json:"id"`
		Revision uint64 `json:"revision"`
		bridgeRule
	}
	if !body(w, r, &req) {
		return
	}
	if _, ok := svc.state.Gateways[req.ID]; !ok {
		fail(w, 400, "Unknown gateway")
		return
	}
	if err := validateBridgeRule(req.bridgeRule); err != nil {
		fail(w, 400, err.Error())
		return
	}
	if req.Revision != svc.state.Revision {
		fail(w, 409, "Configuration changed; reload before saving")
		return
	}
	if req.Revision == ^uint64(0) {
		fail(w, 409, "Revision exhausted")
		return
	}
	// Copy before writing: readers must never observe a non-durable approval.
	b, _ := json.Marshal(svc.state)
	var next bridgeState
	_ = json.Unmarshal(b, &next)
	if req.AllowedUsers == nil {
		req.AllowedUsers = []string{}
	}
	sort.Strings(req.AllowedUsers)
	next.Revision++
	next.Gateways[req.ID] = req.bridgeRule
	actor := s.email
	if actor == "" {
		actor = "token-administrator"
		if a.o.demo {
			actor = "preview-administrator"
		}
	}
	next.Audit = append(next.Audit, bridgeAudit{time.Now().UTC().Format(time.RFC3339), actor, req.ID, next.Revision, req.bridgeRule})
	if len(next.Audit) > 512 {
		next.Audit = next.Audit[len(next.Audit)-512:]
	}
	// Retain recent audit entries within the same bounded durable-state budget.
	// Large valid rosters must not eventually close the service as audit grows.
	for {
		encoded, _ := json.MarshalIndent(next, "", "  ")
		if len(encoded) <= maxResponse {
			break
		}
		if len(next.Audit) <= 1 {
			fail(w, 400, "Configuration exceeds its storage limit")
			return
		}
		next.Audit = next.Audit[len(next.Audit)/2:]
	}
	if svc.store != nil {
		if err := svc.store.write(next); err != nil {
			svc.blocked = true
			fail(w, 503, "Configuration storage failed; bridge reads are closed")
			return
		}
	}
	svc.state = next
	respond(w, 200, map[string]any{"revision": next.Revision, "saved": true})
}

func (a *app) bridgeSnapshot() json.RawMessage {
	if a.bridge == nil {
		return json.RawMessage(`{"error":"Configuration service has not been installed"}`)
	}
	a.bridge.mu.Lock()
	defer a.bridge.mu.Unlock()
	if a.bridge.blocked {
		return json.RawMessage(`{"error":"Configuration storage needs operator recovery; bridge reads are closed"}`)
	}
	b, _ := json.Marshal(struct {
		bridgeState
		Writes bool `json:"writes"`
	}{a.bridge.state, a.o.configWrites || a.o.demo})
	return b
}
