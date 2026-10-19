package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

// Every selector is an administrator-owned, unclaimable node tag. Never compile
// email/IP selectors: Headscale can reuse addresses after a node is deleted.
type accessTeam struct {
	Name    string   `json:"name"`
	Devices []string `json:"device_ids"`
}
type accessGrant struct {
	Team         string   `json:"team"`
	Destinations []string `json:"destination_ids"`
	Ports        []string `json:"ports"`
}
type accessPlan struct {
	Devices []string      `json:"device_ids"`
	Teams   []accessTeam  `json:"teams"`
	Grants  []accessGrant `json:"grants"`
}
type approvalNode struct {
	node
	MachineKey   string `json:"machineKey"`
	UserIdentity struct {
		user
		ProviderID string `json:"providerId"`
	} `json:"user"`
}
type deviceReceipt struct {
	ID            string `json:"id"`
	Fingerprint   string `json:"fingerprint"`
	Tag           string `json:"tag"`
	Original      user   `json:"original"`
	ProviderID    string `json:"provider_id"`
	Expiry        string `json:"expiry"`
	ApprovedAt    string `json:"approved_at"`
	Workload      bool   `json:"workload,omitempty"`
	EnrollmentTag string `json:"enrollment_tag,omitempty"`
}

// Workload admission is an operator-installed, exact-key pin, never a tag-wide grant.
type workloadPin struct {
	ID          string `json:"id"`
	Fingerprint string `json:"fingerprint"`
	Tag         string `json:"tag"`
	Expiry      string `json:"expiry"`
}
type accessProposal struct {
	UserAccess []userServiceAccess `json:"user_access,omitempty"`
	ID         string              `json:"id"`
	Revision   uint64              `json:"revision"`
	Inventory  string              `json:"inventory"`
	Plan       accessPlan          `json:"plan"`
	Comment    string              `json:"comment"`
	Status     string              `json:"status"`
	CreatedAt  string              `json:"created_at"`
	Actor      string              `json:"actor"`
}
type workflowAudit struct {
	At       string `json:"at"`
	Actor    string `json:"actor"`
	Action   string `json:"action"`
	Proposal string `json:"proposal,omitempty"`
	Revision uint64 `json:"revision"`
}
type workflowState struct {
	UserAccess     []userServiceAccess      `json:"user_access,omitempty"`
	Services       []serviceDefinition      `json:"services,omitempty"`
	Version        int                      `json:"version"`
	Revision       uint64                   `json:"revision"`
	Plan           accessPlan               `json:"plan"`
	Receipts       map[string]deviceReceipt `json:"receipts"`
	Proposals      []accessProposal         `json:"proposals"`
	Audit          []workflowAudit          `json:"audit"`
	PolicyHash     string                   `json:"policy_hash"`
	Pending        string                   `json:"pending"`
	Blocked        string                   `json:"blocked"`
	DenialVerified bool                     `json:"denial_verified"`
	Requests       []companyRequest         `json:"requests,omitempty"`
	AutoExcluded   map[string]string        `json:"auto_excluded,omitempty"`
}
type workflow struct {
	mu        sync.Mutex
	store     *privateState
	domains   map[string]bool
	workloads map[string]workloadPin
	state     workflowState
}
type pendingDevice struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Eligible bool   `json:"eligible"`
	Reason   string `json:"reason"`
	Approved bool   `json:"approved"`
}
type workflowView struct {
	Users          []permissionUser    `json:"users"`
	ServiceAccess  []userServiceAccess `json:"service_access"`
	Services       []serviceDefinition `json:"services"`
	Revision       uint64              `json:"revision"`
	Inventory      string              `json:"inventory"`
	Writes         bool                `json:"writes"`
	Blocked        string              `json:"blocked"`
	DenialVerified bool                `json:"denial_verified"`
	Plan           accessPlan          `json:"plan"`
	Devices        []pendingDevice     `json:"devices"`
	Proposals      []accessProposal    `json:"proposals"`
	Audit          []workflowAudit     `json:"audit"`
	Owners         map[string]user     `json:"original_owners"`
	Requests       []companyRequest    `json:"requests"`
}
type compiledGrant struct {
	Src []string `json:"src"`
	Dst []string `json:"dst"`
	IP  []string `json:"ip"`
}
type compiledPolicy struct {
	TagOwners map[string][]string `json:"tagOwners"`
	Grants    []compiledGrant     `json:"grants"`
}

var teamName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
var exactPort = regexp.MustCompile(`^(tcp|udp):([1-9][0-9]{0,4})$`)
var googleMemberSubject = regexp.MustCompile(`^[A-Za-z0-9_-]{1,255}$`)
var approvalTag = regexp.MustCompile(`^tag:tailgate-[0-9a-f]{32}$`)
var workloadTag = regexp.MustCompile(`^tag:[a-z][a-z0-9-]{0,63}$`)
var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

func googleMemberIdentity(id string) bool {
	for _, prefix := range []string{"https://accounts.google.com/", "accounts.google.com/"} {
		if strings.HasPrefix(id, prefix) {
			return googleMemberSubject.MatchString(strings.TrimPrefix(id, prefix))
		}
	}
	return false
}

func loadWorkflow(path string) (*workflow, error) {
	b, err := readBounded(path)
	var c struct {
		StatePath string        `json:"state_path"`
		Domains   []string      `json:"allowed_domains"`
		Workloads []workloadPin `json:"workloads,omitempty"`
	}
	if err != nil || uniqueJSON(b) != nil {
		return nil, errors.New("invalid workflow configuration")
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || len(c.Domains) == 0 || len(c.Domains) > 16 {
		return nil, errors.New("invalid workflow configuration")
	}
	w := &workflow{domains: map[string]bool{}, workloads: map[string]workloadPin{}}
	if len(c.Workloads) > 512 {
		return nil, errors.New("too many workload pins")
	}
	if len(c.Workloads) > 0 {
		info, e := os.Lstat(path)
		if e != nil || !trustedWorkloadConfig(info) {
			return nil, errors.New("workload configuration must be private or root-owned and service-readable without group write access")
		}
	}
	for _, pin := range c.Workloads {
		_, expiryError := time.Parse(time.RFC3339Nano, pin.Expiry)
		// Expired pins must still load so the monitor can withdraw existing grants.
		if !idPattern.MatchString(pin.ID) || !sha256Hex.MatchString(pin.Fingerprint) || !workloadTag.MatchString(pin.Tag) || strings.HasPrefix(pin.Tag, "tag:tailgate-") || expiryError != nil || strings.HasPrefix(pin.Expiry, "0001-") {
			return nil, errors.New("invalid workload pin")
		}
		if _, exists := w.workloads[pin.ID]; exists {
			return nil, errors.New("duplicate workload pin")
		}
		w.workloads[pin.ID] = pin
	}
	for _, domain := range c.Domains {
		if domain != strings.ToLower(domain) || !strings.Contains(domain, ".") || strings.ContainsAny(domain, " /:@\r\n") {
			return nil, errors.New("invalid workflow domain")
		}
		w.domains[domain] = true
	}
	w.store, err = openPrivateState(c.StatePath)
	if err != nil {
		return nil, err
	}
	ok, err := w.store.read(&w.state)
	if err != nil {
		w.store.close()
		return nil, err
	}
	if !ok {
		w.state = workflowState{Version: 1, Receipts: map[string]deviceReceipt{}, Plan: emptyPlan()}
		if err = w.store.write(w.state); err != nil {
			w.store.close()
			return nil, err
		}
	}
	if w.state.Version != 1 || w.state.Receipts == nil || len(w.state.Receipts) > 512 || len(w.state.Proposals) > 128 || len(w.state.Audit) > 512 || len(w.state.Requests) > 512 || len(w.state.AutoExcluded) > 512 {
		w.store.close()
		return nil, errors.New("invalid approval ledger")
	}
	if err := validateUserAccess(w.state.UserAccess); err != nil {
		w.store.close()
		return nil, err
	}
	if err := validateServices(w.state.Services); err != nil {
		w.store.close()
		return nil, err
	}
	if err := validateCompanyRequests(w.state.Requests); err != nil {
		w.store.close()
		return nil, err
	}
	for id, fingerprint := range w.state.AutoExcluded {
		if !idPattern.MatchString(id) || !sha256Hex.MatchString(fingerprint) {
			w.store.close()
			return nil, errors.New("invalid automatic admission exclusion")
		}
	}
	for id, receipt := range w.state.Receipts {
		identityValid := googleMemberIdentity(receipt.ProviderID) && receipt.Original.Provider == "oidc" && receipt.Original.Email != "" && receipt.EnrollmentTag == ""
		if receipt.Workload {
			identityValid = receipt.ProviderID == "" && receipt.Original.Provider == "" && receipt.Original.Email == "" && workloadTag.MatchString(receipt.EnrollmentTag) && !strings.HasPrefix(receipt.EnrollmentTag, "tag:tailgate-")
		}
		if !idPattern.MatchString(id) || receipt.ID != id || !approvalTag.MatchString(receipt.Tag) || !sha256Hex.MatchString(receipt.Fingerprint) || !identityValid {
			w.store.close()
			return nil, errors.New("invalid original identity approval receipt")
		}
	}
	if w.state.PolicyHash != "" && !sha256Hex.MatchString(w.state.PolicyHash) {
		w.store.close()
		return nil, errors.New("invalid approval policy fingerprint")
	}
	if w.state.Pending != "" {
		w.state.Blocked = "An interrupted policy transition requires reconciliation"
	}
	return w, nil
}
func emptyPlan() accessPlan {
	return accessPlan{Devices: []string{}, Teams: []accessTeam{}, Grants: []accessGrant{}}
}
func digest(v any) string {
	b, _ := json.Marshal(v)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
func canonicalPolicy(raw string) (string, error) {
	var v any
	if uniqueJSON([]byte(raw)) != nil || json.Unmarshal([]byte(raw), &v) != nil {
		return "", errors.New("policy must be valid JSON")
	}
	return digest(v), nil
}
func nodeFingerprint(n approvalNode) string {
	return digest(struct{ ID, Key string }{n.ID, n.MachineKey})
}
func inventoryDigest(nodes []approvalNode) string {
	sorted := append([]approvalNode(nil), nodes...)
	slices.SortFunc(sorted, func(a, b approvalNode) int { return strings.Compare(a.ID, b.ID) })
	for i := range sorted {
		sorted[i].Online = false
		sorted[i].LastSeen = ""
	}
	return digest(sorted)
}
func (a *app) approvalInventory(ctx context.Context) ([]approvalNode, error) {
	var v struct {
		Nodes []approvalNode `json:"nodes"`
	}
	if err := a.upstreamContext(ctx, "GET", "/api/v1/node", nil, &v); err != nil {
		return nil, err
	}
	if len(v.Nodes) > 512 {
		return nil, errors.New("approval inventory exceeds 512 devices")
	}
	seen := map[string]bool{}
	for _, n := range v.Nodes {
		if !idPattern.MatchString(n.ID) || n.MachineKey == "" || seen[n.ID] {
			return nil, errors.New("authoritative device inventory is incomplete")
		}
		seen[n.ID] = true
	}
	return v.Nodes, nil
}
func expiredAt(value string) bool {
	if value == "" || strings.HasPrefix(value, "0001-") {
		return false
	}
	t, e := time.Parse(time.RFC3339Nano, value)
	return e != nil || !time.Now().Before(t)
}
func (w *workflow) eligible(n approvalNode) (bool, string) {
	if r, ok := w.state.Receipts[n.ID]; ok {
		if r.Workload {
			pin, exists := w.workloads[n.ID]
			if !exists || pin.Fingerprint != r.Fingerprint || pin.Tag != r.EnrollmentTag || pin.Expiry != r.Expiry || expiredAt(pin.Expiry) {
				return false, "Workload admission changed or expired"
			}
		}
		if r.Fingerprint != nodeFingerprint(n) || len(n.Tags) != 1 || n.Tags[0] != r.Tag {
			return false, "Device key or approval tag changed"
		}
		if expiredAt(r.Expiry) || expiredAt(n.Expiry) {
			return false, "Approval or device has expired; delete and re-enroll"
		}
		return true, ""
	}
	if len(n.Tags) > 0 {
		if pin, exists := w.workloads[n.ID]; exists && pin.Fingerprint == nodeFingerprint(n) && len(n.Tags) == 1 && n.Tags[0] == pin.Tag && !expiredAt(pin.Expiry) && !expiredAt(n.Expiry) && n.UserIdentity.Provider == "" && n.UserIdentity.Email == "" && n.UserIdentity.ProviderID == "" {
			return true, ""
		}
		return false, "Existing tagged devices require a separate administrator enrollment process"
	}
	if expiredAt(n.Expiry) {
		return false, "Device has expired"
	}
	u := n.UserIdentity
	parts := strings.Split(u.Email, "@")
	if len(parts) != 2 || u.Email != strings.ToLower(u.Email) || !w.domains[parts[1]] || u.Provider != "oidc" || !googleMemberIdentity(u.ProviderID) {
		return false, "Requires an allowed company Google identity"
	}
	return true, ""
}
func validatePlan(p *accessPlan, nodes []approvalNode, w *workflow) error {
	if len(p.Devices) > 512 || len(p.Teams) > 64 || len(p.Grants) > 128 {
		return errors.New("plan exceeds workflow limits")
	}
	if p.Devices == nil {
		p.Devices = []string{}
	}
	if p.Teams == nil {
		p.Teams = []accessTeam{}
	}
	if p.Grants == nil {
		p.Grants = []accessGrant{}
	}
	index := map[string]approvalNode{}
	tagNodes := map[string]string{}
	for _, n := range nodes {
		index[n.ID] = n
		for _, tag := range n.Tags {
			if strings.HasPrefix(tag, "tag:tailgate-") {
				if previous, exists := tagNodes[tag]; exists && previous != n.ID {
					return errors.New("an approval tag exists on multiple devices")
				}
				tagNodes[tag] = n.ID
			}
		}
	}
	for id, receipt := range w.state.Receipts {
		if holder, exists := tagNodes[receipt.Tag]; exists && holder != id {
			return errors.New("an approval tag was reassigned outside the workflow")
		}
	}
	approved := map[string]bool{}
	newDevices := 0
	for _, id := range p.Devices {
		n, ok := index[id]
		if !ok || approved[id] {
			return errors.New("device selection is missing or duplicated")
		}
		if ok, reason := w.eligible(n); !ok {
			return fmt.Errorf("device %s: %s", id, reason)
		}
		approved[id] = true
		if _, exists := w.state.Receipts[id]; !exists {
			newDevices++
		}
	}
	if newDevices > 16 {
		return errors.New("approve at most 16 new devices per proposal; retain existing selections and add the next batch")
	}
	if len(w.state.Receipts)+newDevices > 512 {
		return errors.New("historical approval ledger limit reached; deliberate archival is required")
	}
	slices.Sort(p.Devices)
	teams := map[string]bool{}
	for i, t := range p.Teams {
		if !teamName.MatchString(t.Name) || teams[t.Name] || len(t.Devices) == 0 {
			return errors.New("team names must be unique lowercase names with selected devices")
		}
		teams[t.Name] = true
		seen := map[string]bool{}
		for _, id := range t.Devices {
			if !approved[id] || seen[id] {
				return errors.New("team members must be distinct approved devices")
			}
			seen[id] = true
		}
		slices.Sort(p.Teams[i].Devices)
	}
	slices.SortFunc(p.Teams, func(a, b accessTeam) int { return strings.Compare(a.Name, b.Name) })
	for i, g := range p.Grants {
		if !teams[g.Team] || len(g.Destinations) == 0 || len(g.Ports) == 0 || len(g.Ports) > 32 {
			return errors.New("each grant requires a team, selected destinations and concrete ports")
		}
		seen := map[string]bool{}
		for _, id := range g.Destinations {
			if !approved[id] || seen[id] {
				return errors.New("destinations must be distinct approved devices")
			}
			seen[id] = true
		}
		seen = map[string]bool{}
		for _, port := range g.Ports {
			m := exactPort.FindStringSubmatch(port)
			var number int
			if len(m) != 3 {
				return errors.New("ports require tcp:443 or udp:53; ranges and wildcards are forbidden")
			}
			_, _ = fmt.Sscanf(m[2], "%d", &number)
			if number > 65535 || seen[port] {
				return errors.New("invalid or duplicated port")
			}
			seen[port] = true
		}
		slices.Sort(p.Grants[i].Destinations)
		slices.Sort(p.Grants[i].Ports)
	}
	slices.SortFunc(p.Grants, func(a, b accessGrant) int { return strings.Compare(digest(a), digest(b)) })
	return nil
}
func compileAccess(p accessPlan, receipts map[string]deviceReceipt) (string, error) {
	v := compiledPolicy{TagOwners: map[string][]string{}, Grants: []compiledGrant{}}
	for _, r := range receipts {
		v.TagOwners[r.Tag] = []string{}
	}
	teams := map[string][]string{}
	for _, t := range p.Teams {
		for _, id := range t.Devices {
			r, ok := receipts[id]
			if !ok {
				return "", errors.New("missing device approval receipt")
			}
			teams[t.Name] = append(teams[t.Name], r.Tag)
		}
	}
	for _, g := range p.Grants {
		rule := compiledGrant{Src: teams[g.Team], Dst: []string{}, IP: g.Ports}
		for _, id := range g.Destinations {
			r, ok := receipts[id]
			if !ok {
				return "", errors.New("missing destination approval receipt")
			}
			rule.Dst = append(rule.Dst, r.Tag)
		}
		slices.Sort(rule.Src)
		slices.Sort(rule.Dst)
		v.Grants = append(v.Grants, rule)
	}
	b, err := json.MarshalIndent(v, "", "  ")
	return string(b), err
}
func (w *workflow) record(actor, action, proposal string) {
	w.state.Audit = append(w.state.Audit, workflowAudit{At: time.Now().UTC().Format(time.RFC3339), Actor: actor, Action: action, Proposal: proposal, Revision: w.state.Revision})
	if len(w.state.Audit) > 512 {
		w.state.Audit = w.state.Audit[len(w.state.Audit)-512:]
	}
}
func actor(s session) string {
	if s.email != "" {
		return s.email + " [" + s.subject + "]"
	}
	return "private operator"
}
func (a *app) workflowSnapshot(ctx context.Context) (*workflowView, error) {
	w := a.workflow
	w.mu.Lock()
	defer w.mu.Unlock()
	nodes, err := a.approvalInventory(ctx)
	if err != nil {
		return nil, err
	}
	v := &workflowView{Users: w.permissionUsers(nodes), ServiceAccess: w.effectiveUserAccess(nodes), Services: serviceInventory(w.state), Revision: w.state.Revision, Inventory: inventoryDigest(nodes), Writes: a.o.accessWrites, Blocked: w.state.Blocked, DenialVerified: w.state.DenialVerified, Plan: w.state.Plan, Devices: []pendingDevice{}, Proposals: append([]accessProposal{}, w.state.Proposals...), Audit: append([]workflowAudit{}, w.state.Audit...), Owners: map[string]user{}, Requests: append([]companyRequest{}, w.state.Requests...)}
	for _, n := range nodes {
		ok, reason := w.eligible(n)
		email := n.UserIdentity.Email
		if r, exists := w.state.Receipts[n.ID]; exists {
			email = r.Original.Email
			v.Owners[n.ID] = r.Original
		}
		name := n.GivenName
		if name == "" {
			name = n.Name
		}
		v.Devices = append(v.Devices, pendingDevice{ID: n.ID, Name: name, Email: email, Eligible: ok, Reason: reason, Approved: slices.Contains(w.state.Plan.Devices, n.ID)})
	}
	// HTTP encoding happens after this lock is released. Never expose mutable
	// ledger slices/maps to another request's concurrent state updates.
	b, err := json.Marshal(v)
	if err != nil {
		return nil, errors.New("workflow projection failed")
	}
	var detached workflowView
	if json.Unmarshal(b, &detached) != nil {
		return nil, errors.New("workflow projection failed")
	}
	return &detached, nil
}
func (a *app) currentPolicy(ctx context.Context) (string, error) {
	var v struct {
		Policy string `json:"policy"`
	}
	if err := a.upstreamContext(ctx, "GET", "/api/v1/policy", nil, &v); err != nil {
		return "", err
	}
	return v.Policy, nil
}
func (a *app) putPolicy(ctx context.Context, p string) error {
	if err := a.upstreamContext(ctx, "POST", "/api/v1/policy/check", map[string]string{"policy": p}, nil); err != nil {
		return err
	}
	if err := a.upstreamContext(ctx, "PUT", "/api/v1/policy", map[string]string{"policy": p}, nil); err != nil {
		return err
	}
	got, err := a.currentPolicy(ctx)
	if err != nil {
		return err
	}
	wantHash, _ := canonicalPolicy(p)
	gotHash, err := canonicalPolicy(got)
	if err != nil || wantHash != gotHash {
		return errors.New("policy readback did not match the approved policy")
	}
	return nil
}
func (a *app) policyGuard(ctx context.Context) error {
	w := a.workflow
	p, err := a.currentPolicy(ctx)
	if err != nil {
		return err
	}
	h, err := canonicalPolicy(p)
	if err != nil {
		return err
	}
	if w.state.PolicyHash != "" {
		if h != w.state.PolicyHash {
			return errors.New("policy changed outside the approval workflow")
		}
		return nil
	}
	var v compiledPolicy
	if json.Unmarshal([]byte(p), &v) != nil || v.Grants == nil || len(v.Grants) != 0 {
		return errors.New("workflow bootstrap requires an explicit deny-all policy")
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal([]byte(p), &fields)
	for k := range fields {
		if k != "grants" && k != "tagOwners" {
			return errors.New("workflow bootstrap rejects unmanaged policy features")
		}
	}
	if _, ok := fields["grants"]; !ok {
		return errors.New("workflow bootstrap requires an explicit empty grants list")
	}
	for _, owners := range v.TagOwners {
		if len(owners) != 0 {
			return errors.New("workflow bootstrap rejects assignable tags")
		}
	}
	return nil
}
func (a *app) blockWorkflow(reason string) error {
	w := a.workflow
	newFailure := w.state.Blocked != reason || w.state.DenialVerified || w.state.Pending != ""
	w.state.Blocked = reason
	w.state.DenialVerified = false
	w.state.Pending = ""
	if newFailure {
		w.record("system", "blocked", "")
	}
	persistErr := w.store.write(w.state)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p, _ := compileAccess(emptyPlan(), w.state.Receipts)
	if err := a.putPolicy(ctx, p); err != nil {
		return errors.New(reason + "; deny-all enforcement is unverified")
	}
	w.state.Plan = emptyPlan()
	w.state.DenialVerified = true
	w.state.PolicyHash, _ = canonicalPolicy(p)
	w.state.Revision++
	w.record("system", "deny-all verified", "")
	if err := w.store.write(w.state); err != nil || persistErr != nil {
		w.state.DenialVerified = false
		return errors.New(reason + "; deny-all verified but approval persistence requires repair")
	}
	return errors.New(reason + "; deny-all verified; reconcile before further access changes")
}
func (a *app) applyProposal(ctx context.Context, id, who string) error {
	w := a.workflow
	if w.state.Blocked != "" || w.state.Pending != "" {
		return errors.New("workflow is blocked; reconcile first")
	}
	index := -1
	for i, p := range w.state.Proposals {
		if p.ID == id && p.Status == "pending" {
			index = i
			break
		}
	}
	if index < 0 {
		return errors.New("pending proposal not found")
	}
	p := w.state.Proposals[index]
	if err := validateUserAccess(p.UserAccess); err != nil {
		return err
	}
	if p.Revision != w.state.Revision {
		return errors.New("proposal revision is stale")
	}
	nodes, err := a.approvalInventory(ctx)
	if err != nil {
		return err
	}
	if inventoryDigest(nodes) != p.Inventory {
		return errors.New("device inventory changed; create and review a fresh proposal")
	}
	if p.UserAccess == nil && len(w.state.UserAccess) > 0 {
		p.Plan = compileUserServices(p.Plan, w.state.UserAccess, nodes, w)
	}
	if err = validatePlan(&p.Plan, nodes, w); err != nil {
		return err
	}
	if err = a.policyGuard(ctx); err != nil {
		return err
	}
	for _, n := range nodes {
		if !slices.Contains(p.Plan.Devices, n.ID) {
			continue
		}
		if _, ok := w.state.Receipts[n.ID]; !ok {
			if len(w.state.Receipts) >= 512 {
				return errors.New("approval ledger device limit reached; deliberate archival is required")
			}
			b := make([]byte, 16)
			if _, err = rand.Read(b); err != nil {
				return err
			}
			expiry := n.Expiry
			if expiry == "" || strings.HasPrefix(expiry, "0001-") {
				expiry = time.Now().Add(90 * 24 * time.Hour).UTC().Format(time.RFC3339)
			}
			w.state.Receipts[n.ID] = deviceReceipt{ID: n.ID, Fingerprint: nodeFingerprint(n), Tag: "tag:tailgate-" + hex.EncodeToString(b), Original: n.UserIdentity.user, ProviderID: n.UserIdentity.ProviderID, Expiry: expiry, ApprovedAt: time.Now().UTC().Format(time.RFC3339)}
			if pin, ok := w.workloads[n.ID]; ok && len(n.Tags) == 1 {
				r := w.state.Receipts[n.ID]
				r.Workload = true
				r.EnrollmentTag = pin.Tag
				r.Expiry = pin.Expiry
				w.state.Receipts[n.ID] = r
			}
		}
	}
	w.state.Pending = p.ID
	w.record(who, "application started", p.ID)
	if err = w.store.write(w.state); err != nil {
		return err
	}
	stage, err := compileAccess(w.state.Plan, w.state.Receipts)
	if err == nil {
		err = a.putPolicy(ctx, stage)
	}
	if err == nil {
		for _, n := range nodes {
			if !slices.Contains(p.Plan.Devices, n.ID) {
				continue
			}
			r := w.state.Receipts[n.ID]
			if len(n.Tags) == 1 && n.Tags[0] == r.Tag {
				continue
			}
			if err = a.upstreamContext(ctx, "POST", "/api/v1/node/"+n.ID+"/tags", map[string][]string{"tags": {r.Tag}}, nil); err != nil {
				break
			}
		}
	}
	if err == nil {
		nodes, err = a.approvalInventory(ctx)
	}
	if err == nil {
		err = validatePlan(&p.Plan, nodes, w)
	}
	final := ""
	if err == nil {
		final, err = compileAccess(p.Plan, w.state.Receipts)
	}
	if err == nil {
		err = a.putPolicy(ctx, final)
	}
	if err != nil {
		w.state.Proposals[index].Status = "failed"
		return a.blockWorkflow("Policy application failed; review reconciliation and re-enrollment requirements")
	}
	w.state.Plan = p.Plan
	if p.UserAccess != nil {
		w.state.UserAccess = p.UserAccess
	}
	w.state.PolicyHash, _ = canonicalPolicy(final)
	w.state.Pending = ""
	w.state.DenialVerified = false
	w.state.Proposals[index].Status = "approved"
	w.state.Revision++
	w.record(who, "approved", p.ID)
	if err = w.store.write(w.state); err != nil {
		return a.blockWorkflow("Policy applied but durable approval receipt could not be confirmed")
	}
	return nil
}
func (a *app) workflowRequest(out http.ResponseWriter, r *http.Request, s session) {
	if a.workflow == nil {
		fail(out, 404, "Approval workflow is not configured")
		return
	}
	if r.Method == "GET" && r.URL.Path == "/api/workflow" {
		v, err := a.workflowSnapshot(r.Context())
		if err != nil {
			fail(out, 502, err.Error())
		} else {
			respond(out, 200, v)
		}
		return
	}
	if r.Method != "POST" || !a.o.accessWrites {
		fail(out, 403, "Access changes are disabled")
		return
	}
	var in struct {
		Destination string            `json:"destination_id"`
		Port        string            `json:"port"`
		UserIDs     []string          `json:"user_ids"`
		Service     serviceDefinition `json:"service"`
		Revision    uint64            `json:"revision"`
		Inventory   string            `json:"inventory"`
		Plan        accessPlan        `json:"plan"`
		Comment     string            `json:"comment"`
		ID          string            `json:"id"`
	}
	if !body(out, r, &in) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	w := a.workflow
	w.mu.Lock()
	defer w.mu.Unlock()
	var err error
	response := map[string]any{"ok": true}
	switch r.URL.Path {
	case "/api/workflow/service-save":
		err = a.saveService(ctx, in.Service, in.Revision, in.Inventory, actor(s))
	case "/api/workflow/propose", "/api/workflow/service-propose":
		var userAccess []userServiceAccess
		if r.URL.Path == "/api/workflow/service-propose" {
			in.Plan, userAccess, err = a.servicePermissionPlan(ctx, in.Destination, in.Port, in.UserIDs, in.Revision, in.Inventory)
			if err != nil {
				break
			}
		}
		if w.state.Blocked != "" {
			err = errors.New("workflow is blocked; reconcile first")
			break
		}
		var nodes []approvalNode
		nodes, err = a.approvalInventory(ctx)
		if err != nil {
			break
		}
		if in.Revision != w.state.Revision || in.Inventory != inventoryDigest(nodes) {
			err = errors.New("inventory or revision changed; refresh before proposing")
			break
		}
		if len(in.Comment) > 512 {
			err = errors.New("comment exceeds 512 characters")
			break
		}
		if userAccess == nil && len(w.state.UserAccess) > 0 {
			in.Plan = compileUserServices(in.Plan, w.state.UserAccess, nodes, w)
		}
		if err = validatePlan(&in.Plan, nodes, w); err != nil {
			break
		}
		if len(w.state.Proposals) >= 128 {
			pruned := []accessProposal{}
			for _, p := range w.state.Proposals {
				if p.Status == "pending" {
					pruned = append(pruned, p)
				}
			}
			w.state.Proposals = pruned
		}
		if len(w.state.Proposals) >= 128 {
			err = errors.New("pending proposal limit reached")
			break
		}
		id := randomToken()
		w.state.Proposals = append(w.state.Proposals, accessProposal{ID: id, Revision: w.state.Revision, Inventory: in.Inventory, Plan: in.Plan, UserAccess: userAccess, Comment: in.Comment, Status: "pending", CreatedAt: time.Now().UTC().Format(time.RFC3339), Actor: actor(s)})
		w.record(actor(s), "proposed", id)
		err = w.store.write(w.state)
		response["proposal_id"] = id
	case "/api/workflow/approve":
		err = a.applyProposal(ctx, in.ID, actor(s))
	case "/api/workflow/reject":
		found := false
		for i, p := range w.state.Proposals {
			if p.ID == in.ID && p.Status == "pending" {
				w.state.Proposals[i].Status = "rejected"
				w.record(actor(s), "rejected", in.ID)
				found = true
				break
			}
		}
		if !found {
			err = errors.New("pending proposal not found")
		} else {
			err = w.store.write(w.state)
		}
	case "/api/workflow/reconcile":
		err = a.reconcileWorkflow(ctx, true, actor(s))
	case "/api/workflow/revoke":
		err = a.withdrawDeviceLocked(ctx, in.ID, actor(s))
	default:
		fail(out, 404, "Unknown approval action")
		return
	}
	if err != nil {
		fail(out, 409, err.Error())
		return
	}
	respond(out, 200, response)
}
func withoutDevice(p accessPlan, id string) accessPlan {
	p.Devices = slices.DeleteFunc(append([]string{}, p.Devices...), func(x string) bool { return x == id })
	teams := []accessTeam{}
	for _, t := range p.Teams {
		t.Devices = slices.DeleteFunc(append([]string{}, t.Devices...), func(x string) bool { return x == id })
		if len(t.Devices) > 0 {
			teams = append(teams, t)
		}
	}
	p.Teams = teams
	grants := []accessGrant{}
	for _, g := range p.Grants {
		g.Destinations = slices.DeleteFunc(append([]string{}, g.Destinations...), func(x string) bool { return x == id })
		if len(g.Destinations) > 0 && slices.ContainsFunc(teams, func(t accessTeam) bool { return t.Name == g.Team }) {
			grants = append(grants, g)
		}
	}
	p.Grants = grants
	return p
}
func (a *app) withdrawDevice(ctx context.Context, id string) error {
	w := a.workflow
	w.mu.Lock()
	defer w.mu.Unlock()
	bounded, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	return a.withdrawDeviceLocked(bounded, id, "private administrator")
}
func (a *app) withdrawDeviceLocked(ctx context.Context, id, who string) error {
	w := a.workflow
	if !idPattern.MatchString(id) {
		return errors.New("invalid device")
	}
	if !slices.Contains(w.state.Plan.Devices, id) {
		return nil
	}
	if w.state.Blocked != "" {
		return errors.New("reconcile the blocked workflow before revoking")
	}
	if err := a.policyGuard(ctx); err != nil {
		return err
	}
	plan := withoutDevice(w.state.Plan, id)
	p, err := compileAccess(plan, w.state.Receipts)
	if err != nil {
		return err
	}
	w.state.Pending = "revoke:" + id
	w.record(who, "revocation started", id)
	if err = w.store.write(w.state); err != nil {
		return err
	}
	if err = a.putPolicy(ctx, p); err != nil {
		return a.blockWorkflow("Device revocation was uncertain")
	}
	w.state.Plan = plan
	w.state.PolicyHash, _ = canonicalPolicy(p)
	w.state.Pending = ""
	if receipt, ok := w.state.Receipts[id]; ok {
		if w.state.AutoExcluded == nil {
			w.state.AutoExcluded = map[string]string{}
		}
		w.state.AutoExcluded[id] = receipt.Fingerprint
	}
	w.state.Revision++
	w.record(who, "revoked", id)
	if err = w.store.write(w.state); err != nil {
		return a.blockWorkflow("Revocation persistence was uncertain")
	}
	return nil
}
func (a *app) reconcileWorkflow(ctx context.Context, explicit bool, who string) error {
	w := a.workflow
	if w.state.Blocked != "" || w.state.Pending != "" {
		if !explicit {
			if w.state.DenialVerified && w.state.Pending == "" {
				if err := a.policyGuard(ctx); err == nil {
					return nil
				}
			}
			reason := w.state.Blocked
			if reason == "" {
				reason = "Interrupted approval transition"
			}
			return a.blockWorkflow(reason)
		}
		p, _ := compileAccess(emptyPlan(), w.state.Receipts)
		if err := a.putPolicy(ctx, p); err != nil {
			return errors.New("deny-all reconciliation could not be verified")
		}
		w.state.Plan = emptyPlan()
		w.state.Pending = ""
		w.state.Blocked = ""
		w.state.DenialVerified = false
		w.state.PolicyHash, _ = canonicalPolicy(p)
		w.state.Revision++
		w.record(who, "reconciled deny-all", "")
		return w.store.write(w.state)
	}
	nodes, err := a.approvalInventory(ctx)
	if err != nil {
		return a.blockWorkflow("Authoritative inventory unavailable; access cannot be verified")
	}
	if err = a.policyGuard(ctx); err != nil {
		return a.blockWorkflow("Policy changed outside the approval workflow")
	}
	nodes, err = a.restoreReauthenticated(ctx, w.state.Plan, nodes, who)
	if err != nil {
		return a.blockWorkflow("Approved identity restoration failed; review required")
	}
	copyPlan := w.state.Plan
	if err = validatePlan(&copyPlan, nodes, w); err != nil {
		return a.blockWorkflow("Approved inventory changed or expired; access withdrawn")
	}
	return nil
}
func (a *app) workflowMonitor() {
	if !a.o.accessWrites {
		return
	}
	for {
		w := a.workflow
		w.mu.Lock()
		// Time spent waiting for an administrator transaction is not evidence
		// that Headscale is unavailable. Start the budget after owning the lock.
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		if a.reconcileWorkflow(ctx, false, "system") == nil {
			cancel()
			ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
			if err := a.admitApprovedCompanyDevices(ctx); err != nil {
				log.Printf("automatic company device admission: %v", err)
			}
		}
		w.mu.Unlock()
		cancel()
		time.Sleep(30 * time.Second)
	}
}

type operationsCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message"`
}
type operationsStatus struct {
	GeneratedAt string            `json:"generated_at"`
	Checks      []operationsCheck `json:"checks"`
}

func readOperations(path string) *operationsStatus {
	if path == "" {
		return nil
	}
	bad := &operationsStatus{Checks: []operationsCheck{{Name: "Operations projection", Status: "warning", Message: "Operational status is unavailable or invalid"}}}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return bad
	}
	b, err := readBounded(path)
	var status operationsStatus
	if err != nil || len(b) > 32768 || uniqueJSON(b) != nil || json.Unmarshal(b, &status) != nil || len(status.Checks) > 64 {
		return bad
	}
	t, err := time.Parse(time.RFC3339, status.GeneratedAt)
	if err != nil || t.After(time.Now().Add(time.Minute)) {
		return bad
	}
	for _, c := range status.Checks {
		if len(c.Name) == 0 || len(c.Name) > 100 || len(c.Message) > 512 || !slices.Contains([]string{"pass", "warning", "fail", "disabled"}, c.Status) || strings.ContainsAny(c.Name+c.Message, "\x00\r\n") {
			return bad
		}
	}
	if time.Since(t) > 5*time.Minute {
		status.Checks = append(status.Checks, operationsCheck{Name: "Status freshness", Status: "warning", Message: "Operational projection is older than five minutes"})
	}
	return &status
}
