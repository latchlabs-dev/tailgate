package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode"
)

// Company admission starts an exact-identity automatic device workflow.
// Request ownership always comes from the verified Google subject in the session.
type companyRequest struct {
	ID         string         `json:"id"`
	Subject    string         `json:"subject"`
	Email      string         `json:"email"`
	Reason     string         `json:"reason"`
	Status     string         `json:"status"`
	CreatedAt  string         `json:"created_at"`
	ReviewedAt string         `json:"reviewed_at,omitempty"`
	Reviewer   string         `json:"reviewer,omitempty"`
	Note       string         `json:"note,omitempty"`
	AutoAccess *companyAccess `json:"auto_access,omitempty"`
}

// An administrator selects one exact already-approved service for devices
// enrolled by this request's verified Google subject.
type companyAccess struct {
	Service       string `json:"service"`
	DestinationID string `json:"destination_id"`
	Port          string `json:"port"`
}

func validCompanyAccess(access *companyAccess) bool {
	if access == nil {
		return true
	}
	if strings.TrimSpace(access.Service) == "" || !requestText(access.Service, 64) || !idPattern.MatchString(access.DestinationID) {
		return false
	}
	m := exactPort.FindStringSubmatch(access.Port)
	if len(m) != 3 {
		return false
	}
	var port int
	_, _ = fmt.Sscanf(m[2], "%d", &port)
	return port <= 65535
}

func requestText(value string, limit int) bool {
	return len(value) <= limit && !strings.ContainsFunc(value, func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\t' })
}
func validateCompanyRequests(requests []companyRequest) error {
	seen := map[string]bool{}
	for _, r := range requests {
		_, err := time.Parse(time.RFC3339, r.CreatedAt)
		if len(r.ID) != 43 || seen[r.ID] || !googleMemberSubject.MatchString(r.Subject) || !strings.Contains(r.Email, "@") || strings.TrimSpace(r.Reason) == "" || !requestText(r.Reason, 1000) || !requestText(r.Note, 1000) || !validCompanyAccess(r.AutoAccess) || (r.Status != "approved" && r.AutoAccess != nil) || err != nil || (r.Status != "pending" && r.Status != "approved" && r.Status != "rejected" && r.Status != "revoked") {
			return errors.New("invalid company request ledger")
		}
		seen[r.ID] = true
	}
	return nil
}

func (w *workflow) saveCompanyRequests(requests []companyRequest, who, action, id string) error {
	// Work on a detached ledger; a failed durable write cannot publish an in-memory approval.
	b, err := json.Marshal(w.state)
	var next workflowState
	if err != nil || json.Unmarshal(b, &next) != nil {
		return errors.New("request update unavailable")
	}
	next.Requests = requests
	for _, request := range requests {
		if request.ID != id {
			continue
		}
		uid := permissionIdentity("accounts.google.com/" + request.Subject)
		for i := range next.UserAccess {
			entry := &next.UserAccess[i]
			if request.Status == "revoked" {
				entry.Users = slices.DeleteFunc(entry.Users, func(value string) bool { return value == uid })
			}
			if action == "company-approved" && request.AutoAccess != nil && entry.Destination == request.AutoAccess.DestinationID && entry.Port == request.AutoAccess.Port && !slices.Contains(entry.Users, uid) {
				entry.Users = append(entry.Users, uid)
			}
		}
	}
	if digest(next.UserAccess) != digest(w.state.UserAccess) {
		next.Revision++
	}
	next.Audit = append(next.Audit, workflowAudit{At: time.Now().UTC().Format(time.RFC3339), Actor: who, Action: action, Proposal: id, Revision: next.Revision})
	if len(next.Audit) > 512 {
		next.Audit = next.Audit[len(next.Audit)-512:]
	}
	if err := w.store.write(next); err != nil {
		return err
	}
	w.state = next
	return nil
}

func (a *app) memberRequest(out http.ResponseWriter, r *http.Request, s session) {
	if a.workflow == nil || a.google == nil || s.subject == "" || !a.google.memberAllowed(s.email) {
		fail(out, 403, "Company sign-in required")
		return
	}
	w := a.workflow
	if r.Method == "GET" && r.URL.Path == "/api/member" {
		w.mu.Lock()
		mine := []companyRequest{}
		approved := false
		for _, entry := range w.state.Requests {
			if entry.Subject == s.subject {
				// Reviewer identities are for the administrator audit view only.
				entry.Subject, entry.Reviewer = "", ""
				if entry.AutoAccess != nil {
					entry.AutoAccess = &companyAccess{Service: entry.AutoAccess.Service}
				}
				mine = append(mine, entry)
				approved = approved || entry.Status == "approved"
			}
		}
		result := map[string]any{"email": s.email, "requests": mine, "approved": approved}
		if approved {
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			nodes, err := a.approvalInventory(ctx)
			cancel()
			if err == nil {
				type memberDevice struct {
					Name   string `json:"name"`
					Status string `json:"status"`
				}
				devices := []memberDevice{}
				for _, node := range nodes {
					mine := node.UserIdentity.Email == s.email && googleSubject(node.UserIdentity.ProviderID) == s.subject
					if receipt, ok := w.state.Receipts[node.ID]; ok {
						mine = receipt.Original.Email == s.email && googleSubject(receipt.ProviderID) == s.subject && receipt.Fingerprint == nodeFingerprint(node)
					}
					if !mine {
						continue
					}
					name := node.GivenName
					if name == "" {
						name = node.Name
					}
					status := "waiting"
					if slices.Contains(w.state.Plan.Devices, node.ID) {
						if ok, _ := w.eligible(node); ok {
							status = "approved"
						}
					}
					devices = append(devices, memberDevice{Name: name, Status: status})
				}
				result["devices"] = devices
				result["devicesAvailable"] = true
			} else {
				result["devicesAvailable"] = false
			}
			settings, _, available := a.config()
			if available {
				result["controlURL"] = settings.ControlURL
			}
		}
		w.mu.Unlock()
		respond(out, 200, result)
		return
	}
	if r.Method != "POST" || r.URL.Path != "/api/member/request" {
		fail(out, 404, "Unknown request action")
		return
	}
	if !a.o.accessWrites {
		fail(out, 403, "Requests are temporarily unavailable")
		return
	}
	var in struct {
		Reason string `json:"reason"`
	}
	if !body(out, r, &in) {
		return
	}
	in.Reason = strings.TrimSpace(in.Reason)
	if in.Reason == "" || !requestText(in.Reason, 1000) {
		fail(out, 400, "Describe the access you need in up to 1,000 characters")
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	count := 0
	for _, entry := range w.state.Requests {
		if entry.Subject == s.subject {
			count++
			if entry.Status == "pending" || entry.Status == "approved" {
				respond(out, 200, map[string]string{"id": entry.ID, "status": entry.Status})
				return
			}
		}
	}
	if count >= 8 || len(w.state.Requests) >= 512 {
		fail(out, 429, "Request limit reached; contact your company administrator")
		return
	}
	entry := companyRequest{ID: randomToken(), Subject: s.subject, Email: s.email, Reason: in.Reason, Status: "pending", CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	next := append(append([]companyRequest{}, w.state.Requests...), entry)
	if err := w.saveCompanyRequests(next, s.email, "company-requested", entry.ID); err != nil {
		fail(out, 503, "Your request could not be saved; try again")
		return
	}
	respond(out, 201, map[string]string{"id": entry.ID, "status": entry.Status})
}

func (a *app) reviewRequest(out http.ResponseWriter, r *http.Request, s session) {
	if r.Method != "POST" || a.workflow == nil || !a.o.accessWrites || s.member {
		fail(out, 403, "Administrator review required")
		return
	}
	var in struct {
		ID         string         `json:"id"`
		Decision   string         `json:"decision"`
		Note       string         `json:"note"`
		AutoAccess *companyAccess `json:"auto_access"`
	}
	if !body(out, r, &in) {
		return
	}
	in.Note = strings.TrimSpace(in.Note)
	if (in.Decision != "approved" && in.Decision != "rejected" && in.Decision != "revoked") || !requestText(in.Note, 1000) || !validCompanyAccess(in.AutoAccess) || (in.Decision != "approved" && in.AutoAccess != nil) {
		fail(out, 400, "Choose approve, reject or revoke; use a note of up to 1,000 characters")
		return
	}
	w := a.workflow
	w.mu.Lock()
	defer w.mu.Unlock()
	next := append([]companyRequest{}, w.state.Requests...)
	for i, entry := range next {
		if entry.ID != in.ID {
			continue
		}
		if (in.Decision == "revoked" && entry.Status != "approved") || (in.Decision != "revoked" && entry.Status != "pending") {
			fail(out, 409, "This request has already been reviewed")
			return
		}
		if in.AutoAccess != nil && (!slices.Contains(w.state.Plan.Devices, in.AutoAccess.DestinationID) || w.state.Receipts[in.AutoAccess.DestinationID].ID != in.AutoAccess.DestinationID) {
			fail(out, 409, "Select a currently approved service device")
			return
		}
		next[i].Status, next[i].Note = in.Decision, in.Note
		next[i].AutoAccess = in.AutoAccess
		next[i].Reviewer, next[i].ReviewedAt = actor(s), time.Now().UTC().Format(time.RFC3339)
		if err := w.saveCompanyRequests(next, actor(s), "company-"+in.Decision, entry.ID); err != nil {
			fail(out, 503, "The decision could not be saved; try again")
			return
		}
		if in.Decision == "revoked" {
			ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
			defer cancel()
			for _, id := range append([]string{}, w.state.Plan.Devices...) {
				receipt, ok := w.state.Receipts[id]
				if !ok || receipt.Original.Email != entry.Email || googleSubject(receipt.ProviderID) != entry.Subject {
					continue
				}
				if err := a.withdrawDeviceLocked(ctx, id, actor(s)); err != nil {
					_ = a.blockWorkflow("Company access revocation could not be completed")
					fail(out, 503, "Company access was withdrawn; device enforcement needs administrator reconciliation")
					return
				}
			}
		}
		respond(out, 200, map[string]bool{"ok": true})
		return
	}
	fail(out, 404, "Request not found")
}
