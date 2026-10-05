// Package audit is the only way to write the audit log (CLAUDE.md rule 2).
// Callers write the entry in the same transaction as the change it records.
package audit

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"

	"github.com/google/uuid"

	"github.com/Soup9x/Lake-Effect-Buoy/internal/server/store"
)

// Action is a closed set of audited actions.
type Action string

const (
	LoginSuccess   Action = "auth.login"
	LoginFailed    Action = "auth.login_failed"
	LoginLocked    Action = "auth.lockout"
	Logout         Action = "auth.logout"
	PasswordChange Action = "auth.password_change"
	SessionExpired Action = "auth.session_expired"

	UserCreate  Action = "user.create"
	UserDisable Action = "user.disable"

	TenantCreate  Action = "tenant.create"
	TenantUpdate  Action = "tenant.update"
	TenantArchive Action = "tenant.archive"

	TokenCreate Action = "enrollment_token.create"
	TokenRevoke Action = "enrollment_token.revoke"

	AgentEnroll         Action = "agent.enroll"
	AgentEnrollRejected Action = "agent.enroll_rejected"
	AgentRevoke         Action = "agent.revoke"
	AgentRotateRequest  Action = "agent.rotate_requested"
	AgentRotate         Action = "agent.credential_rotated"

	// Allowlisted agent actions queued from the console (CLAUDE.md rule 1).
	ActionQueue  Action = "agent_action.queue"
	ActionCancel Action = "agent_action.cancel"

	// AccessDenied records an authenticated request that failed authorization
	// (CSRF failure, insufficient auth level, IP not allowed).
	AccessDenied Action = "access.denied"
)

type Outcome string

const (
	Success Outcome = "success"
	Denied  Outcome = "denied"
	Error   Outcome = "error"
)

type ActorType string

const (
	ActorUser      ActorType = "user"
	ActorSystem    ActorType = "system"
	ActorAgent     ActorType = "agent"
	ActorToken     ActorType = "enrollment_token"
	ActorAnonymous ActorType = "anonymous"
)

type Actor struct {
	Type  ActorType
	ID    *uuid.UUID
	Label string
}

// Request carries the HTTP context of an audited action.
type Request struct {
	IP        *netip.Addr
	UserAgent string
	RequestID string
}

type Entry struct {
	Actor      Actor
	Request    Request
	TenantID   *uuid.UUID
	Action     Action
	TargetType string
	TargetID   string
	Outcome    Outcome
	Details    map[string]any
}

// forbiddenKeys must never appear in details. Write drops them rather than
// risk persisting a secret.
var forbiddenKeys = []string{"password", "token", "credential", "secret", "key", "cookie"}

func sanitize(d map[string]any) map[string]any {
	out := make(map[string]any, len(d))
	for k, v := range d {
		lk := strings.ToLower(k)
		bad := false
		for _, f := range forbiddenKeys {
			// token_prefix / token_id are identifiers, not secrets.
			if strings.Contains(lk, f) && lk != "token_prefix" && lk != "token_id" && lk != "token_label" {
				bad = true
				break
			}
		}
		if bad {
			out[k] = "[redacted]"
			continue
		}
		out[k] = v
	}
	return out
}

func Write(ctx context.Context, db store.DB, e Entry) error {
	if e.Outcome == "" {
		e.Outcome = Success
	}
	details, err := json.Marshal(sanitize(e.Details))
	if err != nil {
		return err
	}
	ua := e.Request.UserAgent
	if len(ua) > 500 {
		ua = ua[:500]
	}
	_, err = db.Exec(ctx, `INSERT INTO audit_log (actor_type, actor_id, actor_label, tenant_id, action, target_type, target_id, outcome, ip, user_agent, request_id, details)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		string(e.Actor.Type), e.Actor.ID, e.Actor.Label, e.TenantID, string(e.Action), e.TargetType, e.TargetID, string(e.Outcome),
		e.Request.IP, ua, e.Request.RequestID, details)
	return err
}
