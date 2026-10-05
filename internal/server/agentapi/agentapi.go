// Package agentapi implements the public /agent/v1 endpoints.
package agentapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Soup9x/Lake-Effect-Buoy/internal/protocol"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/server/audit"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/server/httpx"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/server/secret"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/server/store"
)

// RotationGrace is how long the previous credential stays valid after a rotation.
const RotationGrace = 10 * time.Minute

type API struct {
	DB         *pgxpool.Pool
	Hasher     *secret.Hasher
	Log        *slog.Logger
	enrollRate *httpx.RateLimiter
	agentRate  *httpx.RateLimiter
	now        func() time.Time
}

func New(db *pgxpool.Pool, h *secret.Hasher, log *slog.Logger) *API {
	return &API{
		DB: db, Hasher: h, Log: log,
		enrollRate: httpx.NewRateLimiter(10, 20),
		// Generous: many agents can sit behind one client NAT.
		agentRate: httpx.NewRateLimiter(6000, 6000),
		now:       time.Now,
	}
}

func (a *API) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST "+protocol.PathEnroll, a.enroll)
	mux.Handle("POST "+protocol.PathHeartbeat, a.authenticated(a.heartbeat))
	mux.Handle("POST "+protocol.PathRotate, a.authenticated(a.rotate))
	mux.Handle("POST "+protocol.PathActionResult, a.authenticated(a.actionResult))
}

// Actions handed out per heartbeat, and how long after any action activity
// the heartbeat stays short so follow-up actions are picked up quickly.
const (
	actionsPerHeartbeat = 10
	fastWindow          = 5 * time.Minute
	fastInterval        = 15 * time.Second
)

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	httpx.WriteJSON(w, status, protocol.ErrorResponse{Error: protocol.ErrorBody{Code: code, Message: msg}})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, protocol.MaxRequestBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, protocol.ErrInvalidRequest, "malformed JSON body")
		return false
	}
	return true
}

func auditReq(r *http.Request) audit.Request {
	return audit.Request{IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r)}
}

var errInvalidToken = errors.New("invalid token")
var errAlreadyEnrolled = errors.New("already enrolled")

func (a *API) enroll(w http.ResponseWriter, r *http.Request) {
	if !a.enrollRate.Allow(httpx.ClientIP(r)) {
		writeErr(w, http.StatusTooManyRequests, protocol.ErrRateLimited, "too many enrollment attempts")
		return
	}
	var req protocol.EnrollRequest
	if !decode(w, r, &req) {
		return
	}
	if err := validateEnroll(&req); err != nil {
		writeErr(w, http.StatusBadRequest, protocol.ErrInvalidRequest, err.Error())
		return
	}
	ctx := r.Context()
	agentID := store.NewID()
	credential := protocol.CredentialPrefix + agentID.String() + "." + secret.Random(32)
	var tenantName string
	var tok *store.EnrollmentToken
	replaced := false

	err := store.InTx(ctx, a.DB, func(tx pgx.Tx) error {
		var err error
		tok, err = store.LockEnrollmentTokenByHash(ctx, tx, a.Hasher.Hash(req.EnrollmentToken))
		if errors.Is(err, store.ErrNotFound) {
			// Accept tokens hashed under the previous key during a key rotation.
			if prev := a.Hasher.PreviousHash(req.EnrollmentToken); prev != nil {
				if tok, err = store.LockEnrollmentTokenByHash(ctx, tx, prev); err == nil {
					err = store.RehashEnrollmentToken(ctx, tx, tok.ID, a.Hasher.Hash(req.EnrollmentToken))
				}
			}
		}
		if errors.Is(err, store.ErrNotFound) {
			return errInvalidToken
		}
		if err != nil {
			return err
		}
		if !tok.Usable(a.now()) {
			return errInvalidToken
		}
		tenant, err := store.GetTenant(ctx, tx, tok.TenantID)
		if err != nil {
			return err
		}
		if tenant.ArchivedAt != nil {
			return errInvalidToken
		}
		tenantName = tenant.Name

		existing, err := store.ActiveAgentByMachine(ctx, tx, tenant.ID, req.MachineID)
		switch {
		case err == nil && !req.Replace:
			return errAlreadyEnrolled
		case err == nil:
			replaced = true
			if err := store.RevokeAgent(ctx, tx, existing.ID); err != nil {
				return err
			}
			if err := store.AddAgentEvent(ctx, tx, existing.ID, tenant.ID, "revoked", map[string]any{"reason": "replaced", "replaced_by": agentID}); err != nil {
				return err
			}
		case !errors.Is(err, store.ErrNotFound):
			return err
		}

		if err := store.CreateAgent(ctx, tx, store.NewAgent{
			ID: agentID, TenantID: tenant.ID, EnrolledVia: tok.ID, CredentialHash: a.Hasher.Hash(credential),
			MachineID: req.MachineID, Hostname: req.Hostname, OSFamily: req.OSFamily, OSName: req.OSName,
			OSVersion: req.OSVersion, Arch: req.Arch, AgentVersion: req.AgentVersion, IP: httpx.ClientIP(r),
		}); err != nil {
			return err
		}
		if err := store.IncrementTokenUse(ctx, tx, tok.ID); err != nil {
			return err
		}
		if err := store.AddAgentEvent(ctx, tx, agentID, tenant.ID, "enrolled", map[string]any{"hostname": req.Hostname, "token_id": tok.ID}); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{
			Actor:    audit.Actor{Type: audit.ActorToken, ID: &tok.ID, Label: fmt.Sprintf("token %s (%s)", tok.TokenPrefix, tok.Label)},
			Request:  auditReq(r),
			TenantID: &tenant.ID, Action: audit.AgentEnroll, TargetType: "agent", TargetID: agentID.String(),
			Details: map[string]any{"hostname": req.Hostname, "machine_id": req.MachineID, "os_family": req.OSFamily, "replaced": replaced},
		})
	})

	switch {
	case errors.Is(err, errInvalidToken):
		a.auditRejected(ctx, r, tok, req, "invalid_token")
		writeErr(w, http.StatusUnauthorized, protocol.ErrInvalidToken, "enrollment token is invalid, expired, revoked or used up")
	case errors.Is(err, errAlreadyEnrolled):
		a.auditRejected(ctx, r, tok, req, "already_enrolled")
		writeErr(w, http.StatusConflict, protocol.ErrAlreadyEnrolled, "this machine already has an active agent in this tenant; re-run with replace to re-enroll")
	case err != nil:
		a.Log.Error("enroll failed", "err", err, "request_id", httpx.RequestID(r))
		writeErr(w, http.StatusInternalServerError, protocol.ErrInternal, "internal error")
	default:
		a.Log.Info("agent enrolled", "agent_id", agentID, "tenant", tenantName, "hostname", req.Hostname)
		httpx.WriteJSON(w, http.StatusCreated, protocol.EnrollResponse{
			AgentID: agentID.String(), Credential: credential, TenantName: tenantName,
			HeartbeatIntervalSeconds: int(protocol.DefaultHeartbeatInterval.Seconds()),
		})
	}
}

// auditRejected records a failed enrollment outside the rolled-back transaction.
func (a *API) auditRejected(ctx context.Context, r *http.Request, tok *store.EnrollmentToken, req protocol.EnrollRequest, reason string) {
	e := audit.Entry{
		Actor:   audit.Actor{Type: audit.ActorAnonymous, Label: "unauthenticated enrollment"},
		Request: auditReq(r), Action: audit.AgentEnrollRejected, Outcome: audit.Denied, TargetType: "agent",
		Details: map[string]any{"reason": reason, "hostname": req.Hostname, "machine_id": req.MachineID},
	}
	if tok != nil {
		e.Actor = audit.Actor{Type: audit.ActorToken, ID: &tok.ID, Label: fmt.Sprintf("token %s (%s)", tok.TokenPrefix, tok.Label)}
		e.TenantID = &tok.TenantID
	}
	if err := audit.Write(ctx, a.DB, e); err != nil {
		a.Log.Error("audit write failed", "err", err)
	}
}

type ctxKey struct{}

// authedAgent is what authenticated stores in the request context.
type authedAgent struct {
	agent *store.Agent
	// heldHash is the current-key hash of the credential the agent presented.
	heldHash []byte
}

func authFrom(r *http.Request) authedAgent { return r.Context().Value(ctxKey{}).(authedAgent) }

func agentFrom(r *http.Request) *store.Agent { return authFrom(r).agent }

// authenticated verifies the agent credential. A revoked agent only learns it
// is revoked (agent_revoked) after proving it holds a valid credential.
func (a *API) authenticated(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.agentRate.Allow(httpx.ClientIP(r)) {
			writeErr(w, http.StatusTooManyRequests, protocol.ErrRateLimited, "rate limited")
			return
		}
		unauthorized := func() {
			writeErr(w, http.StatusUnauthorized, protocol.ErrUnauthorized, "invalid agent credential")
		}
		cred, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok {
			unauthorized()
			return
		}
		idPart, _, ok := strings.Cut(strings.TrimPrefix(cred, protocol.CredentialPrefix), ".")
		if !ok || !strings.HasPrefix(cred, protocol.CredentialPrefix) {
			unauthorized()
			return
		}
		id, err := uuid.Parse(idPart)
		if err != nil {
			unauthorized()
			return
		}
		ctx := r.Context()
		ag, err := store.GetAgent(ctx, a.DB, id)
		if errors.Is(err, store.ErrNotFound) {
			unauthorized()
			return
		}
		if err != nil {
			a.Log.Error("agent lookup failed", "err", err)
			writeErr(w, http.StatusInternalServerError, protocol.ErrInternal, "internal error")
			return
		}

		matched, stale := a.Hasher.Match(cred, ag.CredentialHash)
		usedPrev := false
		if !matched && ag.CredentialPrevHash != nil && ag.CredentialPrevExpiresAt != nil && a.now().Before(*ag.CredentialPrevExpiresAt) {
			matched, _ = a.Hasher.Match(cred, ag.CredentialPrevHash)
			usedPrev = matched
		}
		if !matched {
			unauthorized()
			return
		}
		if ag.RevokedAt != nil || ag.TenantArchivedAt != nil {
			writeErr(w, http.StatusUnauthorized, protocol.ErrAgentRevoked, "this agent has been revoked")
			return
		}
		if stale && !usedPrev {
			if err := store.RehashAgentCredential(ctx, a.DB, ag.ID, a.Hasher.Hash(cred)); err != nil {
				a.Log.Error("rehash credential failed", "err", err)
			}
		}
		if !usedPrev && ag.CredentialPrevHash != nil {
			// The agent has switched to its new credential; retire the old one.
			requested, err := store.ClearPreviousCredential(ctx, a.DB, ag.ID)
			if err != nil {
				a.Log.Error("clear previous credential failed", "err", err)
			} else {
				ag.CredentialPrevHash, ag.CredentialPrevExpiresAt, ag.RotateRequestedAt = nil, nil, requested
			}
		}
		next(w, r.WithContext(context.WithValue(ctx, ctxKey{}, authedAgent{agent: ag, heldHash: a.Hasher.Hash(cred)})))
	})
}

func (a *API) heartbeat(w http.ResponseWriter, r *http.Request) {
	ag := agentFrom(r)
	var req protocol.HeartbeatRequest
	if !decode(w, r, &req) {
		return
	}
	if err := validateHeartbeat(&req, a.now()); err != nil {
		writeErr(w, http.StatusBadRequest, protocol.ErrInvalidRequest, err.Error())
		return
	}
	upd := store.HeartbeatUpdate{
		Hostname: req.Hostname, OSName: req.OSName, OSVersion: req.OSVersion, AgentVersion: req.AgentVersion,
		ClamdStatus: req.ClamAV.Status, SignatureDate: req.ClamAV.SignatureDate, IP: httpx.ClientIP(r),
	}
	if v := req.ClamAV.EngineVersion; v != "" {
		upd.EngineVersion = &v
	}
	if v := req.ClamAV.SignatureVersion; v != 0 {
		upd.SignatureVersion = &v
	}
	if v := req.ClamAV.Error; v != "" {
		upd.ClamdError = &v
	}
	ctx := r.Context()
	var queued []store.QueuedAction
	active := false
	err := store.InTx(ctx, a.DB, func(tx pgx.Tx) error {
		if err := store.RecordHeartbeat(ctx, tx, ag.ID, upd); err != nil {
			return err
		}
		var err error
		if queued, err = store.TakeQueuedActions(ctx, tx, ag.ID, actionsPerHeartbeat); err != nil {
			return err
		}
		if active, err = store.AgentActionsActive(ctx, tx, ag.ID, fastWindow); err != nil {
			return err
		}
		if ag.LastHeartbeatAt != nil && ag.ClamdStatus != req.ClamAV.Status {
			if err := store.AddAgentEvent(ctx, tx, ag.ID, ag.TenantID, "clamd_status_changed",
				map[string]any{"from": ag.ClamdStatus, "to": req.ClamAV.Status, "error": req.ClamAV.Error}); err != nil {
				return err
			}
		}
		if ag.AgentVersion != req.AgentVersion {
			return store.AddAgentEvent(ctx, tx, ag.ID, ag.TenantID, "agent_version_changed",
				map[string]any{"from": ag.AgentVersion, "to": req.AgentVersion})
		}
		return nil
	})
	if err != nil {
		a.Log.Error("heartbeat failed", "err", err, "agent_id", ag.ID)
		writeErr(w, http.StatusInternalServerError, protocol.ErrInternal, "internal error")
		return
	}
	interval := protocol.DefaultHeartbeatInterval
	if active {
		interval = fastInterval
	}
	actions := make([]protocol.Action, 0, len(queued))
	for _, q := range queued {
		actions = append(actions, protocol.Action{ID: q.ID.String(), Type: protocol.ActionType(q.Type), Params: q.Params})
	}
	httpx.WriteJSON(w, http.StatusOK, protocol.HeartbeatResponse{
		HeartbeatIntervalSeconds: int(interval.Seconds()),
		ServerTime:               a.now().UTC(),
		RotateCredential:         ag.RotateRequestedAt != nil,
		Actions:                  actions,
	})
}

func (a *API) rotate(w http.ResponseWriter, r *http.Request) {
	authed := authFrom(r)
	ag := authed.agent
	ctx := r.Context()
	credential := protocol.CredentialPrefix + ag.ID.String() + "." + secret.Random(32)
	err := store.InTx(ctx, a.DB, func(tx pgx.Tx) error {
		// Keep the credential the agent actually holds valid. If it is still on
		// the previous one (an earlier rotate response was lost or not saved),
		// the unused credential from that attempt is discarded.
		if err := store.RotateCredential(ctx, tx, ag.ID, a.Hasher.Hash(credential), authed.heldHash, a.now().Add(RotationGrace)); err != nil {
			return err
		}
		if err := store.AddAgentEvent(ctx, tx, ag.ID, ag.TenantID, "credential_rotated", nil); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{
			Actor:   audit.Actor{Type: audit.ActorAgent, ID: &ag.ID, Label: ag.Hostname},
			Request: auditReq(r), TenantID: &ag.TenantID, Action: audit.AgentRotate, TargetType: "agent", TargetID: ag.ID.String(),
		})
	})
	if err != nil {
		a.Log.Error("rotate failed", "err", err, "agent_id", ag.ID)
		writeErr(w, http.StatusInternalServerError, protocol.ErrInternal, "internal error")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, protocol.RotateResponse{Credential: credential})
}

// actionResult stores an agent's result for an action that was sent to it.
// Everything in it is untrusted: it is validated against the action's type
// and stored for display (escaped) and export (formula-neutralised).
func (a *API) actionResult(w http.ResponseWriter, r *http.Request) {
	ag := agentFrom(r)
	var req protocol.ActionResult
	if !decode(w, r, &req) {
		return
	}
	id, err := uuid.Parse(req.ID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, protocol.ErrInvalidRequest, "id is not a valid action id")
		return
	}
	ctx := r.Context()
	typ, err := store.SentActionType(ctx, a.DB, ag.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusConflict, protocol.ErrInvalidRequest, "no such action awaiting a result from this agent")
		return
	}
	if err != nil {
		a.Log.Error("action lookup failed", "err", err, "agent_id", ag.ID)
		writeErr(w, http.StatusInternalServerError, protocol.ErrInternal, "internal error")
		return
	}
	upd, err := validateActionResult(protocol.ActionType(typ), &req, a.now())
	if err != nil {
		writeErr(w, http.StatusBadRequest, protocol.ErrInvalidRequest, err.Error())
		return
	}
	if err := store.RecordActionResult(ctx, a.DB, ag.ID, id, upd); errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusConflict, protocol.ErrInvalidRequest, "no such action awaiting a result from this agent")
		return
	} else if err != nil {
		a.Log.Error("store action result failed", "err", err, "agent_id", ag.ID)
		writeErr(w, http.StatusInternalServerError, protocol.ErrInternal, "internal error")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, struct{}{})
}
