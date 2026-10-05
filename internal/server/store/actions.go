package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Action statuses.
const (
	ActionQueued    = "queued"
	ActionSent      = "sent"
	ActionDone      = "done"
	ActionFailed    = "failed"
	ActionRejected  = "rejected"
	ActionExpired   = "expired"
	ActionCancelled = "cancelled"
)

// Action deadlines.
const (
	// ActionDeliverWithin: an action not picked up by then (agent offline)
	// expires.
	ActionDeliverWithin = 24 * time.Hour
	// ActionReportWithin / ScanReportWithin: a delivered action must report
	// back by then (an agent too old to know the action never does).
	ActionReportWithin = 10 * time.Minute
	ScanReportWithin   = 4*time.Hour + 15*time.Minute
)

// Job is one request from the console: an action for one or more endpoints.
type Job struct {
	ID           uuid.UUID
	TenantID     uuid.UUID
	TenantName   string
	Type         string
	Params       json.RawMessage
	CreatedBy    uuid.UUID
	CreatorEmail string
	CreatedAt    time.Time
	// Counts by status.
	Total, Open, Done, Failed int
}

// Finished reports whether every action in the job has a final status.
func (j Job) Finished() bool { return j.Open == 0 }

// AgentAction is one action for one endpoint.
type AgentAction struct {
	ID         uuid.UUID
	JobID      uuid.UUID
	AgentID    uuid.UUID
	TenantID   uuid.UUID
	Hostname   string
	TenantName string
	Type       string
	Params     json.RawMessage
	Status     string
	CreatedAt  time.Time
	SentAt     *time.Time
	StartedAt  *time.Time
	FinishedAt *time.Time
	ExpiresAt  time.Time
	Output     string
	Data       json.RawMessage
	Error      string
}

// Open reports whether the action has no final status yet.
func (a AgentAction) Open() bool { return a.Status == ActionQueued || a.Status == ActionSent }

// CreateJob queues an action for each of agentIDs that belongs to tenantID
// and is not revoked. Returns the job and how many actions were queued.
func CreateJob(ctx context.Context, db DB, tenantID uuid.UUID, typ string, params json.RawMessage, createdBy uuid.UUID, agentIDs []uuid.UUID) (uuid.UUID, int, error) {
	jobID := NewID()
	if _, err := db.Exec(ctx, `INSERT INTO action_jobs (id, tenant_id, type, params, created_by) VALUES ($1,$2,$3,$4,$5)`,
		jobID, tenantID, typ, params, createdBy); err != nil {
		return uuid.Nil, 0, err
	}
	ids := make([]uuid.UUID, 0, len(agentIDs))
	for range agentIDs {
		ids = append(ids, NewID())
	}
	tag, err := db.Exec(ctx, `INSERT INTO agent_actions (id, job_id, agent_id, tenant_id, type, params, expires_at)
		SELECT t.action_id, $1, a.id, a.tenant_id, $2, $3, now() + $4::interval
		FROM unnest($5::uuid[], $6::uuid[]) AS t(agent_id, action_id)
		JOIN agents a ON a.id = t.agent_id
		WHERE a.tenant_id = $7 AND a.revoked_at IS NULL`,
		jobID, typ, params, ActionDeliverWithin, agentIDs, ids, tenantID)
	if err != nil {
		return uuid.Nil, 0, err
	}
	return jobID, int(tag.RowsAffected()), nil
}

// QueuedAction is what the heartbeat hands to an agent.
type QueuedAction struct {
	ID     uuid.UUID
	Type   string
	Params json.RawMessage
}

// TakeQueuedActions marks up to limit queued actions of an agent as sent,
// oldest first, and returns them.
func TakeQueuedActions(ctx context.Context, db DB, agentID uuid.UUID, limit int) ([]QueuedAction, error) {
	rows, err := db.Query(ctx, `UPDATE agent_actions SET status = 'sent', sent_at = now(),
			expires_at = now() + CASE WHEN type = 'scan_path' THEN $3::interval ELSE $4::interval END
		WHERE id IN (SELECT id FROM agent_actions WHERE agent_id = $1 AND status = 'queued'
			ORDER BY created_at LIMIT $2 FOR UPDATE SKIP LOCKED)
		RETURNING id, type, params`, agentID, limit, ScanReportWithin, ActionReportWithin)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []QueuedAction
	for rows.Next() {
		var q QueuedAction
		if err := rows.Scan(&q.ID, &q.Type, &q.Params); err != nil {
			return nil, err
		}
		out = append(out, q)
	}
	return out, rows.Err()
}

// AgentActionsActive reports whether an agent has actions waiting or in
// flight, or finished one in the last few minutes; the heartbeat is
// shortened meanwhile so follow-up actions are picked up quickly.
func AgentActionsActive(ctx context.Context, db DB, agentID uuid.UUID, window time.Duration) (bool, error) {
	var active bool
	err := db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM agent_actions WHERE agent_id = $1
		AND (status IN ('queued', 'sent') OR created_at > now() - $2::interval OR finished_at > now() - $2::interval))`,
		agentID, window).Scan(&active)
	return active, err
}

// SentActionType returns the type of an action that was sent to agentID and
// has not reported yet, or ErrNotFound.
func SentActionType(ctx context.Context, db DB, agentID, actionID uuid.UUID) (string, error) {
	var typ string
	err := db.QueryRow(ctx, `SELECT type FROM agent_actions WHERE id = $1 AND agent_id = $2 AND status = 'sent'`,
		actionID, agentID).Scan(&typ)
	return typ, mapErr(err)
}

// ActionResultUpdate is a validated result from an agent.
type ActionResultUpdate struct {
	Status     string
	Output     string
	Data       json.RawMessage
	Error      string
	StartedAt  time.Time
	FinishedAt time.Time
}

// RecordActionResult stores a result for an action that was sent to agentID
// and has not reported yet. Returns ErrNotFound otherwise.
func RecordActionResult(ctx context.Context, db DB, agentID, actionID uuid.UUID, u ActionResultUpdate) error {
	var data any
	if len(u.Data) > 0 {
		data = u.Data
	}
	tag, err := db.Exec(ctx, `UPDATE agent_actions SET status = $3, output = $4, data = $5, error = $6,
			started_at = $7, finished_at = $8
		WHERE id = $1 AND agent_id = $2 AND status = 'sent'`,
		actionID, agentID, u.Status, u.Output, data, u.Error, u.StartedAt, u.FinishedAt)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// ExpireActions gives up on actions that were not delivered or not reported
// in time. Returns how many expired.
func ExpireActions(ctx context.Context, db DB) (int, error) {
	tag, err := db.Exec(ctx, `UPDATE agent_actions SET finished_at = now(), status = 'expired',
			error = CASE WHEN status = 'queued'
				THEN 'the endpoint did not check in to pick this up in time (offline?)'
				ELSE 'the endpoint did not report a result in time (agent too old for this action, restarted, or offline)' END
		WHERE status IN ('queued', 'sent') AND expires_at < now()`)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// CancelQueued cancels the still-queued actions of a job (all of them, or
// one when actionID is not nil). Returns how many were cancelled.
func CancelQueued(ctx context.Context, db DB, jobID uuid.UUID, actionID *uuid.UUID) (int, error) {
	tag, err := db.Exec(ctx, `UPDATE agent_actions SET status = 'cancelled', finished_at = now(), error = 'cancelled from the console'
		WHERE job_id = $1 AND ($2::uuid IS NULL OR id = $2) AND status = 'queued'`, jobID, actionID)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// DeleteOldJobs removes jobs (and their actions) created before maxAge ago.
func DeleteOldJobs(ctx context.Context, db DB, maxAge time.Duration) (int, error) {
	tag, err := db.Exec(ctx, `DELETE FROM action_jobs WHERE created_at < now() - $1::interval
		AND NOT EXISTS (SELECT 1 FROM agent_actions x WHERE x.job_id = action_jobs.id AND x.status IN ('queued', 'sent'))`, maxAge)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

const actionCols = `x.id, x.job_id, x.agent_id, x.tenant_id, a.hostname, t.name, x.type, x.params, x.status,
	x.created_at, x.sent_at, x.started_at, x.finished_at, x.expires_at, x.output, x.data, x.error`

const actionFrom = ` FROM agent_actions x JOIN agents a ON a.id = x.agent_id JOIN tenants t ON t.id = x.tenant_id`

func scanAction(row interface{ Scan(...any) error }) (*AgentAction, error) {
	var x AgentAction
	err := row.Scan(&x.ID, &x.JobID, &x.AgentID, &x.TenantID, &x.Hostname, &x.TenantName, &x.Type, &x.Params, &x.Status,
		&x.CreatedAt, &x.SentAt, &x.StartedAt, &x.FinishedAt, &x.ExpiresAt, &x.Output, &x.Data, &x.Error)
	if err != nil {
		return nil, err
	}
	return &x, nil
}

func queryActions(ctx context.Context, db DB, sql string, args ...any) ([]AgentAction, error) {
	rows, err := db.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AgentAction
	for rows.Next() {
		x, err := scanAction(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *x)
	}
	return out, rows.Err()
}

func GetAction(ctx context.Context, db DB, id uuid.UUID) (*AgentAction, error) {
	x, err := scanAction(db.QueryRow(ctx, `SELECT `+actionCols+actionFrom+` WHERE x.id = $1`, id))
	return x, mapErr(err)
}

// ListAgentActions returns an endpoint's most recent actions, newest first.
func ListAgentActions(ctx context.Context, db DB, agentID uuid.UUID, limit int) ([]AgentAction, error) {
	return queryActions(ctx, db, `SELECT `+actionCols+actionFrom+` WHERE x.agent_id = $1 ORDER BY x.created_at DESC, x.id DESC LIMIT $2`, agentID, limit)
}

// ListJobActions returns a job's actions ordered by hostname.
func ListJobActions(ctx context.Context, db DB, jobID uuid.UUID) ([]AgentAction, error) {
	return queryActions(ctx, db, `SELECT `+actionCols+actionFrom+` WHERE x.job_id = $1 ORDER BY lower(a.hostname), x.id`, jobID)
}

const jobSelect = `SELECT j.id, j.tenant_id, t.name, j.type, j.params, j.created_by, u.email, j.created_at,
		count(x.id), count(x.id) FILTER (WHERE x.status IN ('queued', 'sent')),
		count(x.id) FILTER (WHERE x.status = 'done'),
		count(x.id) FILTER (WHERE x.status IN ('failed', 'rejected', 'expired', 'cancelled'))
	FROM action_jobs j JOIN tenants t ON t.id = j.tenant_id JOIN users u ON u.id = j.created_by
	LEFT JOIN agent_actions x ON x.job_id = j.id`

const jobGroup = ` GROUP BY j.id, t.name, u.email`

func scanJob(row interface{ Scan(...any) error }) (*Job, error) {
	var j Job
	if err := row.Scan(&j.ID, &j.TenantID, &j.TenantName, &j.Type, &j.Params, &j.CreatedBy, &j.CreatorEmail, &j.CreatedAt,
		&j.Total, &j.Open, &j.Done, &j.Failed); err != nil {
		return nil, err
	}
	return &j, nil
}

func GetJob(ctx context.Context, db DB, id uuid.UUID) (*Job, error) {
	j, err := scanJob(db.QueryRow(ctx, jobSelect+` WHERE j.id = $1`+jobGroup, id))
	return j, mapErr(err)
}

// ListJobs returns recent jobs, newest first, optionally for one tenant.
func ListJobs(ctx context.Context, db DB, tenantID *uuid.UUID, limit int) ([]Job, error) {
	rows, err := db.Query(ctx, jobSelect+` WHERE ($1::uuid IS NULL OR j.tenant_id = $1)`+jobGroup+
		` ORDER BY j.created_at DESC, j.id DESC LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Job
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *j)
	}
	return out, rows.Err()
}
