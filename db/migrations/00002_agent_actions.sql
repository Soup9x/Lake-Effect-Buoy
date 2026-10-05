-- +goose Up
-- Allowlisted agent actions (CLAUDE.md rule 1) queued from the console, and
-- their results. A job groups the actions queued together: one endpoint, or
-- a batch within a tenant.
CREATE TABLE action_jobs (
    id          uuid PRIMARY KEY,
    tenant_id   uuid NOT NULL REFERENCES tenants (id),
    type        text NOT NULL CHECK (type IN ('clamd_check', 'clamd_reload', 'clamd_stats', 'scan_path')),
    params      jsonb NOT NULL DEFAULT '{}',
    created_by  uuid NOT NULL REFERENCES users (id),
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX action_jobs_time ON action_jobs (created_at DESC);
CREATE INDEX action_jobs_tenant ON action_jobs (tenant_id, created_at DESC);

CREATE TABLE agent_actions (
    id          uuid PRIMARY KEY,
    job_id      uuid NOT NULL REFERENCES action_jobs (id) ON DELETE CASCADE,
    agent_id    uuid NOT NULL REFERENCES agents (id) ON DELETE CASCADE,
    tenant_id   uuid NOT NULL REFERENCES tenants (id),
    type        text NOT NULL,
    params      jsonb NOT NULL DEFAULT '{}',
    status      text NOT NULL DEFAULT 'queued'
                CHECK (status IN ('queued', 'sent', 'done', 'failed', 'rejected', 'expired', 'cancelled')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    sent_at     timestamptz NULL,
    -- As reported by the agent.
    started_at  timestamptz NULL,
    finished_at timestamptz NULL,
    -- queued: must be delivered before this; sent: must be reported before this.
    expires_at  timestamptz NOT NULL,
    output      text NOT NULL DEFAULT '',
    data        jsonb NULL,
    error       text NOT NULL DEFAULT ''
);
CREATE INDEX agent_actions_queued ON agent_actions (agent_id, created_at) WHERE status = 'queued';
CREATE INDEX agent_actions_agent ON agent_actions (agent_id, created_at DESC);
CREATE INDEX agent_actions_job ON agent_actions (job_id);
CREATE INDEX agent_actions_open ON agent_actions (expires_at) WHERE status IN ('queued', 'sent');

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cav_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON action_jobs, agent_actions TO cav_app;
    END IF;
END;
$$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE agent_actions;
DROP TABLE action_jobs;
