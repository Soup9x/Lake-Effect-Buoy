# ClamAV MSP Console: Phase 1 Design Proposal

Status: **Approved by Nolan 2026-10-01 with the changes in section 0a.** Section 0a overrides anything below it that conflicts.
Date: 2026-10-01

## 0a. Changes from review (binding)

1. **Release signing.** Agent binaries are signed with a minisign (Ed25519) key that never lives on the server. The public key is embedded in the agent and in both install scripts. Install scripts verify the minisign signature (not just a server-provided checksum) before installing. The server only hosts the binaries and `.minisig` files.
2. **401 handling.** For a revoked credential the server returns `401` with error code `agent_revoked`. The agent stops **only** on that code. Any other 401 means keep retrying with slow backoff (30 to 60 min, jittered) and log loudly.
3. **operations.md** covers backing up and rotating `TOKEN_HASH_KEY` and the consequences of losing it.
4. **Caddy exposure.** Only `/agent/v1/*`, `/downloads/*` and `/healthz` are public. Everything else (UI and admin routes) is restricted to a configurable list of source IPs/CIDRs (`ADMIN_ALLOWED_CIDRS`, for VPN/Tailscale).
5. **Session idle timeout.** UI background auto-refresh requests do not extend the session idle timeout.
6. **Windows service account.** The service runs as the virtual account `NT SERVICE\ClamAVAgent`, not LocalSystem. The credential file is ACL'd to that account + Administrators only.

Answers: Q1 htmx with server-rendered pages (replaces the React SPA; the JSON admin API becomes secondary). Q2 private repo `clamav-console` under GitHub account `Soup9x`, created once Phase 1 builds. Q3 admin behind VPN, agent endpoints public (see 4). Q4 no Windows code-signing cert yet, deferred. Q5 offline after 3 minutes.


## 0. Decisions at a glance

These are my recommended defaults. Each one is marked so you can approve it or change it.

| # | Decision | Recommendation |
|---|----------|----------------|
| D1 | Server language | **Go**, same module as the agent, so the agent/server protocol types are shared and compile-checked. |
| D2 | Web UI | ~~React SPA~~ **Server-rendered Go templates + htmx** (per Q1), embedded in the server binary. |
| D3 | DB access | `pgx` + `sqlc` (typed SQL, no ORM). Migrations with `goose`, run on server start. |
| D4 | TLS | **Caddy** container in Compose terminates TLS (automatic Let's Encrypt, or a supplied cert). Server listens on plain HTTP on the internal Compose network only. |
| D5 | Agent credential | Random 256-bit bearer secret issued at enrollment, stored hashed server-side. mTLS deferred (harder through a reverse proxy; can be added later without changing the data model much). |
| D6 | Heartbeat storage | Latest state on the `agents` row only. No per-heartbeat history in Phase 1 (1,000 agents = 1.4M rows/day). Status *changes* are recorded as `agent_events`. |
| D7 | Online/offline | Computed at read time: online if `last_heartbeat_at > now() - 180s` (3 missed beats). Threshold is a server setting. |
| D8 | Agent actions in Phase 1 | The allowlist framework ships, with **zero remote actions enabled**. The agent only sends read-only `VERSION`/`PING` to clamd for its own heartbeat. |
| D9 | Agent binary distribution | Server serves minisign-signed binaries at `/downloads/`; install scripts verify the signature with an embedded public key (0a.1). |
| D10 | Users/roles | MSP staff accounts only, single `admin` role in Phase 1, with a `role` column so tenant-scoped roles can be added later. |

---

## 1. Repo layout

Single Go module, monorepo.

```
clamav-console/
├── CLAUDE.md                      # permanent project rules (section 7)
├── README.md
├── go.mod / go.sum
├── Makefile                       # build, test, lint, sqlc, ui, release
├── .env.example                   # placeholder values only; .env is gitignored
├── .gitignore
├── .gitleaks.toml                 # secret scanning (pre-commit + CI)
├── cmd/
│   ├── server/                    # console server main (serve, migrate, admin subcommands)
│   └── agent/                     # agent main (run, enroll, install-service, status)
├── internal/
│   ├── protocol/                  # agent<->server wire types + action allowlist (shared)
│   ├── agent/
│   │   ├── clamd/                 # clamd socket client (only the commands we allow)
│   │   ├── actions/               # allowlisted action handlers + param validators
│   │   ├── config/                # config file load/validate
│   │   ├── credstore/             # credential storage (0600 file / Windows ACL)
│   │   ├── service/               # systemd + Windows service wrappers
│   │   └── heartbeat/             # collector + send loop with jittered backoff
│   └── server/
│       ├── api/                   # HTTP routing, handlers, request validation
│       │   ├── admin/             # /api/v1  (session-authenticated)
│       │   └── agent/             # /agent/v1 (agent-credential-authenticated)
│       ├── auth/                  # passwords, sessions, CSRF, MFA-ready login flow
│       ├── audit/                 # audit writer (only way to record admin actions)
│       ├── store/                 # sqlc-generated queries + transactions
│       ├── tokens/                # enrollment token + agent credential generation/hashing
│       ├── config/                # env-var config (no secrets from files in repo)
│       └── web/                   # embeds built UI assets
├── db/
│   ├── migrations/                # goose SQL migrations
│   └── queries/                   # sqlc .sql query files
├── web/                           # (dropped: UI is server-rendered, see internal/server/web)
├── deploy/
│   ├── docker-compose.yml         # caddy + server + postgres
│   ├── Caddyfile
│   └── Dockerfile.server          # multi-stage, distroless, non-root
├── packaging/
│   ├── linux/
│   │   ├── install.sh
│   │   ├── uninstall.sh
│   │   └── clamav-agent.service
│   └── windows/
│       ├── install.ps1
│       └── uninstall.ps1
├── docs/
│   ├── design/phase1.md           # this document, once approved
│   ├── install-agent.md
│   └── operations.md              # deploy, backup, key rotation
└── .github/workflows/ci.yml       # lint, test, gitleaks, govulncheck, build matrix
```

Why one module: `internal/protocol` is imported by both binaries, so a field rename or a new action can't drift between agent and server. `internal/` also prevents the agent from importing server code and vice versa (enforced with a `depguard` lint rule).

---

## 2. Data model (Postgres)

All IDs are UUIDv7 (time-sortable). All timestamps are `timestamptz`. Secrets are never stored in plaintext; token hashes are `HMAC-SHA256(TOKEN_HASH_KEY, token)` so a DB dump alone can't be used to brute-force or replay them.

### tenants
| column | type | notes |
|---|---|---|
| id | uuid PK | |
| name | text not null | unique (case-insensitive) among non-archived |
| slug | text not null unique | for URLs |
| external_id | text null | ID in external PSA/doc system |
| source | text null | e.g. `halopsa`, `itglue`; null = created locally |
| notes | text null | |
| archived_at | timestamptz null | soft delete; archiving revokes tokens |
| created_at / updated_at | timestamptz | |

Constraint: `unique (source, external_id) where external_id is not null` so a future sync can upsert safely. Check: `external_id` and `source` are both null or both set.

### users
| column | type | notes |
|---|---|---|
| id | uuid PK | |
| email | citext unique not null | login name |
| display_name | text | |
| password_hash | text not null | argon2id, encoded params |
| role | text not null default `admin` | check in (`admin`) for Phase 1 |
| disabled_at | timestamptz null | |
| failed_login_count | int | lockout support |
| locked_until | timestamptz null | |
| password_changed_at | timestamptz | |
| created_at / updated_at | | |

### user_mfa_factors (created now, unused in Phase 1)
| column | type | notes |
|---|---|---|
| id | uuid PK | |
| user_id | uuid FK users | |
| type | text | `totp`, `webauthn` |
| secret_enc / credential | bytea | encrypted with `MFA_ENC_KEY` env var |
| confirmed_at, last_used_at, created_at | | |

### sessions
| column | type | notes |
|---|---|---|
| id | uuid PK | |
| token_hash | bytea unique | cookie value is random 256-bit, only hash stored |
| user_id | uuid FK | |
| auth_level | smallint | 1 = password, 2 = password + MFA |
| mfa_required | bool | true if user has a confirmed factor |
| csrf_token | bytea | per-session |
| created_at, last_seen_at, expires_at | | idle 30 min, absolute 12 h |
| ip, user_agent | inet, text | |
| revoked_at | timestamptz null | |

### enrollment_tokens
| column | type | notes |
|---|---|---|
| id | uuid PK | |
| tenant_id | uuid FK tenants | |
| label | text | e.g. "Main office rollout" |
| token_prefix | text | first 8 chars, shown in UI to identify it |
| token_hash | bytea unique | full token shown **once** at creation |
| expires_at | timestamptz not null | default 7 days, max 90 |
| max_uses | int null | null = unlimited until expiry |
| use_count | int not null default 0 | |
| revoked_at | timestamptz null | |
| created_by | uuid FK users | |
| created_at | | |

Token format: `cav_enr_<base32 32 bytes>`. The recognisable prefix lets gitleaks/GitHub secret scanning catch leaked tokens.

### agents
| column | type | notes |
|---|---|---|
| id | uuid PK | the agent ID, issued at enrollment |
| tenant_id | uuid FK tenants | fixed at enrollment, from the token |
| enrolled_via | uuid FK enrollment_tokens | |
| credential_hash | bytea not null | HMAC of current credential |
| credential_prev_hash | bytea null | valid only until `credential_prev_expires_at` (rotation grace) |
| credential_rotated_at | timestamptz | |
| machine_id | text | `/etc/machine-id` or Windows MachineGuid, used to flag duplicates |
| hostname | text | |
| os_family | text | `linux` / `windows` |
| os_name, os_version, arch | text | |
| agent_version | text | |
| clamav_engine_version | text null | e.g. `1.4.1` |
| signature_version | int null | daily DB version, e.g. `27410` |
| signature_date | timestamptz null | |
| clamd_status | text | `running`, `not_responding`, `not_installed`, `unknown` |
| clamd_error | text null | short last error, length-capped |
| last_heartbeat_at | timestamptz null | |
| last_ip | inet null | as seen by server (X-Forwarded-For from Caddy only) |
| enrolled_at | timestamptz | |
| revoked_at | timestamptz null | revoked agents get 401 and stop |
| created_at / updated_at | | |

Index: `(tenant_id, hostname)`, `(last_heartbeat_at)`.

### agent_events
Low-volume history: enrolled, revoked, clamd status changed, agent version changed, credential rotated, went offline/online (written by a background sweeper). `id, agent_id, tenant_id, type, details jsonb, occurred_at`.

### audit_log (append-only)
| column | type | notes |
|---|---|---|
| id | bigint identity PK | |
| occurred_at | timestamptz default now() | |
| actor_type | text | `user`, `system`, `agent` |
| actor_id | uuid null | |
| actor_label | text | email at the time, so history survives renames |
| tenant_id | uuid null | |
| action | text | dotted verb, from a fixed list in code, e.g. `tenant.create`, `enrollment_token.revoke`, `auth.login_failed` |
| target_type, target_id | text, text | |
| outcome | text | `success` / `denied` / `error` |
| ip, user_agent, request_id | | |
| details | jsonb | before/after for updates; **never secrets** |

Append-only is enforced in the database, not just in code: the app's DB role gets `INSERT, SELECT` only on `audit_log`, and a trigger raises on `UPDATE`/`DELETE`/`TRUNCATE`. Retention/pruning (if ever) is done by a separate migration-owner role, and is itself audited.

**What gets audited (Phase 1):** login success/failure, logout, lockout, session revoke; user create/disable/password change; tenant create/update/archive; enrollment token create/revoke; agent enroll (actor = token), agent revoke, credential rotation; any `denied` authorization result on an admin endpoint.

---

## 3. Agent ↔ server API

Base path `/agent/v1`, HTTPS only, JSON bodies, max request size 64 KB. The agent makes outbound requests only and never opens a listening socket.

**Auth header:** `Authorization: Bearer cav_agt_<agent_id>.<secret>`. Server looks up the agent by ID, compares `HMAC(secret)` in constant time, rejects revoked agents and archived tenants.

### POST /agent/v1/enroll
No auth header; the enrollment token is in the body. Rate-limited per IP.

Request:
```json
{
  "enrollment_token": "cav_enr_…",
  "machine_id": "3f2a…",
  "hostname": "FS01",
  "os_family": "windows",
  "os_name": "Windows Server 2022 Standard",
  "os_version": "10.0.20348",
  "arch": "amd64",
  "agent_version": "0.1.0"
}
```
Response `201`:
```json
{
  "agent_id": "0192…",
  "credential": "cav_agt_0192….<secret>",
  "tenant_name": "Acme Dental",
  "heartbeat_interval_seconds": 60
}
```
Errors: `401 invalid_token` (one generic error for unknown/expired/revoked/exhausted, so tokens can't be probed), `409 already_enrolled` if the machine_id matches an active agent in the same tenant (UI offers "replace"). Token `use_count` increment and agent insert happen in one transaction.

### POST /agent/v1/heartbeat
Sent every 60 s, with ±10 s jitter, and immediately on startup.

Request:
```json
{
  "hostname": "FS01",
  "os_name": "Windows Server 2022 Standard",
  "os_version": "10.0.20348",
  "agent_version": "0.1.0",
  "clamav": {
    "status": "running",
    "engine_version": "1.4.1",
    "signature_version": 27410,
    "signature_date": "2026-09-30T08:01:00Z",
    "error": null
  },
  "sent_at": "2026-10-01T14:30:00Z"
}
```
`engine_version`, `signature_version`, `signature_date` come from parsing clamd's `VERSION` reply (`ClamAV 1.4.1/27410/Tue Sep 30 08:01:00 2026`). `status` is `running` if `PING` returns `PONG`.

Response `200`:
```json
{
  "heartbeat_interval_seconds": 60,
  "server_time": "2026-10-01T14:30:00Z",
  "actions": []
}
```
`actions` is always empty in Phase 1 (D8). It's in the contract now so adding actions later doesn't need a protocol version bump.

Every field is validated server-side: length caps, printable charset, enum values, version strings matched against a regex, dates within a sane window. Invalid heartbeats get `400` and are not partially applied.

### POST /agent/v1/credential/rotate
Authenticated. Server issues a new credential and keeps the old hash valid for 10 minutes so a crash mid-rotation doesn't strand the agent. Agent writes the new credential to its store, then confirms on the next heartbeat. Phase 1 trigger: manual from the UI (flag returned in heartbeat response) or `clamav-agent rotate`.

### Agent-side failure behaviour
- `401` with error code `agent_revoked`: credential revoked. Agent stops heartbeating, logs loudly, exits with a distinct code so the service manager doesn't hot-loop (systemd `RestartPreventExitStatus`).
- Any other `401`: keep running, log loudly at error level, retry with slow backoff (30 to 60 min, jittered), so a proxy misconfiguration or server bug can't permanently kill a fleet of agents.
- Network errors / `5xx`: exponential backoff, capped at 5 min, then back to 60 s on success.
- TLS: system trust store by default; optional `ca_cert_pin` (SPKI SHA-256) in config for self-hosted certs.

### Action allowlist design (framework only in Phase 1)
- `internal/protocol/actions.go` defines a closed Go enum of action types. Each type has a typed params struct and a `Validate()` method. Unknown types are rejected and reported back as `rejected_unknown_action`.
- The agent dispatches through a static `map[ActionType]Handler` built at compile time. Handlers may only call the `clamd` package (fixed protocol commands) or other typed, purpose-built functions. **No `os/exec` with server-supplied strings, no shell, anywhere in the agent.** A lint rule (`forbidigo`) bans `os/exec` in `internal/agent/actions` outright; if a future action truly needs to start a process (e.g. `freshclam`), the binary path is a constant and arguments are constants or validated enums, reviewed as a security change.
- Path parameters (for a future `scan_path`) are cleaned, must be absolute, must sit under an allowlist of roots set in the **local** agent config (not by the server), and are passed to clamd as data, never interpolated.
- Server side, admins can only queue actions whose types exist in the same enum, and each queue/result is audited.
- Candidate Phase 2 actions for reference: `clamd_ping`, `reload_signatures` (clamd `RELOAD`), `update_signatures` (fixed `freshclam` invocation), `scan_path`.

---

## 4. Admin REST API (used by the web UI)

Base path `/api/v1`. Session cookie auth (`__Host-session`, HttpOnly, Secure, SameSite=Strict). State-changing requests must also send `X-CSRF-Token` matching the session. JSON in/out. Errors use one shape: `{"error": {"code": "...", "message": "..."}}`. Lists are cursor-paginated.

| Method & path | Purpose | Audited |
|---|---|---|
| POST `/auth/login` | email + password → session. Returns `{ "next": "done" }` or, later, `{ "next": "mfa" }` | yes |
| POST `/auth/mfa/verify` | **reserved**, returns 501 in Phase 1 | — |
| POST `/auth/logout` | revoke current session | yes |
| GET `/auth/me` | current user, auth_level, csrf token | no |
| POST `/auth/password` | change own password (requires current) | yes |
| GET `/tenants` | list with endpoint counts (total/online/offline) | no |
| POST `/tenants` | create (`name`, optional `external_id`, `source`, `notes`) | yes |
| GET `/tenants/{id}` | detail | no |
| PATCH `/tenants/{id}` | update | yes |
| POST `/tenants/{id}/archive` | archive + revoke its tokens | yes |
| GET `/tenants/{id}/enrollment-tokens` | list (prefix, label, expiry, uses; never the token) | no |
| POST `/tenants/{id}/enrollment-tokens` | create; response contains the plaintext token **once** plus install commands | yes |
| POST `/enrollment-tokens/{id}/revoke` | revoke | yes |
| GET `/tenants/{id}/agents` | endpoints with `online`, `last_heartbeat_at`, versions, clamd status; filters `status=online/offline`, `q=` hostname | no |
| GET `/agents/{id}` | endpoint detail + recent `agent_events` | no |
| POST `/agents/{id}/revoke` | revoke credential | yes |
| POST `/agents/{id}/rotate-credential` | request rotation on next heartbeat | yes |
| GET `/audit-log` | filter by tenant, actor, action, time range | no (read) |
| GET `/users`, POST `/users`, POST `/users/{id}/disable` | staff account management | yes |

Other server endpoints: `GET /healthz` (liveness), `GET /readyz` (DB reachable), `GET /downloads/agent/{os}/{arch}` + `SHA256SUMS`.

### MFA-ready login design
Login is a small state machine stored on the session: after a correct password the session gets `auth_level=1`. If the user has a confirmed MFA factor (`mfa_required=true`), every route except `/auth/mfa/*`, `/auth/logout` and `/auth/me` requires `auth_level=2`. In Phase 1 no user has a factor, so password login is complete. Adding TOTP/WebAuthn later is new endpoints plus a `user_mfa_factors` row, with no changes to middleware or existing routes. A server setting `REQUIRE_MFA=true` can later force enrollment.

### Other auth controls
- argon2id (m=64 MiB, t=3, p=2), min password length 12, checked against a breached-password list offline.
- Lockout: 10 failures → 15 min lock; per-IP rate limit on `/auth/login`.
- First admin is created by `clamav-console admin create --email …` inside the container, reading the password from stdin. **No default credentials.**
- Security headers set by the server: strict CSP (no inline script), `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, HSTS via Caddy.

---

## 5. Web UI (Phase 1 screens)

1. **Login** (email, password; MFA step slot reserved).
2. **Tenants**: table of name, external ID/source badge, endpoints online/total, oldest signature date. Create/edit/archive.
3. **Tenant → Endpoints**: hostname, OS, agent version, ClamAV version, signature version and age (amber > 2 days, red > 7 days), clamd status, online/offline dot, last heartbeat ("43 s ago"). Auto-refresh every 30 s.
4. **Tenant → Enrollment tokens**: create (label, expiry, max uses), show token once with copy-paste Windows and Linux install commands, revoke.
5. **Endpoint detail**: fields above + recent events, revoke / rotate buttons (confirmation dialog).
6. **Audit log**: filterable table.

---

## 6. Agent runtime, install & deployment

### Agent config (`/etc/clamav-agent/agent.yaml`, `C:\ProgramData\ClamAVAgent\agent.yaml`)
```yaml
server_url: https://console.example.com
clamd:
  # Linux: unix socket. Windows: TCP, which must be loopback (127.0.0.1 / ::1);
  # the agent refuses any non-loopback address.
  address: unix:///run/clamav/clamd.ctl
ca_cert_pin: ""            # optional SPKI SHA-256
log_level: info
```
Credential lives in a separate file: Linux `/var/lib/clamav-agent/credential` (0600, owned by the agent user); Windows `C:\ProgramData\ClamAVAgent\credential`, ACL'd to `NT SERVICE\ClamAVAgent` + Administrators only (0a.6).

The installer auto-detects the clamd socket on Linux (`/run/clamav/clamd.ctl` on Debian/Ubuntu, `/run/clamd.scan/clamd.sock` on RHEL) and reads `clamd.conf` on Windows for `TCPAddr`/`TCPSocket`.

### Linux (systemd)
- Runs as dedicated user `clamav-agent`, added to the group that owns the clamd socket. Not root.
- Unit hardening: `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, `CapabilityBoundingSet=` (empty), `ReadWritePaths=/var/lib/clamav-agent`.
- `install.sh`: downloads binary for the arch from the server, verifies SHA-256, creates user/dirs, writes config, runs `clamav-agent enroll` with the token read from the `CAV_ENROLL_TOKEN` env var or stdin (not argv, so it doesn't show up in `ps`), enables and starts the unit. Idempotent; `--reinstall` to re-enroll.

### Windows (service)
- Service `ClamAVAgent`, runs as the virtual account `NT SERVICE\ClamAVAgent` (0a.6); recovery set to restart on failure.
- `install.ps1`: same flow as Linux, checksum via `Get-FileHash`, installs to `C:\Program Files\ClamAVAgent\`, token from `-EnrollToken` parameter or `$env:CAV_ENROLL_TOKEN`.
- Code-signing the Windows binary is recommended before rolling out to clients (open question Q4).

### Server deployment (Docker Compose)
- `caddy` (ports 80/443, the only published ports), `server` (internal only), `postgres` (internal only, named volume).
- Caddy publishes only `/agent/v1/*`, `/downloads/*`, `/healthz` to any source; all other paths require the client IP to be in `ADMIN_ALLOWED_CIDRS` (0a.4).
- `server` image: distroless, non-root, read-only root FS.
- All config from env vars, loaded from a `.env` file next to the compose file on the host (gitignored). `.env.example` lists them with placeholders:
  `DATABASE_URL`, `TOKEN_HASH_KEY`, `MFA_ENC_KEY`, `PUBLIC_URL`, `ACME_EMAIL`, `POSTGRES_PASSWORD`, `AGENT_OFFLINE_AFTER_SECONDS`.
- Server refuses to start if a required secret is missing, empty, or equals a placeholder value from `.env.example`.

---

## 7. CLAUDE.md: permanent project rules (draft)

```markdown
# Project rules (security). These are non-negotiable.

1. Agent actions are a fixed allowlist.
   - The agent may only execute action types defined in internal/protocol/actions.go,
     each with a typed, validated parameter struct.
   - Never add arbitrary command execution, shell invocation, script download-and-run,
     or "run this string" features to the agent, under any name, ever.
   - Never pass server-supplied data to os/exec, a shell, or a file path without
     validation against a local allowlist. os/exec is banned in internal/agent/actions
     by lint; do not disable that rule.
   - The agent never listens on a network port. It only makes outbound HTTPS requests
     and talks to clamd over a Unix socket or loopback TCP.
   - Adding or changing an action type is a security change: update the allowlist,
     validators, tests (including malicious-input tests) and docs in the same PR.

2. All admin actions are audited.
   - Every state-changing admin endpoint writes an audit_log entry via internal/server/audit,
     in the same transaction as the change. Denied attempts are audited too.
   - audit_log is append-only. Never add code paths that update or delete it.
   - Never write secrets (passwords, tokens, credentials) into audit details or logs.

3. The web UI and admin API require authentication.
   - Every /api/v1 route except /auth/login is behind session auth + CSRF checks.
     New routes must be registered through the authenticated router.
   - Keep the MFA-ready design: authorization checks use the session auth_level;
     do not add shortcuts that bypass it.
   - No default or hard-coded credentials.

4. Secrets come from environment variables only.
   - Never commit secrets, real tokens, keys, certificates or .env files.
     .env.example contains placeholders only.
   - Store only hashes of enrollment tokens, agent credentials and session tokens.
   - gitleaks runs in CI and pre-commit; do not bypass it.
```

---

## 8. Testing & CI (Phase 1)
- Unit tests for clamd reply parsing, token hashing, validators, auth state machine.
- Integration tests against real Postgres (testcontainers) for enrollment, heartbeat, revocation, audit-append-only (asserting UPDATE/DELETE fail).
- A fake clamd for agent tests. Fuzz tests for heartbeat validation and clamd parser.
- CI: `golangci-lint` (incl. `forbidigo`, `depguard`, `gosec`), `go test -race`, `govulncheck`, `gitleaks`, UI typecheck/build, cross-compile agent for linux/amd64, linux/arm64, windows/amd64.

## 9. Explicitly out of scope for Phase 1
Remote actions (scans, signature updates), scan results/detections, alerting, PSA sync, MFA implementation, tenant-scoped staff roles, agent auto-update, per-heartbeat history.

## 10. Open questions for Nolan
- **Q1. Stack:** OK with Go server + React SPA (D1/D2)? Lighter alternative: server-rendered pages with htmx (less JS, but the REST API would then be secondary).
- **Q2. Repo:** what name, and which GitHub owner/org? No repo is attached to this project yet.
- **Q3. Hosting/TLS:** will the console be on a public hostname (Let's Encrypt via Caddy) or behind your own cert/VPN?
- **Q4. Windows code-signing:** do you have a code-signing cert, or should that wait?
- **Q5. Agent offline threshold:** 3 missed heartbeats (3 min) OK?

---

## 11. Implementation notes (Phase 1 as built)

Differences from the sections above, decided during implementation:

- **SQL access:** hand-written `pgx` queries in `internal/server/store` instead of `sqlc` code generation. Same intent (plain SQL, no ORM) without a codegen toolchain.
- **Admin JSON API:** with htmx (Q1) the UI is served as HTML routes (`/tenants`, `/agents/{id}`, ...). The `/api/v1` JSON API in section 4 is deferred; the handlers sit on the same store/audit layer, so it can be added without schema changes.
- **Migrations:** run by a one-shot `migrate` Compose service as the owner role. The long-running server connects as `cav_app` and never holds owner credentials.
- **Windows credential storage:** file ACLs only (`NT SERVICE\ClamAVAgent` + Administrators). DPAPI machine scope was dropped because any process on the machine can decrypt machine-scoped DPAPI, so it adds little over the ACL.
- **TOKEN_HASH_KEY rotation:** `TOKEN_HASH_KEY_PREVIOUS` is accepted during a rotation and secrets are re-hashed on use (docs/operations.md).
- **Breached-password check:** not implemented in Phase 1 (minimum length 12, lockout and rate limiting are).
- **Agent actions (after Phase 1):** four actions are enabled, all fixed clamd protocol commands: `clamd_check` (`VERSION`), `clamd_reload` (`RELOAD`), `clamd_stats` (`STATS`) and `scan_path` (`CONTSCAN`, read-only: no quarantine or delete). `update_signatures` (freshclam) is not offered, because it would need `os/exec`. `scan_path` only accepts folders under `scan_roots` from the agent's local config (empty by default, so scans are refused), resolved with symlinks before the containment check. The server stores a job (`action_jobs`) per request, one action row per endpoint (`agent_actions`), delivers queued actions in the heartbeat response, and takes results at `POST /agent/v1/actions/result` (strictly decoded, size-capped, control characters replaced). Actions expire if not delivered in 24 h or not reported in time. Queue, cancel and refused requests are audited; results are agent data, not admin actions, so they are not.
- **Windows signature verification is interim:** `install.ps1` verifies minisign with an inline C# BLAKE2b + Ed25519 implementation (Wycheproof and BLAKE2b vector tests in CI on PowerShell 5.1 and 7). It is to be replaced by Authenticode verification once a code-signing certificate exists (Q4).
