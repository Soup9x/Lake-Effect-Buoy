// Package web serves the server-rendered htmx admin UI.
package web

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Soup9x/Lake-Effect-Buoy/internal/protocol"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/server/audit"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/server/auth"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/server/httpx"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/server/secret"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/server/store"
)

type Server struct {
	DB           *pgxpool.Pool
	Auth         *auth.Manager
	Hasher       *secret.Hasher
	Log          *slog.Logger
	PublicURL    *url.URL
	OfflineAfter time.Duration
	// DownloadsDir holds the agent release files; the install commands
	// depend on what is published there (console-ca.pem, install.ps1).
	DownloadsDir string
	tmpl         templates
	loginRate    *httpx.RateLimiter
}

func New(db *pgxpool.Pool, am *auth.Manager, h *secret.Hasher, log *slog.Logger, publicURL *url.URL, offlineAfter time.Duration, downloadsDir string) *Server {
	return &Server{DB: db, Auth: am, Hasher: h, Log: log, PublicURL: publicURL, OfflineAfter: offlineAfter, DownloadsDir: downloadsDir,
		tmpl: loadTemplates(), loginRate: httpx.NewRateLimiter(20, 10)}
}

// Handler returns the UI. Every route except /login and /static goes
// through protect (CLAUDE.md rule 3).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", staticFiles()))
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.loginSubmit)

	p := func(pattern string, h http.HandlerFunc) { mux.Handle(pattern, s.protect(h)) }
	p("POST /logout", s.logout)
	p("GET /login/mfa", s.mfaPage)
	p("GET /{$}", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/tenants", http.StatusSeeOther) })
	p("GET /tenants", s.tenantsPage)
	p("POST /tenants", s.tenantCreate)
	p("GET /tenants/{id}", s.tenantEndpoints)
	p("GET /tenants/{id}/agents", s.tenantAgentsFragment)
	p("GET /tenants/{id}/tokens", s.tenantTokens)
	p("POST /tenants/{id}/tokens", s.tokenCreate)
	p("GET /tenants/{id}/settings", s.tenantSettings)
	p("POST /tenants/{id}", s.tenantUpdate)
	p("POST /tenants/{id}/archive", s.tenantArchive)
	p("POST /enrollment-tokens/{id}/revoke", s.tokenRevoke)
	p("GET /agents/{id}", s.agentPage)
	p("POST /agents/{id}/revoke", s.agentRevoke)
	p("POST /agents/{id}/rotate", s.agentRotate)
	p("POST /agents/{id}/actions", s.agentActionCreate)
	p("GET /agents/{id}/actions/rows", s.agentActionRows)
	p("GET /agents/{id}/actions/export.csv", s.agentActionsExport("csv"))
	p("GET /agents/{id}/actions/export.json", s.agentActionsExport("json"))
	p("GET /tenants/{id}/run", s.runPage)
	p("POST /tenants/{id}/jobs", s.jobCreate)
	p("GET /jobs", s.jobsPage)
	p("GET /jobs/{id}", s.jobPage)
	p("GET /jobs/{id}/rows", s.jobRows)
	p("POST /jobs/{id}/cancel", s.jobCancel)
	p("GET /jobs/{id}/export.csv", s.jobExport("csv"))
	p("GET /jobs/{id}/export.json", s.jobExport("json"))
	p("GET /jobs/{id}/infections.csv", s.jobExport("infections"))
	p("GET /actions/{id}", s.actionPage)
	p("GET /audit", s.auditPage)
	p("GET /users", s.usersPage)
	p("POST /users", s.userCreate)
	p("POST /users/{id}/disable", s.userDisable)
	p("GET /account", s.accountPage)
	p("POST /account/password", s.passwordChange)
	return s.Auth.Load(mux)
}

func isHTMX(r *http.Request) bool { return r.Header.Get("HX-Request") == "true" }

// redirect works for both plain form posts and htmx requests.
func redirect(w http.ResponseWriter, r *http.Request, to string) {
	if isHTMX(r) {
		w.Header().Set("HX-Redirect", to)
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

func (s *Server) protect(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		sess := auth.SessionFrom(r)
		if sess == nil {
			redirect(w, r, "/login")
			return
		}
		if !auth.FullyAuthenticated(sess) && r.URL.Path != "/login/mfa" && r.URL.Path != "/logout" {
			s.denied(r, sess, "mfa_required")
			redirect(w, r, "/login/mfa")
			return
		}
		if !auth.CheckCSRF(r, sess) {
			s.denied(r, sess, "csrf")
			http.Error(w, "invalid CSRF token; reload the page and try again", http.StatusForbidden)
			return
		}
		h(w, r)
	})
}

func (s *Server) denied(r *http.Request, sess *store.Session, reason string) {
	if err := audit.Write(r.Context(), s.DB, audit.Entry{Actor: actor(sess), Request: auditReq(r), Action: audit.AccessDenied,
		Outcome: audit.Denied, TargetType: "route", TargetID: r.Method + " " + r.URL.Path, Details: map[string]any{"reason": reason}}); err != nil {
		s.Log.Error("audit write failed", "err", err)
	}
}

func actor(sess *store.Session) audit.Actor {
	return audit.Actor{Type: audit.ActorUser, ID: &sess.User.ID, Label: sess.User.Email}
}

func auditReq(r *http.Request) audit.Request {
	return audit.Request{IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r)}
}

func (s *Server) serverError(w http.ResponseWriter, r *http.Request, err error) {
	s.Log.Error("request failed", "path", r.URL.Path, "err", err, "request_id", httpx.RequestID(r))
	http.Error(w, "internal error (request "+httpx.RequestID(r)+")", http.StatusInternalServerError)
}

func pathID(r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	return id, err == nil
}

// flashes maps ?msg= keys to fixed text so no user input is reflected.
var flashes = map[string]string{
	"tenant_created": "Tenant created.", "tenant_updated": "Tenant saved.", "tenant_archived": "Tenant archived.",
	"token_revoked": "Enrollment token revoked.", "agent_revoked": "Agent revoked.",
	"rotation_requested": "Credential rotation requested; it happens on the agent's next heartbeat.",
	"user_created":       "User created.", "user_disabled": "User disabled.", "password_changed": "Password changed. Other sessions were signed out.",
	"job_cancelled": "Actions not yet picked up by their endpoints were cancelled.",
}

func flash(r *http.Request) string { return flashes[r.URL.Query().Get("msg")] }

// ---- login ----

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if sess := auth.SessionFrom(r); auth.FullyAuthenticated(sess) {
		http.Redirect(w, r, "/tenants", http.StatusSeeOther)
		return
	}
	s.render(w, r, http.StatusOK, "login", page{Title: "Sign in", Data: struct{ Email string }{}})
}

func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	email := strings.TrimSpace(r.PostFormValue("email"))
	data := struct{ Email string }{email}
	if !s.loginRate.Allow(httpx.ClientIP(r)) {
		s.render(w, r, http.StatusTooManyRequests, "login", page{Title: "Sign in", Error: "Too many attempts. Wait a minute and try again.", Data: data})
		return
	}
	sess, err := s.Auth.Login(r.Context(), w, r, email, r.PostFormValue("password"))
	switch {
	case errors.Is(err, auth.ErrBadCredentials):
		s.render(w, r, http.StatusUnauthorized, "login", page{Title: "Sign in", Error: "Invalid email or password.", Data: data})
	case errors.Is(err, auth.ErrLocked):
		s.render(w, r, http.StatusUnauthorized, "login", page{Title: "Sign in", Error: "This account is temporarily locked after repeated failures. Try again later.", Data: data})
	case err != nil:
		s.serverError(w, r, err)
	case !auth.FullyAuthenticated(sess):
		http.Redirect(w, r, "/login/mfa", http.StatusSeeOther)
	default:
		http.Redirect(w, r, "/tenants", http.StatusSeeOther)
	}
}

// mfaPage is the reserved second-factor step. MFA verification is not
// implemented in Phase 1; users with a confirmed factor cannot proceed.
func (s *Server) mfaPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusNotImplemented, "mfa", page{Title: "Second factor"})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFrom(r)
	ctx := r.Context()
	err := store.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if err := store.RevokeSession(ctx, tx, sess.ID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{Actor: actor(sess), Request: auditReq(r), Action: audit.Logout, TargetType: "session", TargetID: sess.ID.String()})
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.Auth.ClearCookie(w)
	redirect(w, r, "/login")
}

// ---- tenants ----

type tenantForm struct {
	Name, Source, ExternalID, Notes string
}

var reSource = regexp.MustCompile(`^[a-z0-9_-]{1,50}$`)

func parseTenantForm(r *http.Request) (tenantForm, store.TenantInput, string) {
	f := tenantForm{
		Name:       strings.TrimSpace(r.PostFormValue("name")),
		Source:     strings.TrimSpace(r.PostFormValue("source")),
		ExternalID: strings.TrimSpace(r.PostFormValue("external_id")),
		Notes:      strings.TrimSpace(r.PostFormValue("notes")),
	}
	in := store.TenantInput{Name: f.Name}
	switch {
	case f.Name == "" || len(f.Name) > 200:
		return f, in, "Name is required (max 200 characters)."
	case (f.Source == "") != (f.ExternalID == ""):
		return f, in, "Set both external source and external ID, or neither."
	case f.Source != "" && !reSource.MatchString(f.Source):
		return f, in, "External source may only contain a-z, 0-9, _ and -."
	case len(f.ExternalID) > 200 || len(f.Notes) > 4000:
		return f, in, "External ID or notes are too long."
	}
	if f.Source != "" {
		in.Source, in.ExternalID = &f.Source, &f.ExternalID
	}
	if f.Notes != "" {
		in.Notes = &f.Notes
	}
	return f, in, ""
}

func formFromTenant(t *store.Tenant) tenantForm {
	d := func(s *string) string {
		if s == nil {
			return ""
		}
		return *s
	}
	return tenantForm{Name: t.Name, Source: d(t.Source), ExternalID: d(t.ExternalID), Notes: d(t.Notes)}
}

func tenantAuditDetails(t *store.Tenant) map[string]any {
	return map[string]any{"name": t.Name, "slug": t.Slug, "source": t.Source, "external_id": t.ExternalID}
}

type tenantsData struct {
	Tenants      []store.TenantSummary
	ShowArchived bool
	Form         tenantForm
}

func (s *Server) tenantsPage(w http.ResponseWriter, r *http.Request) {
	s.renderTenants(w, r, http.StatusOK, tenantForm{}, "")
}

func (s *Server) renderTenants(w http.ResponseWriter, r *http.Request, status int, f tenantForm, errMsg string) {
	showArchived := r.URL.Query().Get("archived") == "1"
	list, err := store.ListTenants(r.Context(), s.DB, s.OfflineAfter, showArchived)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, status, "tenants", page{Title: "Tenants", Flash: flash(r), Error: errMsg,
		Data: tenantsData{Tenants: list, ShowArchived: showArchived, Form: f}})
}

func (s *Server) tenantCreate(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFrom(r)
	f, in, msg := parseTenantForm(r)
	if msg != "" {
		s.renderTenants(w, r, http.StatusBadRequest, f, msg)
		return
	}
	ctx := r.Context()
	var t *store.Tenant
	err := store.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var err error
		if t, err = store.CreateTenant(ctx, tx, in); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{Actor: actor(sess), Request: auditReq(r), TenantID: &t.ID, Action: audit.TenantCreate,
			TargetType: "tenant", TargetID: t.ID.String(), Details: tenantAuditDetails(t)})
	})
	if errors.Is(err, store.ErrConflict) {
		s.renderTenants(w, r, http.StatusConflict, f, "A tenant with that name or external ID already exists.")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	redirect(w, r, "/tenants/"+t.ID.String()+"?msg=tenant_created")
}

func (s *Server) loadTenant(w http.ResponseWriter, r *http.Request) *store.Tenant {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return nil
	}
	t, err := store.GetTenant(r.Context(), s.DB, id)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return nil
	}
	if err != nil {
		s.serverError(w, r, err)
		return nil
	}
	return t
}

type agentsData struct {
	Agents       []store.Agent
	Now          time.Time
	OfflineAfter time.Duration
	RefreshURL   string
	Filter       store.AgentFilter
}

type tenantData struct {
	Tenant *store.Tenant
	Tab    string
	agentsData
	Tokens   []store.EnrollmentToken
	NewToken *newToken
	Form     tenantForm
}

func (s *Server) agentsFor(r *http.Request, t *store.Tenant) (agentsData, error) {
	q := r.URL.Query()
	f := store.AgentFilter{TenantID: t.ID, Query: strings.TrimSpace(q.Get("q")), Revoked: q.Get("revoked") == "1"}
	if st := q.Get("status"); st == "online" || st == "offline" {
		f.Status = st
	}
	if len(f.Query) > 100 {
		f.Query = f.Query[:100]
	}
	agents, err := store.ListAgents(r.Context(), s.DB, f, s.OfflineAfter)
	rq := url.Values{}
	for k, v := range map[string]string{"q": f.Query, "status": f.Status} {
		if v != "" {
			rq.Set(k, v)
		}
	}
	if f.Revoked {
		rq.Set("revoked", "1")
	}
	ref := "/tenants/" + t.ID.String() + "/agents"
	if len(rq) > 0 {
		ref += "?" + rq.Encode()
	}
	return agentsData{Agents: agents, Now: time.Now(), OfflineAfter: s.OfflineAfter, RefreshURL: ref, Filter: f}, err
}

func (s *Server) tenantEndpoints(w http.ResponseWriter, r *http.Request) {
	t := s.loadTenant(w, r)
	if t == nil {
		return
	}
	ad, err := s.agentsFor(r, t)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "tenant", page{Title: t.Name, Flash: flash(r), Data: tenantData{Tenant: t, Tab: "endpoints", agentsData: ad}})
}

// tenantAgentsFragment serves the auto-refreshing endpoints table.
func (s *Server) tenantAgentsFragment(w http.ResponseWriter, r *http.Request) {
	t := s.loadTenant(w, r)
	if t == nil {
		return
	}
	ad, err := s.agentsFor(r, t)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.renderFragment(w, "tenant", "agents_table", ad)
}

func (s *Server) tenantSettings(w http.ResponseWriter, r *http.Request) {
	t := s.loadTenant(w, r)
	if t == nil {
		return
	}
	s.render(w, r, http.StatusOK, "tenant", page{Title: t.Name, Flash: flash(r), Data: tenantData{Tenant: t, Tab: "settings", Form: formFromTenant(t)}})
}

func (s *Server) tenantUpdate(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFrom(r)
	t := s.loadTenant(w, r)
	if t == nil {
		return
	}
	f, in, msg := parseTenantForm(r)
	if msg != "" {
		s.render(w, r, http.StatusBadRequest, "tenant", page{Title: t.Name, Error: msg, Data: tenantData{Tenant: t, Tab: "settings", Form: f}})
		return
	}
	ctx := r.Context()
	err := store.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		updated, err := store.UpdateTenant(ctx, tx, t.ID, in)
		if err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{Actor: actor(sess), Request: auditReq(r), TenantID: &t.ID, Action: audit.TenantUpdate,
			TargetType: "tenant", TargetID: t.ID.String(), Details: map[string]any{"before": tenantAuditDetails(t), "after": tenantAuditDetails(updated)}})
	})
	if errors.Is(err, store.ErrConflict) {
		s.render(w, r, http.StatusConflict, "tenant", page{Title: t.Name, Error: "Another tenant already uses that name or external ID.", Data: tenantData{Tenant: t, Tab: "settings", Form: f}})
		return
	}
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	redirect(w, r, "/tenants/"+t.ID.String()+"/settings?msg=tenant_updated")
}

func (s *Server) tenantArchive(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFrom(r)
	t := s.loadTenant(w, r)
	if t == nil {
		return
	}
	ctx := r.Context()
	err := store.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if err := store.ArchiveTenant(ctx, tx, t.ID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{Actor: actor(sess), Request: auditReq(r), TenantID: &t.ID, Action: audit.TenantArchive,
			TargetType: "tenant", TargetID: t.ID.String(), Details: tenantAuditDetails(t)})
	})
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.serverError(w, r, err)
		return
	}
	redirect(w, r, "/tenants?msg=tenant_archived")
}

// ---- enrollment tokens ----

type newToken struct {
	Token    string
	Commands installCommands
}

func (s *Server) tokensData(r *http.Request, t *store.Tenant) (tenantData, error) {
	toks, err := store.ListEnrollmentTokens(r.Context(), s.DB, t.ID)
	d := tenantData{Tenant: t, Tab: "tokens", Tokens: toks}
	d.Now = time.Now()
	return d, err
}

func (s *Server) tenantTokens(w http.ResponseWriter, r *http.Request) {
	t := s.loadTenant(w, r)
	if t == nil {
		return
	}
	d, err := s.tokensData(r, t)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "tenant", page{Title: t.Name, Flash: flash(r), Data: d})
}

func (s *Server) tokenCreate(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFrom(r)
	t := s.loadTenant(w, r)
	if t == nil {
		return
	}
	bad := func(msg string) {
		d, err := s.tokensData(r, t)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		s.render(w, r, http.StatusBadRequest, "tenant", page{Title: t.Name, Error: msg, Data: d})
	}
	if t.ArchivedAt != nil {
		bad("This tenant is archived.")
		return
	}
	label := strings.TrimSpace(r.PostFormValue("label"))
	if label == "" || len(label) > 200 {
		bad("Label is required (max 200 characters).")
		return
	}
	days, err := strconv.Atoi(r.PostFormValue("expires_days"))
	if err != nil || days < 1 || days > 90 {
		bad("Validity must be 1 to 90 days.")
		return
	}
	var maxUses *int
	if v := strings.TrimSpace(r.PostFormValue("max_uses")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 100000 {
			bad("Max uses must be blank or 1 to 100000.")
			return
		}
		maxUses = &n
	}

	token := protocol.EnrollTokenPrefix + secret.Random(32)
	prefix := token[:len(protocol.EnrollTokenPrefix)+8]
	ctx := r.Context()
	err = store.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		tok, err := store.CreateEnrollmentToken(ctx, tx, t.ID, label, prefix, s.Hasher.Hash(token), time.Now().Add(time.Duration(days)*24*time.Hour), maxUses, sess.User.ID)
		if err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{Actor: actor(sess), Request: auditReq(r), TenantID: &t.ID, Action: audit.TokenCreate,
			TargetType: "enrollment_token", TargetID: tok.ID.String(),
			Details: map[string]any{"token_label": label, "token_prefix": prefix, "expires_days": days, "max_uses": maxUses}})
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d, err := s.tokensData(r, t)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	base := strings.TrimRight(s.PublicURL.String(), "/")
	ca, err := loadConsoleCA(s.DownloadsDir)
	var cmds installCommands
	if err != nil {
		s.Log.Error("cannot use the published console CA", "err", err)
		cmds.Problem = "The console CA published in the downloads directory is invalid (" + err.Error() + "), so no install commands can be generated. Fix it, then create a new token."
	} else {
		cmds = buildInstallCommands(base, token, ca)
	}
	d.NewToken = &newToken{Token: token, Commands: cmds}
	s.render(w, r, http.StatusOK, "tenant", page{Title: t.Name, Flash: "Enrollment token created.", Data: d})
}

func (s *Server) tokenRevoke(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFrom(r)
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	var tok *store.EnrollmentToken
	err := store.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var err error
		if tok, err = store.GetEnrollmentToken(ctx, tx, id); err != nil {
			return err
		}
		if err := store.RevokeEnrollmentToken(ctx, tx, id); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{Actor: actor(sess), Request: auditReq(r), TenantID: &tok.TenantID, Action: audit.TokenRevoke,
			TargetType: "enrollment_token", TargetID: id.String(), Details: map[string]any{"token_label": tok.Label, "token_prefix": tok.TokenPrefix}})
	})
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	redirect(w, r, "/tenants/"+tok.TenantID.String()+"/tokens?msg=token_revoked")
}

// ---- agents ----

func (s *Server) agentPage(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	a, err := store.GetAgent(r.Context(), s.DB, id)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.renderAgent(w, r, http.StatusOK, a, "")
}

type agentData struct {
	Agent        *store.Agent
	Events       []store.AgentEvent
	Actions      agentActionsData
	Choices      []actionChoice
	Now          time.Time
	OfflineAfter time.Duration
}

func (s *Server) renderAgent(w http.ResponseWriter, r *http.Request, status int, a *store.Agent, errMsg string) {
	events, err := store.ListAgentEvents(r.Context(), s.DB, a.ID, 50)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	acts, err := store.ListAgentActions(r.Context(), s.DB, a.ID, 20)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, status, "agent", page{Title: a.Hostname, Flash: flash(r), Error: errMsg, Data: agentData{
		Agent: a, Events: events, Actions: agentActionsData{AgentID: a.ID, Actions: acts}, Choices: actionChoices(),
		Now: time.Now(), OfflineAfter: s.OfflineAfter}})
}

func (s *Server) agentAction(w http.ResponseWriter, r *http.Request, action audit.Action, msg string,
	do func(tx pgx.Tx, a *store.Agent) error) {
	sess := auth.SessionFrom(r)
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	err := store.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		a, err := store.GetAgent(ctx, tx, id)
		if err != nil {
			return err
		}
		if err := do(tx, a); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{Actor: actor(sess), Request: auditReq(r), TenantID: &a.TenantID, Action: action,
			TargetType: "agent", TargetID: id.String(), Details: map[string]any{"hostname": a.Hostname}})
	})
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	redirect(w, r, "/agents/"+id.String()+"?msg="+msg)
}

func (s *Server) agentRevoke(w http.ResponseWriter, r *http.Request) {
	s.agentAction(w, r, audit.AgentRevoke, "agent_revoked", func(tx pgx.Tx, a *store.Agent) error {
		if err := store.RevokeAgent(r.Context(), tx, a.ID); err != nil {
			return err
		}
		return store.AddAgentEvent(r.Context(), tx, a.ID, a.TenantID, "revoked", map[string]any{"by": auth.SessionFrom(r).User.Email})
	})
}

func (s *Server) agentRotate(w http.ResponseWriter, r *http.Request) {
	s.agentAction(w, r, audit.AgentRotateRequest, "rotation_requested", func(tx pgx.Tx, a *store.Agent) error {
		return store.RequestRotation(r.Context(), tx, a.ID)
	})
}

// ---- audit ----

func (s *Server) auditPage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.AuditFilter{Action: strings.TrimSpace(q.Get("action")), Actor: strings.TrimSpace(q.Get("actor")), Limit: 100}
	tenantID := q.Get("tenant")
	if id, err := uuid.Parse(tenantID); err == nil {
		f.TenantID = &id
	} else {
		tenantID = ""
	}
	if b, err := strconv.ParseInt(q.Get("before"), 10, 64); err == nil && b > 0 {
		f.BeforeID = b
	}
	rows, err := store.ListAudit(r.Context(), s.DB, f)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	tenants, err := store.ListTenants(r.Context(), s.DB, s.OfflineAfter, true)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	next := ""
	if len(rows) == f.Limit {
		nq := url.Values{}
		for _, k := range []string{"action", "actor", "tenant"} {
			if v := q.Get(k); v != "" {
				nq.Set(k, v)
			}
		}
		nq.Set("before", strconv.FormatInt(rows[len(rows)-1].ID, 10))
		next = "/audit?" + nq.Encode()
	}
	s.render(w, r, http.StatusOK, "audit", page{Title: "Audit log", Data: struct {
		Rows     []store.AuditRow
		Tenants  []store.TenantSummary
		TenantID string
		Filter   store.AuditFilter
		NextURL  string
	}{rows, tenants, tenantID, f, next}})
}

// ---- users ----

type userForm struct{ Email, DisplayName string }

var reEmail = regexp.MustCompile(`^[^@\s]{1,64}@[^@\s]{1,189}$`)

func (s *Server) renderUsers(w http.ResponseWriter, r *http.Request, status int, f userForm, errMsg string) {
	users, err := store.ListUsers(r.Context(), s.DB)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, status, "users", page{Title: "Users", Flash: flash(r), Error: errMsg, Data: struct {
		Users []store.User
		Form  userForm
	}{users, f}})
}

func (s *Server) usersPage(w http.ResponseWriter, r *http.Request) {
	s.renderUsers(w, r, http.StatusOK, userForm{}, "")
}

func (s *Server) userCreate(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFrom(r)
	f := userForm{Email: strings.TrimSpace(r.PostFormValue("email")), DisplayName: strings.TrimSpace(r.PostFormValue("display_name"))}
	pw := r.PostFormValue("password")
	if !reEmail.MatchString(f.Email) {
		s.renderUsers(w, r, http.StatusBadRequest, f, "Enter a valid email address.")
		return
	}
	if len(f.DisplayName) > 200 {
		s.renderUsers(w, r, http.StatusBadRequest, f, "Name is too long.")
		return
	}
	if err := auth.ValidatePassword(pw, f.Email); err != nil {
		s.renderUsers(w, r, http.StatusBadRequest, f, "Password: "+err.Error()+".")
		return
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	ctx := r.Context()
	err = store.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		u, err := store.CreateUser(ctx, tx, f.Email, f.DisplayName, hash)
		if err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{Actor: actor(sess), Request: auditReq(r), Action: audit.UserCreate,
			TargetType: "user", TargetID: u.ID.String(), Details: map[string]any{"email": u.Email}})
	})
	if errors.Is(err, store.ErrConflict) {
		s.renderUsers(w, r, http.StatusConflict, f, "A user with that email already exists.")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	redirect(w, r, "/users?msg=user_created")
}

func (s *Server) userDisable(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFrom(r)
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if id == sess.User.ID {
		http.Error(w, "you cannot disable your own account", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	err := store.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		u, err := store.GetUser(ctx, tx, id)
		if err != nil {
			return err
		}
		if err := store.DisableUser(ctx, tx, id); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{Actor: actor(sess), Request: auditReq(r), Action: audit.UserDisable,
			TargetType: "user", TargetID: id.String(), Details: map[string]any{"email": u.Email}})
	})
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	redirect(w, r, "/users?msg=user_disabled")
}

// ---- account ----

func (s *Server) accountPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "account", page{Title: "Account", Flash: flash(r)})
}

func (s *Server) passwordChange(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFrom(r)
	cur, nw, conf := r.PostFormValue("current"), r.PostFormValue("new"), r.PostFormValue("confirm")
	fail := func(msg string) {
		s.render(w, r, http.StatusBadRequest, "account", page{Title: "Account", Error: msg})
	}
	if !auth.CheckPassword(cur, sess.User.PasswordHash) {
		_ = audit.Write(r.Context(), s.DB, audit.Entry{Actor: actor(sess), Request: auditReq(r), Action: audit.PasswordChange,
			Outcome: audit.Denied, TargetType: "user", TargetID: sess.User.ID.String(), Details: map[string]any{"reason": "wrong_current"}})
		fail("Current password is incorrect.")
		return
	}
	if nw != conf {
		fail("New passwords do not match.")
		return
	}
	if err := auth.ValidatePassword(nw, sess.User.Email); err != nil {
		fail("New password: " + err.Error() + ".")
		return
	}
	hash, err := auth.HashPassword(nw)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	ctx := r.Context()
	err = store.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if err := store.SetPassword(ctx, tx, sess.User.ID, hash); err != nil {
			return err
		}
		if err := store.RevokeOtherSessions(ctx, tx, sess.User.ID, sess.ID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{Actor: actor(sess), Request: auditReq(r), Action: audit.PasswordChange,
			TargetType: "user", TargetID: sess.User.ID.String()})
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	redirect(w, r, "/account?msg=password_changed")
}
