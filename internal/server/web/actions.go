package web

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Soup9x/Lake-Effect-Buoy/internal/protocol"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/server/audit"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/server/auth"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/server/store"
)

// Agent actions from the console: a fixed menu of allowlisted ClamAV
// operations (CLAUDE.md rule 1), queued for one endpoint or a batch, with
// their results and exports. Every queue and cancel is audited (rule 2).

// actionLabels are the menu entries, in display order.
var actionLabels = map[protocol.ActionType]string{
	protocol.ActionClamdCheck:  "Check clamd",
	protocol.ActionClamdReload: "Reload signatures",
	protocol.ActionClamdStats:  "clamd stats",
	protocol.ActionScanPath:    "Scan a folder",
}

type actionChoice struct {
	Type  protocol.ActionType
	Label string
}

func actionChoices() []actionChoice {
	out := make([]actionChoice, 0, len(protocol.ActionTypes))
	for _, t := range protocol.ActionTypes {
		out = append(out, actionChoice{t, actionLabels[t]})
	}
	return out
}

func actionLabel(t string) string {
	if l, ok := actionLabels[protocol.ActionType(t)]; ok {
		return l
	}
	return t
}

// maxBatch caps the endpoints in one job.
const maxBatch = 2000

// actionRequest validates the action part of a form and returns its type and
// canonical params, or a message for the user.
func actionRequest(r *http.Request) (protocol.ActionType, json.RawMessage, string) {
	typ := protocol.ActionType(r.PostFormValue("type"))
	if !protocol.IsAllowed(typ) {
		return "", nil, "Choose an action."
	}
	var params any = struct{}{}
	if typ == protocol.ActionScanPath {
		path := strings.TrimSpace(r.PostFormValue("path"))
		if err := protocol.ValidateScanPath(path); err != nil {
			return "", nil, "Folder to scan: " + err.Error() + "."
		}
		params = protocol.ScanPathParams{Path: path}
	}
	raw, _ := json.Marshal(params)
	// Belt and braces: exactly what the agent will decode.
	if _, err := protocol.DecodeParams(protocol.Action{Type: typ, Params: raw}); err != nil {
		return "", nil, "Invalid action: " + err.Error()
	}
	return typ, raw, ""
}

// queueJob creates a job and its audit entry in one transaction.
func (s *Server) queueJob(r *http.Request, tenantID uuid.UUID, typ protocol.ActionType, params json.RawMessage, agentIDs []uuid.UUID, scope string) (uuid.UUID, int, error) {
	sess := auth.SessionFrom(r)
	ctx := r.Context()
	var jobID uuid.UUID
	var n int
	err := store.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var err error
		jobID, n, err = store.CreateJob(ctx, tx, tenantID, string(typ), params, sess.User.ID, agentIDs)
		if err != nil {
			return err
		}
		if n == 0 {
			return errNoTargets
		}
		return audit.Write(ctx, tx, audit.Entry{Actor: actor(sess), Request: auditReq(r), TenantID: &tenantID, Action: audit.ActionQueue,
			TargetType: "action_job", TargetID: jobID.String(),
			Details: map[string]any{"type": string(typ), "params": params, "endpoints": n, "scope": scope}})
	})
	return jobID, n, err
}

var errNoTargets = errors.New("no endpoints")

// actionRefused audits a queue request that was turned down (CLAUDE.md
// rule 2: denied attempts are audited too). The requested type and path are
// recorded, clipped, so probing for other action types shows up in the log.
func (s *Server) actionRefused(r *http.Request, tenantID uuid.UUID, target, targetID, reason string) {
	if err := audit.Write(r.Context(), s.DB, audit.Entry{Actor: actor(auth.SessionFrom(r)), Request: auditReq(r), TenantID: &tenantID,
		Action: audit.ActionQueue, Outcome: audit.Denied, TargetType: target, TargetID: targetID,
		Details: map[string]any{"reason": reason, "type": clip(r.PostFormValue("type"), 64), "path": clip(r.PostFormValue("path"), 1024)}}); err != nil {
		s.Log.Error("audit write failed", "err", err)
	}
}

func clip(s string, n int) string {
	if len(s) > n {
		s = s[:n]
	}
	return strings.ToValidUTF8(s, "")
}

// agentActionCreate queues an action for one endpoint (endpoint page).
func (s *Server) agentActionCreate(w http.ResponseWriter, r *http.Request) {
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
	typ, params, msg := actionRequest(r)
	if msg == "" && a.RevokedAt != nil {
		msg = "This endpoint is revoked."
	}
	if msg == "" {
		var jobID uuid.UUID
		jobID, _, err = s.queueJob(r, a.TenantID, typ, params, []uuid.UUID{a.ID}, "endpoint")
		if err == nil {
			redirect(w, r, "/jobs/"+jobID.String())
			return
		}
		if errors.Is(err, errNoTargets) {
			msg = "This endpoint cannot take actions."
		}
	}
	if msg != "" {
		s.actionRefused(r, a.TenantID, "agent", a.ID.String(), msg)
		s.renderAgent(w, r, http.StatusBadRequest, a, msg)
		return
	}
	s.serverError(w, r, err)
}

// ---- batch ----

type runData struct {
	Tenant       *store.Tenant
	Agents       []store.Agent
	Choices      []actionChoice
	Now          time.Time
	OfflineAfter time.Duration
	Form         runForm
}

type runForm struct {
	Type     string
	Path     string
	Target   string
	Selected map[string]bool
}

func (s *Server) runPage(w http.ResponseWriter, r *http.Request) {
	t := s.loadTenant(w, r)
	if t == nil {
		return
	}
	s.renderRun(w, r, http.StatusOK, t, runForm{Target: "online"}, "")
}

func (s *Server) renderRun(w http.ResponseWriter, r *http.Request, status int, t *store.Tenant, f runForm, errMsg string) {
	agents, err := store.ListAgents(r.Context(), s.DB, store.AgentFilter{TenantID: t.ID}, s.OfflineAfter)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, status, "run", page{Title: "Run action · " + t.Name, Error: errMsg, Data: runData{
		Tenant: t, Agents: agents, Choices: actionChoices(), Now: time.Now(), OfflineAfter: s.OfflineAfter, Form: f}})
}

func (s *Server) jobCreate(w http.ResponseWriter, r *http.Request) {
	t := s.loadTenant(w, r)
	if t == nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	f := runForm{Type: r.PostFormValue("type"), Path: r.PostFormValue("path"), Target: r.PostFormValue("target"), Selected: map[string]bool{}}
	for _, v := range r.PostForm["agent_id"] {
		f.Selected[v] = true
	}
	refuse := func(msg string) {
		s.actionRefused(r, t.ID, "tenant", t.ID.String(), msg)
		s.renderRun(w, r, http.StatusBadRequest, t, f, msg)
	}
	if t.ArchivedAt != nil {
		refuse("This tenant is archived.")
		return
	}
	typ, params, msg := actionRequest(r)
	if msg != "" {
		refuse(msg)
		return
	}
	var ids []uuid.UUID
	switch f.Target {
	case "all", "online":
		filter := store.AgentFilter{TenantID: t.ID}
		if f.Target == "online" {
			filter.Status = "online"
		}
		agents, err := store.ListAgents(r.Context(), s.DB, filter, s.OfflineAfter)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		for _, a := range agents {
			ids = append(ids, a.ID)
		}
	case "selected":
		for v := range f.Selected {
			id, err := uuid.Parse(v)
			if err != nil {
				refuse("Invalid endpoint selection.")
				return
			}
			ids = append(ids, id)
		}
	default:
		refuse("Choose which endpoints to run it on.")
		return
	}
	if len(ids) > maxBatch {
		refuse(fmt.Sprintf("At most %d endpoints per batch.", maxBatch))
		return
	}
	jobID, _, err := s.queueJob(r, t.ID, typ, params, ids, f.Target)
	if errors.Is(err, errNoTargets) {
		refuse("No endpoints to run it on (none selected, or none online).")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	redirect(w, r, "/jobs/"+jobID.String())
}

// ---- job, action and list pages ----

type jobData struct {
	Job     *store.Job
	Label   string
	Path    string
	Actions []store.AgentAction
}

func (s *Server) loadJob(w http.ResponseWriter, r *http.Request) (*jobData, bool) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return nil, false
	}
	j, err := store.GetJob(r.Context(), s.DB, id)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return nil, false
	}
	if err != nil {
		s.serverError(w, r, err)
		return nil, false
	}
	acts, err := store.ListJobActions(r.Context(), s.DB, id)
	if err != nil {
		s.serverError(w, r, err)
		return nil, false
	}
	return &jobData{Job: j, Label: actionLabel(j.Type), Path: paramPath(j.Params), Actions: acts}, true
}

func (s *Server) jobPage(w http.ResponseWriter, r *http.Request) {
	d, ok := s.loadJob(w, r)
	if !ok {
		return
	}
	s.render(w, r, http.StatusOK, "job", page{Title: d.Label + " · " + d.Job.TenantName, Flash: flash(r), Data: d})
}

// jobRows is the auto-refreshing part of the job page.
func (s *Server) jobRows(w http.ResponseWriter, r *http.Request) {
	d, ok := s.loadJob(w, r)
	if !ok {
		return
	}
	s.renderFragment(w, "job", "job_results", d)
}

func (s *Server) jobCancel(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFrom(r)
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	err := store.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		j, err := store.GetJob(ctx, tx, id)
		if err != nil {
			return err
		}
		n, err := store.CancelQueued(ctx, tx, id, nil)
		if err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{Actor: actor(sess), Request: auditReq(r), TenantID: &j.TenantID, Action: audit.ActionCancel,
			TargetType: "action_job", TargetID: id.String(), Details: map[string]any{"type": j.Type, "cancelled": n}})
	})
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	redirect(w, r, "/jobs/"+id.String()+"?msg=job_cancelled")
}

func (s *Server) jobsPage(w http.ResponseWriter, r *http.Request) {
	jobs, err := store.ListJobs(r.Context(), s.DB, nil, 200)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "jobs", page{Title: "Actions", Data: jobs})
}

type actionData struct {
	Action *store.AgentAction
	Label  string
	Path   string
	Scan   *protocol.ScanResult
	Check  *protocol.ClamAVStatus
}

func (s *Server) actionPage(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	a, err := store.GetAction(r.Context(), s.DB, id)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d := actionData{Action: a, Label: actionLabel(a.Type), Path: paramPath(a.Params)}
	if len(a.Data) > 0 {
		switch protocol.ActionType(a.Type) {
		case protocol.ActionScanPath:
			var sr protocol.ScanResult
			if json.Unmarshal(a.Data, &sr) == nil {
				d.Scan = &sr
			}
		case protocol.ActionClamdCheck:
			var st protocol.ClamAVStatus
			if json.Unmarshal(a.Data, &st) == nil {
				d.Check = &st
			}
		}
	}
	s.render(w, r, http.StatusOK, "action", page{Title: d.Label + " · " + a.Hostname, Data: d})
}

// agentActionRows is the auto-refreshing action history on the endpoint page.
func (s *Server) agentActionRows(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	acts, err := store.ListAgentActions(r.Context(), s.DB, id, 20)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.renderFragment(w, "agent", "agent_actions", agentActionsData{AgentID: id, Actions: acts})
}

type agentActionsData struct {
	AgentID uuid.UUID
	Actions []store.AgentAction
}

// AnyOpen reports whether the history still has actions without a result.
func (d agentActionsData) AnyOpen() bool {
	for _, a := range d.Actions {
		if a.Open() {
			return true
		}
	}
	return false
}

// ---- helpers used by templates and exports ----

func paramPath(params json.RawMessage) string {
	var p protocol.ScanPathParams
	if json.Unmarshal(params, &p) == nil {
		return p.Path
	}
	return ""
}

// actionSummary is the one-line result shown in tables and exports.
func actionSummary(a store.AgentAction) string {
	switch a.Status {
	case store.ActionQueued:
		return "waiting for the endpoint to check in"
	case store.ActionSent:
		if a.Type == string(protocol.ActionScanPath) {
			return "scanning"
		}
		return "sent, waiting for the result"
	}
	if a.Type == string(protocol.ActionScanPath) && len(a.Data) > 0 {
		var sr protocol.ScanResult
		if json.Unmarshal(a.Data, &sr) == nil {
			s := fmt.Sprintf("%d infected, %d not scanned", sr.InfectedTotal, sr.ErrorsTotal)
			if a.Error != "" {
				s += "; " + a.Error
			}
			return s
		}
	}
	if a.Error != "" {
		return a.Error
	}
	if a.Type == string(protocol.ActionClamdStats) {
		return "see output"
	}
	line, _, _ := strings.Cut(a.Output, "\n")
	return line
}

func statusClass(status string) string {
	switch status {
	case store.ActionDone:
		return "ok"
	case store.ActionFailed, store.ActionRejected, store.ActionExpired:
		return "bad"
	}
	return "muted"
}

// scanInfected returns the infected count of a scan action (0 otherwise).
func scanInfected(a store.AgentAction) int {
	if a.Type != string(protocol.ActionScanPath) || len(a.Data) == 0 {
		return 0
	}
	var sr protocol.ScanResult
	if json.Unmarshal(a.Data, &sr) != nil {
		return 0
	}
	return sr.InfectedTotal
}

// ---- exports ----

// csvSafe neutralises cells a spreadsheet would treat as a formula. Agent
// output and file names are untrusted: "=HYPERLINK(...)" in a file name must
// stay text.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func writeCSV(w http.ResponseWriter, filename string, header []string, rows [][]string) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Cache-Control", "no-store")
	cw := csv.NewWriter(w)
	_ = cw.Write(header)
	for _, row := range rows {
		for i := range row {
			row[i] = csvSafe(row[i])
		}
		_ = cw.Write(row)
	}
	cw.Flush()
}

func writeJSONFile(w http.ResponseWriter, filename string, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func fmtOpt(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

var actionCSVHeader = []string{"job_id", "action_id", "tenant", "endpoint", "action", "path", "status", "summary",
	"infected_total", "not_scanned_total", "error", "queued_at", "sent_at", "started_at", "finished_at", "output"}

func actionCSVRow(a store.AgentAction) []string {
	infected, notScanned := "", ""
	if a.Type == string(protocol.ActionScanPath) && len(a.Data) > 0 {
		var sr protocol.ScanResult
		if json.Unmarshal(a.Data, &sr) == nil {
			infected, notScanned = fmt.Sprint(sr.InfectedTotal), fmt.Sprint(sr.ErrorsTotal)
		}
	}
	return []string{a.JobID.String(), a.ID.String(), a.TenantName, a.Hostname, actionLabel(a.Type), paramPath(a.Params), a.Status,
		actionSummary(a), infected, notScanned, a.Error, a.CreatedAt.UTC().Format(time.RFC3339), fmtOpt(a.SentAt),
		fmtOpt(a.StartedAt), fmtOpt(a.FinishedAt), a.Output}
}

// exportAction is the JSON export shape of one action.
type exportAction struct {
	ID         uuid.UUID       `json:"id"`
	JobID      uuid.UUID       `json:"job_id"`
	Tenant     string          `json:"tenant"`
	Endpoint   string          `json:"endpoint"`
	AgentID    uuid.UUID       `json:"agent_id"`
	Type       string          `json:"type"`
	Params     json.RawMessage `json:"params"`
	Status     string          `json:"status"`
	Summary    string          `json:"summary"`
	QueuedAt   time.Time       `json:"queued_at"`
	SentAt     *time.Time      `json:"sent_at"`
	StartedAt  *time.Time      `json:"started_at"`
	FinishedAt *time.Time      `json:"finished_at"`
	Output     string          `json:"output"`
	Data       json.RawMessage `json:"data,omitempty"`
	Error      string          `json:"error"`
}

func toExport(acts []store.AgentAction) []exportAction {
	out := make([]exportAction, 0, len(acts))
	for _, a := range acts {
		out = append(out, exportAction{ID: a.ID, JobID: a.JobID, Tenant: a.TenantName, Endpoint: a.Hostname, AgentID: a.AgentID,
			Type: a.Type, Params: a.Params, Status: a.Status, Summary: actionSummary(a), QueuedAt: a.CreatedAt, SentAt: a.SentAt,
			StartedAt: a.StartedAt, FinishedAt: a.FinishedAt, Output: a.Output, Data: a.Data, Error: a.Error})
	}
	return out
}

func shortID(id uuid.UUID) string { return strings.ReplaceAll(id.String(), "-", "")[:12] }

// jobExport serves /jobs/{id}/export.{csv,json} and /jobs/{id}/infections.csv.
func (s *Server) jobExport(format string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		d, ok := s.loadJob(w, r)
		if !ok {
			return
		}
		name := "buoy-job-" + shortID(d.Job.ID)
		switch format {
		case "csv":
			rows := make([][]string, 0, len(d.Actions))
			for _, a := range d.Actions {
				rows = append(rows, actionCSVRow(a))
			}
			writeCSV(w, name+".csv", actionCSVHeader, rows)
		case "infections":
			var rows [][]string
			for _, a := range d.Actions {
				var sr protocol.ScanResult
				if a.Type != string(protocol.ActionScanPath) || json.Unmarshal(a.Data, &sr) != nil {
					continue
				}
				for _, in := range sr.Infected {
					rows = append(rows, []string{a.TenantName, a.Hostname, in.Path, in.Signature, fmtOpt(a.FinishedAt), a.ID.String()})
				}
			}
			writeCSV(w, name+"-infections.csv", []string{"tenant", "endpoint", "file", "signature", "scan_finished_at", "action_id"}, rows)
		default:
			writeJSONFile(w, name+".json", struct {
				Job     any            `json:"job"`
				Actions []exportAction `json:"actions"`
			}{map[string]any{"id": d.Job.ID, "tenant": d.Job.TenantName, "type": d.Job.Type, "params": d.Job.Params,
				"queued_by": d.Job.CreatorEmail, "queued_at": d.Job.CreatedAt}, toExport(d.Actions)})
		}
	}
}

// agentActionsExport serves /agents/{id}/actions/export.{csv,json}.
func (s *Server) agentActionsExport(format string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathID(r)
		if !ok {
			http.NotFound(w, r)
			return
		}
		acts, err := store.ListAgentActions(r.Context(), s.DB, id, 1000)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		name := "buoy-endpoint-" + shortID(id) + "-actions"
		if format == "csv" {
			rows := make([][]string, 0, len(acts))
			for _, a := range acts {
				rows = append(rows, actionCSVRow(a))
			}
			writeCSV(w, name+".csv", actionCSVHeader, rows)
			return
		}
		writeJSONFile(w, name+".json", toExport(acts))
	}
}
