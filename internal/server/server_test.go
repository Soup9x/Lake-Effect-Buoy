package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"html"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Soup9x/Lake-Effect-Buoy/internal/protocol"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/server/auth"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/server/config"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/server/store"
)

// Integration tests need TEST_DATABASE_URL pointing at a Postgres role that
// may CREATE DATABASE. Each run uses a fresh throwaway database.
func testDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "cav_test_" + hex.EncodeToString(b)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)")
		_ = admin.Close(context.Background())
	})
	u, _ := url.Parse(base)
	u.Path = "/" + name
	if err := Migrate(ctx, u.String()); err != nil {
		t.Fatal(err)
	}
	pool, err := store.Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

type env struct {
	t         *testing.T
	pool      *pgxpool.Pool
	srv       *httptest.Server
	client    *http.Client
	csrf      string
	downloads string
}

func setup(t *testing.T, allowed string) *env {
	pool := testDB(t)
	pu, _ := url.Parse("https://console.example.test")
	cfg := &config.Config{
		PublicURL: pu, TokenHashKey: bytes.Repeat([]byte("k"), 32), AgentOfflineAfter: 3 * time.Minute,
		DownloadsDir: t.TempDir(), AdminAllowedCIDRs: []netip.Prefix{netip.MustParsePrefix(allowed)},
		SessionIdleTimeout: 30 * time.Minute, SessionAbsoluteTimeout: 12 * time.Hour,
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httptest.NewServer(Handler(cfg, pool, log))
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	return &env{t: t, pool: pool, srv: srv, client: &http.Client{Jar: jar}, downloads: cfg.DownloadsDir}
}

func (e *env) do(method, path string, body io.Reader, hdr map[string]string) (int, string) {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.srv.URL+path, body)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (e *env) form(path string, v url.Values) (int, string) {
	if v.Get("csrf_token") == "" && e.csrf != "" {
		v.Set("csrf_token", e.csrf)
	}
	return e.do("POST", path, strings.NewReader(v.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
}

func (e *env) login() {
	e.t.Helper()
	hash, _ := auth.HashPassword("correct horse battery staple")
	if _, err := store.CreateUser(context.Background(), e.pool, "admin@example.test", "Admin", hash); err != nil {
		e.t.Fatal(err)
	}
	code, body := e.form("/login", url.Values{"email": {"admin@example.test"}, "password": {"correct horse battery staple"}})
	if code != 200 || !strings.Contains(body, "Tenants") {
		e.t.Fatalf("login failed: %d", code)
	}
	e.csrf = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`).FindStringSubmatch(body)[1]
}

func (e *env) agentCall(path string, body any, cred string) (int, map[string]any) {
	e.t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", e.srv.URL+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if cred != "" {
		req.Header.Set("Authorization", "Bearer "+cred)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func errCode(m map[string]any) string {
	e, _ := m["error"].(map[string]any)
	s, _ := e["code"].(string)
	return s
}

// enrollAgent creates a tenant and token via the UI and enrolls one agent.
func (e *env) enrollAgent() (tenantID, credential string) {
	e.t.Helper()
	_, body := e.form("/tenants", url.Values{"name": {"Acme"}})
	tenantID = regexp.MustCompile(`/tenants/([0-9a-f-]{36})/tokens`).FindStringSubmatch(body)[1]
	_, body = e.form("/tenants/"+tenantID+"/tokens", url.Values{"label": {"t"}, "expires_days": {"1"}})
	tok := regexp.MustCompile(`cav_enr_[a-z0-9]+`).FindString(body)
	code, resp := e.agentCall(protocol.PathEnroll, protocol.EnrollRequest{EnrollmentToken: tok, MachineID: "m1", Hostname: "host1",
		OSFamily: "linux", OSName: "Debian 12", OSVersion: "6.1", Arch: "amd64", AgentVersion: "0.1.0"}, "")
	if code != 201 {
		e.t.Fatalf("enroll: %d %v", code, resp)
	}
	return tenantID, resp["credential"].(string)
}

var hb = protocol.HeartbeatRequest{Hostname: "host1", OSName: "Debian 12", OSVersion: "6.1", AgentVersion: "0.1.0",
	ClamAV: protocol.ClamAVStatus{Status: protocol.ClamdRunning, EngineVersion: "1.4.1", SignatureVersion: 27410}}

func TestAgentRevokedOnlyForValidCredential(t *testing.T) {
	e := setup(t, "127.0.0.0/8")
	e.login()
	_, cred := e.enrollAgent()
	if code, _ := e.agentCall(protocol.PathHeartbeat, hb, cred); code != 200 {
		t.Fatalf("heartbeat: %d", code)
	}
	if code, m := e.agentCall(protocol.PathHeartbeat, hb, cred+"x"); code != 401 || errCode(m) != protocol.ErrUnauthorized {
		t.Fatalf("tampered credential: %d %v", code, m)
	}
	if code, m := e.agentCall(protocol.PathHeartbeat, hb, ""); code != 401 || errCode(m) != protocol.ErrUnauthorized {
		t.Fatalf("missing credential: %d %v", code, m)
	}
	id := strings.SplitN(strings.TrimPrefix(cred, protocol.CredentialPrefix), ".", 2)[0]
	if code, _ := e.form("/agents/"+id+"/revoke", url.Values{}); code != 200 {
		t.Fatalf("revoke: %d", code)
	}
	if code, m := e.agentCall(protocol.PathHeartbeat, hb, cred); code != 401 || errCode(m) != protocol.ErrAgentRevoked {
		t.Fatalf("revoked: %d %v", code, m)
	}
	// A wrong secret for a revoked agent must not reveal revocation.
	if code, m := e.agentCall(protocol.PathHeartbeat, hb, cred+"x"); code != 401 || errCode(m) != protocol.ErrUnauthorized {
		t.Fatalf("tampered credential for revoked agent: %d %v", code, m)
	}
}

func TestArchivedTenantRevokesAgents(t *testing.T) {
	e := setup(t, "127.0.0.0/8")
	e.login()
	tenantID, cred := e.enrollAgent()
	if code, _ := e.form("/tenants/"+tenantID+"/archive", url.Values{}); code != 200 {
		t.Fatalf("archive: %d", code)
	}
	if code, m := e.agentCall(protocol.PathHeartbeat, hb, cred); code != 401 || errCode(m) != protocol.ErrAgentRevoked {
		t.Fatalf("archived tenant: %d %v", code, m)
	}
}

func TestAdminRoutesRestrictedByCIDR(t *testing.T) {
	e := setup(t, "10.0.0.0/8") // test client is 127.0.0.1, outside the allowlist
	for _, p := range []string{"/login", "/tenants", "/readyz", "/static/app.css"} {
		if code, _ := e.do("GET", p, nil, nil); code != 404 {
			t.Errorf("%s from disallowed IP: got %d, want 404", p, code)
		}
	}
	if code, _ := e.do("GET", "/healthz", nil, nil); code != 200 {
		t.Errorf("/healthz should be public, got %d", code)
	}
	if code, m := e.agentCall(protocol.PathEnroll, map[string]string{}, ""); code != 400 {
		t.Errorf("enroll should be public, got %d %v", code, m)
	}
	if code, _ := e.do("GET", "/downloads/missing", nil, nil); code != 404 {
		t.Errorf("downloads: got %d", code)
	}
}

func TestBackgroundRefreshDoesNotExtendSession(t *testing.T) {
	e := setup(t, "127.0.0.0/8")
	e.login()
	tenantID, _ := e.enrollAgent()
	ctx := context.Background()
	old := time.Now().Add(-20 * time.Minute).UTC().Truncate(time.Second)
	if _, err := e.pool.Exec(ctx, `UPDATE sessions SET last_seen_at=$1`, old); err != nil {
		t.Fatal(err)
	}
	lastSeen := func() time.Time {
		var ts time.Time
		if err := e.pool.QueryRow(ctx, `SELECT last_seen_at FROM sessions WHERE revoked_at IS NULL`).Scan(&ts); err != nil {
			t.Fatal(err)
		}
		return ts.UTC()
	}
	bg := map[string]string{auth.BackgroundHeader: "1", "HX-Request": "true"}
	if code, body := e.do("GET", "/tenants/"+tenantID+"/agents", nil, bg); code != 200 || !strings.Contains(body, "host1") {
		t.Fatalf("background refresh: %d", code)
	}
	if got := lastSeen(); !got.Equal(old) {
		t.Fatalf("background refresh moved last_seen_at from %v to %v", old, got)
	}
	e.do("GET", "/tenants/"+tenantID, nil, nil)
	if got := lastSeen(); !got.After(old) {
		t.Fatalf("foreground request did not extend session")
	}

	// Past the idle timeout, a background refresh is sent to the login page.
	if _, err := e.pool.Exec(ctx, `UPDATE sessions SET last_seen_at=now() - interval '31 minutes'`); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", e.srv.URL+"/tenants/"+tenantID+"/agents", nil)
	for k, v := range bg {
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.Header.Get("HX-Redirect") != "/login" {
		t.Fatalf("expired session: want HX-Redirect /login, got %q (%d)", resp.Header.Get("HX-Redirect"), resp.StatusCode)
	}
}

func TestCSRFAndAuditAppendOnly(t *testing.T) {
	e := setup(t, "127.0.0.0/8")
	e.login()
	code, _ := e.form("/tenants", url.Values{"name": {"X"}, "csrf_token": {"wrong"}})
	if code != 403 {
		t.Fatalf("bad CSRF: got %d", code)
	}
	ctx := context.Background()
	var denied int
	_ = e.pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action='access.denied'`).Scan(&denied)
	if denied != 1 {
		t.Fatalf("access.denied entries: %d", denied)
	}
	if _, err := e.pool.Exec(ctx, `UPDATE audit_log SET action='x'`); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("update audit_log: %v", err)
	}
	if _, err := e.pool.Exec(ctx, `DELETE FROM audit_log`); err == nil {
		t.Fatal("delete audit_log succeeded")
	}
	if _, err := e.pool.Exec(ctx, `TRUNCATE audit_log`); err == nil {
		t.Fatal("truncate audit_log succeeded")
	}
}

func TestLockout(t *testing.T) {
	e := setup(t, "127.0.0.0/8")
	e.login()
	jar, _ := cookiejar.New(nil)
	e.client = &http.Client{Jar: jar}
	// Nine earlier failures; the tenth locks the account.
	if _, err := e.pool.Exec(context.Background(), `UPDATE users SET failed_login_count=9`); err != nil {
		t.Fatal(err)
	}
	e.form("/login", url.Values{"email": {"admin@example.test"}, "password": {"wrong-password-123"}})
	code, body := e.form("/login", url.Values{"email": {"admin@example.test"}, "password": {"correct horse battery staple"}})
	if code != 401 || !strings.Contains(body, "locked") {
		t.Fatalf("expected lockout, got %d", code)
	}

	// After the lock expires, one wrong password must not lock the account
	// again: the count starts over.
	ctx := context.Background()
	if _, err := e.pool.Exec(ctx, `UPDATE users SET locked_until=now() - interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	e.form("/login", url.Values{"email": {"admin@example.test"}, "password": {"wrong-password-123"}})
	var count int
	var lockedUntil *time.Time
	if err := e.pool.QueryRow(ctx, `SELECT failed_login_count, locked_until FROM users`).Scan(&count, &lockedUntil); err != nil {
		t.Fatal(err)
	}
	if count != 1 || lockedUntil != nil {
		t.Fatalf("after expired lock: failed_login_count=%d locked_until=%v, want 1 and NULL", count, lockedUntil)
	}
	code, body = e.form("/login", url.Values{"email": {"admin@example.test"}, "password": {"correct horse battery staple"}})
	if code != 200 || !strings.Contains(body, "Tenants") {
		t.Fatalf("login after expired lock: got %d", code)
	}
}

func TestRotationSurvivesLostResponse(t *testing.T) {
	e := setup(t, "127.0.0.0/8")
	e.login()
	_, old := e.enrollAgent()
	id := strings.SplitN(strings.TrimPrefix(old, protocol.CredentialPrefix), ".", 2)[0]
	heartbeat := func(cred string) (int, bool) {
		t.Helper()
		code, m := e.agentCall(protocol.PathHeartbeat, hb, cred)
		rotate, _ := m["rotate_credential"].(bool)
		return code, rotate
	}
	rotate := func(cred string) string {
		t.Helper()
		code, m := e.agentCall(protocol.PathRotate, struct{}{}, cred)
		if code != 200 {
			t.Fatalf("rotate: %d %v", code, m)
		}
		return m["credential"].(string)
	}

	if code, _ := e.form("/agents/"+id+"/rotate", url.Values{}); code != 200 {
		t.Fatalf("request rotation: %d", code)
	}
	if code, r := heartbeat(old); code != 200 || !r {
		t.Fatalf("heartbeat after request: %d rotate=%v", code, r)
	}

	// The agent never receives (or fails to save) the first new credential.
	lost := rotate(old)
	if code, r := heartbeat(old); code != 200 || !r {
		t.Fatalf("heartbeat on old credential after lost rotation: %d rotate=%v, want 200 and rotate", code, r)
	}
	// It retries with the credential it still holds; the lost one is dropped.
	got := rotate(old)
	if code, _ := heartbeat(lost); code != 401 {
		t.Fatalf("discarded credential: got %d, want 401", code)
	}
	if code, r := heartbeat(old); code != 200 || !r {
		t.Fatalf("old credential during grace after retry: %d rotate=%v", code, r)
	}

	// First use of the new credential completes the rotation.
	if code, r := heartbeat(got); code != 200 || r {
		t.Fatalf("heartbeat on new credential: %d rotate=%v, want 200 and no rotate", code, r)
	}
	if code, _ := heartbeat(old); code != 401 {
		t.Fatalf("old credential after confirmation: got %d, want 401", code)
	}

	// A rotation requested while another is unconfirmed is not lost.
	next := rotate(got)
	if code, _ := e.form("/agents/"+id+"/rotate", url.Values{}); code != 200 {
		t.Fatalf("request rotation: %d", code)
	}
	if code, r := heartbeat(next); code != 200 || !r {
		t.Fatalf("heartbeat after mid-rotation request: %d rotate=%v, want rotate", code, r)
	}
}

// TestInstallCommandsPinPrivateCA: once a private CA is published in the
// downloads directory, new tokens come with commands that pin it.
func TestInstallCommandsPinPrivateCA(t *testing.T) {
	e := setup(t, "127.0.0.0/8")
	e.login()
	_, body := e.form("/tenants", url.Values{"name": {"Acme"}})
	tenantID := regexp.MustCompile(`/tenants/([0-9a-f-]{36})/tokens`).FindStringSubmatch(body)[1]
	newToken := func() string {
		t.Helper()
		_, body := e.form("/tenants/"+tenantID+"/tokens", url.Values{"label": {"t"}, "expires_days": {"1"}})
		return html.UnescapeString(body)
	}

	body = newToken()
	if !strings.Contains(body, "--token-stdin") || strings.Contains(body, "--ca-sha256") || !strings.Contains(body, "Invoke-WebRequest") {
		t.Fatal("public-CA commands missing or pinned")
	}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Caddy Local Authority"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, IsCA: true}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err := os.WriteFile(filepath.Join(e.downloads, "console-ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.downloads, "install.ps1"), []byte("# install.ps1"), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	fp := hex.EncodeToString(sum[:])
	body = newToken()
	for _, want := range []string{"--ca-sha256 " + fp, "-CaSha256 " + fp, `--cacert "$d/ca.pem"`, strings.ToUpper(fp[:2]) + ":"} {
		if !strings.Contains(body, want) {
			t.Errorf("private-CA token page lacks %q", want)
		}
	}

	// A broken CA file yields an explanation, not unpinned commands.
	if err := os.WriteFile(filepath.Join(e.downloads, "console-ca.pem"), []byte("junk"), 0o644); err != nil {
		t.Fatal(err)
	}
	body = newToken()
	if !strings.Contains(body, "console CA published in the downloads directory is invalid") || (strings.Contains(body, "install.sh") && strings.Contains(body, "sudo sh")) {
		t.Fatal("invalid CA file: expected an error and no install commands")
	}
}

func TestAgentActionFlow(t *testing.T) {
	e := setup(t, "127.0.0.0/8")
	e.login()
	tenantID, cred := e.enrollAgent()
	ctx := context.Background()
	agentID := uuid.MustParse(strings.SplitN(strings.TrimPrefix(cred, protocol.CredentialPrefix), ".", 2)[0])
	var userID uuid.UUID
	if err := e.pool.QueryRow(ctx, `SELECT id FROM users`).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	jobID, n, err := store.CreateJob(ctx, e.pool, uuid.MustParse(tenantID), string(protocol.ActionClamdReload), json.RawMessage(`{}`), userID, []uuid.UUID{agentID, uuid.New()})
	if err != nil || n != 1 {
		t.Fatalf("create job: %v, queued %d (the unknown agent must be skipped)", err, n)
	}

	hbResp := func() protocol.HeartbeatResponse {
		t.Helper()
		b, _ := json.Marshal(hb)
		req, _ := http.NewRequest("POST", e.srv.URL+protocol.PathHeartbeat, bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+cred)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var out protocol.HeartbeatResponse
		if resp.StatusCode != 200 || json.NewDecoder(resp.Body).Decode(&out) != nil {
			t.Fatalf("heartbeat %d", resp.StatusCode)
		}
		return out
	}
	first := hbResp()
	if len(first.Actions) != 1 || first.Actions[0].Type != protocol.ActionClamdReload || first.HeartbeatIntervalSeconds != 15 {
		t.Fatalf("first heartbeat: %+v", first)
	}
	if again := hbResp(); len(again.Actions) != 0 {
		t.Fatalf("action delivered twice: %+v", again.Actions)
	}
	actionID := first.Actions[0].ID

	result := protocol.ActionResult{ID: actionID, Outcome: protocol.OutcomeDone, Output: "clamd is reloading its signature databases",
		StartedAt: time.Now().Add(-time.Second), FinishedAt: time.Now()}
	if code, m := e.agentCall(protocol.PathActionResult, result, cred); code != 200 {
		t.Fatalf("result: %d %v", code, m)
	}
	if code, _ := e.agentCall(protocol.PathActionResult, result, cred); code != 409 {
		t.Fatalf("second result: got %d, want 409", code)
	}
	a, err := store.GetAction(ctx, e.pool, uuid.MustParse(actionID))
	if err != nil || a.Status != store.ActionDone || a.Output != result.Output || a.FinishedAt == nil {
		t.Fatalf("stored action %+v %v", a, err)
	}
	job, err := store.GetJob(ctx, e.pool, jobID)
	if err != nil || job.Total != 1 || job.Done != 1 || !job.Finished() {
		t.Fatalf("job %+v %v", job, err)
	}

	// Another agent cannot report on this agent's action, and nobody can
	// report on an action that was never sent.
	_, other := e.enrollSecond(tenantID)
	jobID2, _, _ := store.CreateJob(ctx, e.pool, uuid.MustParse(tenantID), string(protocol.ActionClamdStats), json.RawMessage(`{}`), userID, []uuid.UUID{agentID})
	acts, _ := store.ListJobActions(ctx, e.pool, jobID2)
	queuedResult := protocol.ActionResult{ID: acts[0].ID.String(), Outcome: protocol.OutcomeDone, StartedAt: time.Now(), FinishedAt: time.Now()}
	if code, _ := e.agentCall(protocol.PathActionResult, queuedResult, cred); code != 409 {
		t.Fatalf("result for an undelivered action: got %d, want 409", code)
	}
	hbResp()
	if code, _ := e.agentCall(protocol.PathActionResult, queuedResult, other); code != 409 {
		t.Fatalf("result from another agent: got %d, want 409", code)
	}

	// Overdue actions expire.
	if _, err := e.pool.Exec(ctx, `UPDATE agent_actions SET expires_at = now() - interval '1 second' WHERE job_id = $1`, jobID2); err != nil {
		t.Fatal(err)
	}
	if n, err := store.ExpireActions(ctx, e.pool); err != nil || n != 1 {
		t.Fatalf("expire: %d %v", n, err)
	}
	if a, _ := store.GetAction(ctx, e.pool, acts[0].ID); a.Status != store.ActionExpired || a.Error == "" {
		t.Fatalf("expired action %+v", a)
	}
}

// enrollSecond enrolls another agent in the tenant with a fresh token.
func (e *env) enrollSecond(tenantID string) (string, string) {
	e.t.Helper()
	_, body := e.form("/tenants/"+tenantID+"/tokens", url.Values{"label": {"t2"}, "expires_days": {"1"}})
	tok := regexp.MustCompile(`cav_enr_[a-z0-9]+`).FindString(body)
	code, resp := e.agentCall(protocol.PathEnroll, protocol.EnrollRequest{EnrollmentToken: tok, MachineID: "m2", Hostname: "host2",
		OSFamily: "linux", OSName: "Debian 12", OSVersion: "6.1", Arch: "amd64", AgentVersion: "0.1.0"}, "")
	if code != 201 {
		e.t.Fatalf("enroll second: %d %v", code, resp)
	}
	return resp["agent_id"].(string), resp["credential"].(string)
}

func TestActionUI(t *testing.T) {
	e := setup(t, "127.0.0.0/8")
	e.login()
	tenantID, cred := e.enrollAgent()
	agentID := strings.SplitN(strings.TrimPrefix(cred, protocol.CredentialPrefix), ".", 2)[0]
	ctx := context.Background()
	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := e.pool.QueryRow(ctx, q, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	if code, body := e.do("GET", "/agents/"+agentID, nil, nil); code != 200 || !strings.Contains(body, "Run on host1") || !strings.Contains(body, "Scan a folder") {
		t.Fatalf("endpoint page: %d", code)
	}

	// Anything off the menu is refused, audited, and queues nothing.
	for _, v := range []url.Values{
		{"type": {"run_command"}, "path": {"rm -rf /"}},
		{"type": {"scan_path"}, "path": {"../../etc"}},
		{"type": {"scan_path"}, "path": {"/srv/\x00x"}},
		{"type": {"scan_path"}, "path": {"relative/dir"}},
	} {
		if code, body := e.form("/agents/"+agentID+"/actions", v); code != 400 || !strings.Contains(body, "flash error") {
			t.Fatalf("%v: %d", v, code)
		}
	}
	if code, _ := e.form("/agents/"+agentID+"/actions", url.Values{"type": {"clamd_check"}, "csrf_token": {"wrong"}}); code != 403 {
		t.Fatalf("bad CSRF: %d", code)
	}
	if n := count(`SELECT count(*) FROM agent_actions`); n != 0 {
		t.Fatalf("%d actions queued by refused requests", n)
	}
	if n := count(`SELECT count(*) FROM audit_log WHERE action='agent_action.queue' AND outcome='denied' AND details->>'type'='run_command'`); n != 1 {
		t.Fatalf("refused run_command audited %d times", n)
	}

	// One endpoint: queue a scan, deliver it, report a result.
	code, body := e.form("/agents/"+agentID+"/actions", url.Values{"type": {"scan_path"}, "path": {" /srv/www "}})
	if code != 200 || !strings.Contains(body, "<code>/srv/www</code>") || !strings.Contains(body, "waiting for the endpoint") || !strings.Contains(body, `hx-get="/jobs/`) {
		t.Fatalf("job page: %d", code)
	}
	jobID := regexp.MustCompile(`/jobs/([0-9a-f-]{36})/export.csv`).FindStringSubmatch(body)[1]
	if n := count(`SELECT count(*) FROM audit_log WHERE action='agent_action.queue' AND outcome='success' AND target_id=$1
		AND details->'params'->>'path'='/srv/www' AND (details->>'endpoints')::int=1`, jobID); n != 1 {
		t.Fatal("queue not audited")
	}
	_, hbOut := e.agentCall(protocol.PathHeartbeat, hb, cred)
	acts, _ := hbOut["actions"].([]any)
	if len(acts) != 1 {
		t.Fatalf("heartbeat actions: %v", hbOut["actions"])
	}
	actionID := acts[0].(map[string]any)["id"].(string)
	scan, _ := json.Marshal(protocol.ScanResult{Path: "/srv/www", InfectedTotal: 2, ErrorsTotal: 0, Infected: []protocol.ScanInfection{
		{Path: "/srv/www/<script>alert(1)</script>.php", Signature: "Php.Malware-1"},
		{Path: "/srv/www/b", Signature: `=HYPERLINK("http://evil.test","x")`},
	}})
	res := protocol.ActionResult{ID: actionID, Outcome: protocol.OutcomeDone, Output: "=cmd|' /C calc'!A0\nscanned", Data: scan,
		StartedAt: time.Now().Add(-time.Minute), FinishedAt: time.Now()}
	if code, m := e.agentCall(protocol.PathActionResult, res, cred); code != 200 {
		t.Fatalf("result: %d %v", code, m)
	}

	code, body = e.do("GET", "/jobs/"+jobID, nil, nil)
	if code != 200 || !strings.Contains(body, "2 infected, 0 not scanned") || strings.Contains(body, `hx-get="/jobs/`) {
		t.Fatalf("finished job page: %d (should show the result and stop refreshing)", code)
	}
	code, body = e.do("GET", "/actions/"+actionID, nil, nil)
	if code != 200 || strings.Contains(body, "<script>alert") || !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;.php") || !strings.Contains(body, "Php.Malware-1") {
		t.Fatalf("action page: %d", code)
	}
	if code, body := e.do("GET", "/agents/"+agentID, nil, nil); code != 200 || !strings.Contains(body, "/actions/"+actionID) || strings.Contains(body, `hx-get="/agents/`) {
		t.Fatalf("endpoint history: %d", code)
	}

	// Exports. Cells a spreadsheet would run as formulas stay text.
	readCSV := func(path string) [][]string {
		t.Helper()
		resp, err := e.client.Get(e.srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/csv") || !strings.Contains(resp.Header.Get("Content-Disposition"), "attachment") {
			t.Fatalf("%s: %d %v", path, resp.StatusCode, resp.Header)
		}
		rows, err := csv.NewReader(resp.Body).ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		return rows
	}
	rows := readCSV("/jobs/" + jobID + "/export.csv")
	if len(rows) != 2 || rows[1][3] != "host1" || rows[1][6] != "done" || rows[1][8] != "2" || rows[1][15] != "'=cmd|' /C calc'!A0\nscanned" {
		t.Fatalf("job csv: %q", rows)
	}
	rows = readCSV("/jobs/" + jobID + "/infections.csv")
	if len(rows) != 3 || rows[2][2] != "/srv/www/b" || rows[2][3] != `'=HYPERLINK("http://evil.test","x")` {
		t.Fatalf("infections csv: %q", rows)
	}
	if rows := readCSV("/agents/" + agentID + "/actions/export.csv"); len(rows) != 2 || rows[1][1] != actionID {
		t.Fatalf("endpoint csv: %q", rows)
	}
	code, body = e.do("GET", "/jobs/"+jobID+"/export.json", nil, nil)
	var exp struct {
		Actions []struct {
			Status string          `json:"status"`
			Output string          `json:"output"`
			Data   json.RawMessage `json:"data"`
		} `json:"actions"`
	}
	if code != 200 || json.Unmarshal([]byte(body), &exp) != nil || len(exp.Actions) != 1 || exp.Actions[0].Output != res.Output ||
		!strings.Contains(string(exp.Actions[0].Data), "Php.Malware-1") {
		t.Fatalf("json export: %d %s", code, body)
	}

	// Batch: run on ticked endpoints; only this tenant's agents count.
	agent2, _ := e.enrollSecond(tenantID)
	_, body = e.form("/tenants", url.Values{"name": {"Other"}})
	otherTenant := regexp.MustCompile(`/tenants/([0-9a-f-]{36})/tokens`).FindStringSubmatch(body)[1]
	if code, body := e.do("GET", "/tenants/"+tenantID+"/run", nil, nil); code != 200 || !strings.Contains(body, `value="`+agent2+`"`) {
		t.Fatalf("run page: %d", code)
	}
	code, body = e.form("/tenants/"+otherTenant+"/jobs", url.Values{"type": {"clamd_check"}, "target": {"selected"}, "agent_id": {agentID}})
	if code != 400 || !strings.Contains(body, "No endpoints to run it on") {
		t.Fatalf("another tenant's endpoint: %d", code)
	}
	if code, _ := e.form("/tenants/"+tenantID+"/jobs", url.Values{"type": {"clamd_check"}, "target": {"selected"}, "agent_id": {"x' OR 1=1"}}); code != 400 {
		t.Fatalf("bad selection: %d", code)
	}
	code, body = e.form("/tenants/"+tenantID+"/jobs", url.Values{"type": {"clamd_stats"}, "target": {"selected"}, "agent_id": {agentID, agent2}})
	if code != 200 || !strings.Contains(body, "for 2 endpoints") || !strings.Contains(body, "Cancel waiting actions") {
		t.Fatalf("batch job: %d", code)
	}
	batchID := regexp.MustCompile(`/jobs/([0-9a-f-]{36})/cancel`).FindStringSubmatch(body)[1]
	if code, body := e.do("GET", "/jobs", nil, nil); code != 200 || !strings.Contains(body, "/jobs/"+batchID) || !strings.Contains(body, "clamd stats") {
		t.Fatalf("jobs page: %d", code)
	}

	// Cancelling stops what has not been picked up, and is audited.
	if code, body := e.form("/jobs/"+batchID+"/cancel", url.Values{}); code != 200 || !strings.Contains(body, "were cancelled") || !strings.Contains(body, "2 failed or not run") {
		t.Fatalf("cancel: %d", code)
	}
	if n := count(`SELECT count(*) FROM agent_actions WHERE job_id=$1 AND status='cancelled'`, batchID); n != 2 {
		t.Fatalf("%d cancelled", n)
	}
	if n := count(`SELECT count(*) FROM audit_log WHERE action='agent_action.cancel' AND target_id=$1 AND (details->>'cancelled')::int=2`, batchID); n != 1 {
		t.Fatal("cancel not audited")
	}
	if _, hbOut := e.agentCall(protocol.PathHeartbeat, hb, cred); len(hbOut["actions"].([]any)) != 0 {
		t.Fatalf("cancelled action delivered: %v", hbOut["actions"])
	}

	// A revoked endpoint takes no new actions.
	e.form("/agents/"+agent2+"/revoke", url.Values{})
	if code, body := e.form("/agents/"+agent2+"/actions", url.Values{"type": {"clamd_check"}}); code != 400 || !strings.Contains(body, "revoked") {
		t.Fatalf("revoked endpoint: %d", code)
	}
}
