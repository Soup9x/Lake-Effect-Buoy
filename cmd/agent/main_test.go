package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Soup9x/Lake-Effect-Buoy/internal/protocol"
)

// TestEnrollThenRunUntilRevoked drives the real subcommands against an
// httptest server speaking the protocol types.
func TestEnrollThenRunUntilRevoked(t *testing.T) {
	var beats atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+protocol.PathEnroll, func(w http.ResponseWriter, r *http.Request) {
		var req protocol.EnrollRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.EnrollmentToken != "cav_enr_TESTTOKEN" {
			w.WriteHeader(401)
			_ = json.NewEncoder(w).Encode(protocol.ErrorResponse{Error: protocol.ErrorBody{Code: protocol.ErrInvalidToken}})
			return
		}
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(protocol.EnrollResponse{AgentID: "a1", Credential: "cav_agt_a1.secret", TenantName: "Acme"})
	})
	mux.HandleFunc("POST "+protocol.PathHeartbeat, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer cav_agt_a1.secret" {
			t.Errorf("auth %q", r.Header.Get("Authorization"))
		}
		var hb protocol.HeartbeatRequest
		_ = json.NewDecoder(r.Body).Decode(&hb)
		if hb.ClamAV.Status == "" || hb.Hostname == "" {
			t.Errorf("heartbeat %+v", hb)
		}
		beats.Add(1)
		w.WriteHeader(401)
		_ = json.NewEncoder(w).Encode(protocol.ErrorResponse{Error: protocol.ErrorBody{Code: protocol.ErrAgentRevoked}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	dir := t.TempDir()
	cfg := filepath.Join(dir, "agent.yaml")
	cred := filepath.Join(dir, "credential")
	t.Setenv("CAV_ENROLL_TOKEN", "cav_enr_TESTTOKEN")
	code := realMain([]string{"enroll", "--server", srv.URL, "--config", cfg, "--credential", cred,
		"--clamd", "tcp://127.0.0.1:1", "--insecure-http-for-testing"})
	if code != exitOK {
		t.Fatalf("enroll exit %d", code)
	}
	if os.Getenv("CAV_ENROLL_TOKEN") != "" {
		t.Fatal("token left in environment")
	}
	b, _ := os.ReadFile(cfg)
	if strings.Contains(string(b), "cav_") {
		t.Fatal("secret in config file")
	}
	// Second enroll without --replace must refuse before reading a token.
	if code := realMain([]string{"enroll", "--server", srv.URL, "--config", cfg, "--credential", cred, "--insecure-http-for-testing"}); code == exitOK {
		t.Fatal("re-enroll without --replace succeeded")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if code := runAgent(ctx, cfg, cred); code != exitConfig {
		t.Fatalf("run exit %d, want %d", code, exitConfig)
	}
	if beats.Load() != 1 {
		t.Fatalf("beats %d", beats.Load())
	}
}

func TestRunWithoutCredentialExits78(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "agent.yaml")
	_ = os.WriteFile(cfg, []byte("server_url: https://console.example\nclamd:\n  address: tcp://127.0.0.1:3310\n"), 0o644)
	if code := runAgent(context.Background(), cfg, filepath.Join(dir, "missing")); code != exitConfig {
		t.Fatalf("exit %d", code)
	}
	if code := runAgent(context.Background(), filepath.Join(dir, "nope.yaml"), filepath.Join(dir, "missing")); code != exitConfig {
		t.Fatalf("exit %d", code)
	}
}

func TestUsage(t *testing.T) {
	if realMain(nil) != exitUsage || realMain([]string{"bogus"}) != exitUsage || realMain([]string{"verify", "x"}) != exitUsage {
		t.Fatal("usage exits")
	}
	if realMain([]string{"enroll"}) != exitUsage {
		t.Fatal("enroll without --server")
	}
}

// TestEnrollWithPrivateCA checks that --ca-cert-file lets the agent trust a
// console whose certificate is not in the system trust store, and that the
// setting is kept for later runs.
func TestEnrollWithPrivateCA(t *testing.T) {
	var beats atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+protocol.PathEnroll, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(protocol.EnrollResponse{AgentID: "a1", Credential: "cav_agt_a1.secret", TenantName: "Acme"})
	})
	mux.HandleFunc("POST "+protocol.PathHeartbeat, func(w http.ResponseWriter, r *http.Request) {
		beats.Add(1)
		w.WriteHeader(401)
		_ = json.NewEncoder(w).Encode(protocol.ErrorResponse{Error: protocol.ErrorBody{Code: protocol.ErrAgentRevoked}})
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	dir := t.TempDir()
	cfg := filepath.Join(dir, "agent.yaml")
	cred := filepath.Join(dir, "credential")
	ca := filepath.Join(dir, "console-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	args := []string{"enroll", "--server", srv.URL, "--config", cfg, "--credential", cred, "--clamd", "tcp://127.0.0.1:1"}

	// Without the CA the console's certificate is untrusted.
	t.Setenv("CAV_ENROLL_TOKEN", "cav_enr_TESTTOKEN")
	if code := realMain(args); code == exitOK {
		t.Fatal("enrolled without trusting the console's CA")
	}
	t.Setenv("CAV_ENROLL_TOKEN", "cav_enr_TESTTOKEN")
	if code := realMain(append(args, "--ca-cert-file", "console-ca.pem")); code != exitUsage {
		t.Fatalf("relative --ca-cert-file: exit %d, want %d", code, exitUsage)
	}
	t.Setenv("CAV_ENROLL_TOKEN", "cav_enr_TESTTOKEN")
	if code := realMain(append(args, "--ca-cert-file", ca)); code != exitOK {
		t.Fatalf("enroll with --ca-cert-file: exit %d", code)
	}
	if b, _ := os.ReadFile(cfg); !strings.Contains(string(b), "ca_cert_file: "+ca) {
		t.Fatalf("ca_cert_file not saved in config:\n%s", b)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if code := runAgent(ctx, cfg, cred); code != exitConfig || beats.Load() != 1 {
		t.Fatalf("run: exit %d after %d heartbeats, want %d after 1", code, beats.Load(), exitConfig)
	}
	// A broken CA file stops the agent at startup instead of retrying forever.
	if err := os.WriteFile(ca, []byte("not a certificate"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := runAgent(ctx, cfg, cred); code != exitConfig || beats.Load() != 1 {
		t.Fatalf("run with broken CA file: exit %d after %d heartbeats", code, beats.Load())
	}
}

func TestSetScanRoots(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "agent.yaml")
	if err := os.WriteFile(cfg, []byte("server_url: https://h\nclamd: {address: tcp://127.0.0.1:3310}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if code := realMain([]string{"set-scan-roots", "--config", cfg, root, root + "/", "/nonexistent-dir"}); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	b, _ := os.ReadFile(cfg)
	if !strings.Contains(string(b), "scan_roots:") || strings.Count(string(b), root) != 1 || !strings.Contains(string(b), "server_url: https://h") {
		t.Fatalf("config:\n%s", b)
	}
	if code := realMain([]string{"set-scan-roots", "--config", cfg, "relative/dir"}); code != exitUsage {
		t.Fatalf("relative root: exit %d", code)
	}
	if code := realMain([]string{"set-scan-roots", "--config", cfg}); code != exitOK {
		t.Fatalf("clear: exit %d", code)
	}
	if b, _ := os.ReadFile(cfg); strings.Contains(string(b), "scan_roots") {
		t.Fatalf("roots not cleared:\n%s", b)
	}
}
