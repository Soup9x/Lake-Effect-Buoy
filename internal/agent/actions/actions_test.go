package actions

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Soup9x/Lake-Effect-Buoy/internal/protocol"
)

// fakeClamd records what it was asked and plays back fixed replies.
type fakeClamd struct {
	mu        sync.Mutex
	scanned   []string
	scanLines []string
	scanErr   error
	release   chan struct{} // if set, ContScan waits for it
}

func (f *fakeClamd) Status(context.Context) protocol.ClamAVStatus {
	d := time.Date(2026, 10, 2, 6, 26, 12, 0, time.UTC)
	return protocol.ClamAVStatus{Status: protocol.ClamdRunning, EngineVersion: "1.5.4", SignatureVersion: 28141, SignatureDate: &d}
}
func (f *fakeClamd) Reload(context.Context) error { return nil }
func (f *fakeClamd) Stats(context.Context) (string, error) {
	return "POOLS: 1\n\nSTATE: VALID PRIMARY\nQUEUE: 0 items\n", nil
}
func (f *fakeClamd) ContScan(_ context.Context, path string, _ time.Duration, onLine func(string)) error {
	if f.release != nil {
		<-f.release
	}
	f.mu.Lock()
	f.scanned = append(f.scanned, path)
	f.mu.Unlock()
	for _, l := range f.scanLines {
		onLine(strings.ReplaceAll(l, "ROOT", path))
	}
	return f.scanErr
}

// run dispatches one action and waits for its single report.
func run(t *testing.T, d *Dispatcher, a protocol.Action) protocol.ActionResult {
	t.Helper()
	ch := make(chan protocol.ActionResult, 2)
	d.Dispatch(context.Background(), a, func(r protocol.ActionResult) { ch <- r })
	select {
	case r := <-ch:
		select {
		case extra := <-ch:
			t.Fatalf("reported twice: %+v", extra)
		case <-time.After(20 * time.Millisecond):
		}
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("no report")
	}
	return protocol.ActionResult{}
}

func scanAction(path string) protocol.Action {
	b, _ := json.Marshal(protocol.ScanPathParams{Path: path})
	return protocol.Action{ID: "0192f0c4-0000-7000-8000-000000000001", Type: protocol.ActionScanPath, Params: b}
}

func TestHandlersMatchProtocolAllowlist(t *testing.T) {
	for typ := range handlers {
		if !protocol.IsAllowed(typ) {
			t.Errorf("handler for %q which the protocol does not allow", typ)
		}
	}
	for _, typ := range protocol.ActionTypes {
		if handlers[typ] == nil {
			t.Errorf("no handler for allowed type %q", typ)
		}
	}
}

func TestMaliciousActionsRejected(t *testing.T) {
	var buf bytes.Buffer
	f := &fakeClamd{}
	d := &Dispatcher{Logger: slog.New(slog.NewTextHandler(&buf, nil)), Clamd: f, ScanRoots: []string{t.TempDir()}}
	cases := []struct {
		a    protocol.Action
		want string
	}{
		{protocol.Action{ID: "1", Type: "run_command", Params: json.RawMessage(`{"cmd":"rm -rf /"}`)}, protocol.OutcomeRejected},
		{protocol.Action{ID: "2", Type: "exec", Params: json.RawMessage(`"curl evil | sh"`)}, protocol.OutcomeRejected},
		{protocol.Action{ID: "3", Type: ""}, protocol.OutcomeRejected},
		{protocol.Action{ID: "4\n5", Type: "scan_path\x00", Params: json.RawMessage(`{"path":"/srv"}`)}, protocol.OutcomeRejected},
		{protocol.Action{ID: strings.Repeat("x", 5000), Type: "clamd_ping", Params: json.RawMessage(`{}`)}, protocol.OutcomeRejected},
		{protocol.Action{ID: "6", Type: protocol.ActionScanPath, Params: json.RawMessage(`{"path":"../../etc"}`)}, protocol.OutcomeInvalid},
		{protocol.Action{ID: "7", Type: protocol.ActionScanPath, Params: json.RawMessage(`{"path":"/x","r":true}`)}, protocol.OutcomeInvalid},
		{protocol.Action{ID: "8", Type: protocol.ActionClamdStats, Params: json.RawMessage(`{"cmd":"SHUTDOWN"}`)}, protocol.OutcomeInvalid},
	}
	for _, c := range cases {
		res := run(t, d, c.a)
		if res.Outcome != c.want {
			t.Errorf("%q: outcome %q, want %q", c.a.Type, res.Outcome, c.want)
		}
		if len(res.ID) > 64 || strings.ContainsAny(res.ID, "\n\x00") || res.Error == "" {
			t.Errorf("result %+v", res)
		}
	}
	if len(f.scanned) != 0 {
		t.Fatalf("clamd was asked to scan %q", f.scanned)
	}
	if strings.Count(buf.String(), "action rejected") != len(cases) {
		t.Fatalf("log: %s", buf.String())
	}
}

func TestQuickActions(t *testing.T) {
	d := &Dispatcher{Clamd: &fakeClamd{}}
	res := run(t, d, protocol.Action{ID: "1", Type: protocol.ActionClamdCheck})
	var st protocol.ClamAVStatus
	if res.Outcome != protocol.OutcomeDone || json.Unmarshal(res.Data, &st) != nil || st.SignatureVersion != 28141 || !strings.Contains(res.Output, "28141") {
		t.Errorf("check: %+v", res)
	}
	if res := run(t, d, protocol.Action{ID: "2", Type: protocol.ActionClamdReload}); res.Outcome != protocol.OutcomeDone || !strings.Contains(res.Output, "reloading") {
		t.Errorf("reload: %+v", res)
	}
	if res := run(t, d, protocol.Action{ID: "3", Type: protocol.ActionClamdStats, Params: json.RawMessage(`{}`)}); res.Outcome != protocol.OutcomeDone || !strings.Contains(res.Output, "QUEUE: 0 items\n") {
		t.Errorf("stats: %+v", res)
	}
}

func TestScanPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses Unix paths")
	}
	root := t.TempDir()
	sub := filepath.Join(root, "site")
	outside := t.TempDir()
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	// A symlink inside the root that points outside it.
	escape := filepath.Join(root, "escape")
	if err := os.Symlink(outside, escape); err != nil {
		t.Fatal(err)
	}
	f := &fakeClamd{scanLines: []string{"ROOT/a.exe: Win.Test.EICAR_HDB-1 FOUND", "ROOT/b: lstat() failed: Permission denied. ERROR"}}
	d := &Dispatcher{Clamd: f, ScanRoots: []string{root}}

	res := run(t, d, scanAction(sub))
	var sr protocol.ScanResult
	if res.Outcome != protocol.OutcomeDone || json.Unmarshal(res.Data, &sr) != nil {
		t.Fatalf("scan: %+v", res)
	}
	if sr.InfectedTotal != 1 || sr.Infected[0].Signature != "Win.Test.EICAR_HDB-1" || sr.Infected[0].Path != sub+"/a.exe" ||
		sr.ErrorsTotal != 1 || !strings.Contains(sr.Errors[0].Error, "Permission denied") {
		t.Fatalf("scan result %+v", sr)
	}

	for name, p := range map[string]string{"outside": outside, "symlink escape": escape, "missing": filepath.Join(root, "nope")} {
		if res := run(t, d, scanAction(p)); res.Outcome != protocol.OutcomeFailed || res.Error == "" {
			t.Errorf("%s: %+v", name, res)
		}
	}
	if res := run(t, &Dispatcher{Clamd: f}, scanAction(sub)); res.Outcome != protocol.OutcomeFailed || !strings.Contains(res.Error, "not enabled") {
		t.Errorf("no roots: %+v", res)
	}
	if len(f.scanned) != 1 || f.scanned[0] != sub {
		t.Fatalf("clamd scanned %q, want only %q", f.scanned, sub)
	}
}

func TestOneScanAtATime(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses Unix paths")
	}
	root := t.TempDir()
	f := &fakeClamd{release: make(chan struct{})}
	d := &Dispatcher{Clamd: f, ScanRoots: []string{root}}
	first := make(chan protocol.ActionResult, 1)
	d.Dispatch(context.Background(), scanAction(root), func(r protocol.ActionResult) { first <- r })
	// Quick actions still run while the scan is in progress.
	if res := run(t, d, protocol.Action{ID: "q", Type: protocol.ActionClamdReload}); res.Outcome != protocol.OutcomeDone {
		t.Fatalf("reload during scan: %+v", res)
	}
	if res := run(t, d, scanAction(root)); res.Outcome != protocol.OutcomeFailed || !strings.Contains(res.Error, "already running") {
		t.Fatalf("second scan: %+v", res)
	}
	close(f.release)
	if res := <-first; res.Outcome != protocol.OutcomeDone {
		t.Fatalf("first scan: %+v", res)
	}
	// Once finished, another scan may start.
	f.release = nil
	if res := run(t, d, scanAction(root)); res.Outcome != protocol.OutcomeDone {
		t.Fatalf("third scan: %+v", res)
	}
}

func TestScanResultFitsLimit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses Unix paths")
	}
	root := t.TempDir()
	var lines []string
	for i := range 5000 {
		lines = append(lines, fmt.Sprintf("ROOT/%s%d: Some.Signature-%d FOUND", strings.Repeat("d", 200), i, i))
	}
	f := &fakeClamd{scanLines: lines, scanErr: errors.New("scan stopped")}
	res := run(t, &Dispatcher{Clamd: f, ScanRoots: []string{root}}, scanAction(root))
	var sr protocol.ScanResult
	if json.Unmarshal(res.Data, &sr) != nil || !sr.Truncated || sr.InfectedTotal != 5000 || len(sr.Infected) == 0 || len(sr.Infected) >= 5000 {
		t.Fatalf("truncation: total %d listed %d truncated %v", sr.InfectedTotal, len(sr.Infected), sr.Truncated)
	}
	if len(res.Data) > protocol.MaxResultData || res.Outcome != protocol.OutcomeFailed {
		t.Fatalf("data %d bytes, outcome %q", len(res.Data), res.Outcome)
	}
	body, _ := json.Marshal(res)
	if len(body) > protocol.MaxRequestBytes {
		t.Fatalf("result request is %d bytes, over the protocol limit", len(body))
	}
}

func TestCleanText(t *testing.T) {
	if got := cleanText("a\nb\x00c\x1b[31m\xff", 100, false); got != "a?b?c?[31m?" {
		t.Errorf("single line: %q", got)
	}
	if got := cleanText("a\nb\tc", 100, true); got != "a\nb\tc" {
		t.Errorf("multiline: %q", got)
	}
	if got := cleanText(strings.Repeat("é", 10), 5, false); got != "éé" {
		t.Errorf("cap: %q", got)
	}
}
