package agentapi

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Soup9x/Lake-Effect-Buoy/internal/protocol"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/server/store"
)

func TestValidateHeartbeat(t *testing.T) {
	now := time.Now()
	ok := protocol.HeartbeatRequest{Hostname: "FS01", OSName: "Windows Server 2022", AgentVersion: "0.1.0",
		ClamAV: protocol.ClamAVStatus{Status: protocol.ClamdRunning, EngineVersion: "1.4.1", SignatureVersion: 27410}}
	if err := validateHeartbeat(&ok, now); err != nil {
		t.Fatalf("valid heartbeat rejected: %v", err)
	}
	future := now.Add(72 * time.Hour)
	cases := map[string]func(r *protocol.HeartbeatRequest){
		"empty hostname":     func(r *protocol.HeartbeatRequest) { r.Hostname = "" },
		"shell metachar":     func(r *protocol.HeartbeatRequest) { r.Hostname = "a;b" },
		"control char":       func(r *protocol.HeartbeatRequest) { r.OSName = "x\x00y" },
		"long os":            func(r *protocol.HeartbeatRequest) { r.OSName = strings.Repeat("a", 201) },
		"bad status":         func(r *protocol.HeartbeatRequest) { r.ClamAV.Status = "exploded" },
		"bad engine version": func(r *protocol.HeartbeatRequest) { r.ClamAV.EngineVersion = "1.0 <b>" },
		"negative sigs":      func(r *protocol.HeartbeatRequest) { r.ClamAV.SignatureVersion = -1 },
		"future sig date":    func(r *protocol.HeartbeatRequest) { r.ClamAV.SignatureDate = &future },
		"bad agent version":  func(r *protocol.HeartbeatRequest) { r.AgentVersion = "" },
	}
	for name, mut := range cases {
		r := ok
		mut(&r)
		if err := validateHeartbeat(&r, now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func FuzzValidateEnroll(f *testing.F) {
	f.Add("cav_enr_abc", "m1", "host", "linux", "amd64", "0.1.0")
	f.Fuzz(func(t *testing.T, tok, mid, host, fam, arch, ver string) {
		r := protocol.EnrollRequest{EnrollmentToken: tok, MachineID: mid, Hostname: host, OSFamily: fam, Arch: arch, AgentVersion: ver}
		if validateEnroll(&r) == nil {
			if strings.ContainsAny(host, ";|&$`<>") || (fam != "linux" && fam != "windows") {
				t.Fatalf("accepted invalid input %+v", r)
			}
		}
	})
}

func TestValidateActionResult(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	base := func() protocol.ActionResult {
		return protocol.ActionResult{ID: "x", Outcome: protocol.OutcomeDone, StartedAt: now.Add(-time.Minute), FinishedAt: now}
	}
	ok := func(typ protocol.ActionType, r protocol.ActionResult) store.ActionResultUpdate {
		t.Helper()
		u, err := validateActionResult(typ, &r, now)
		if err != nil {
			t.Fatalf("%s %+v: %v", typ, r, err)
		}
		return u
	}

	// Outcomes map onto statuses.
	for outcome, status := range map[string]string{
		protocol.OutcomeDone: store.ActionDone, protocol.OutcomeFailed: store.ActionFailed,
		protocol.OutcomeRejected: store.ActionRejected, protocol.OutcomeInvalid: store.ActionRejected,
	} {
		r := base()
		r.Outcome = outcome
		if u := ok(protocol.ActionClamdReload, r); u.Status != status {
			t.Errorf("%s -> %s", outcome, u.Status)
		}
	}

	// Text is sanitised, newlines kept only in output.
	r := base()
	r.Output, r.Error = "POOLS: 1\nQUEUE: 0\x1b[2J\r", "bad\nthing\x00"
	if u := ok(protocol.ActionClamdStats, r); u.Output != "POOLS: 1\nQUEUE: 0?[2J?" || u.Error != "bad?thing?" {
		t.Errorf("sanitised %q %q", u.Output, u.Error)
	}

	// Implausible agent times are replaced by the server's.
	r = base()
	r.StartedAt, r.FinishedAt = now.Add(-365*24*time.Hour), now.Add(48*time.Hour)
	if u := ok(protocol.ActionClamdReload, r); !u.StartedAt.Equal(now) || !u.FinishedAt.Equal(now) {
		t.Errorf("times %v %v", u.StartedAt, u.FinishedAt)
	}

	// Scan data is re-encoded after validation; control characters neutralised.
	r = base()
	r.Data = json.RawMessage(`{"path":"/srv","infected":[{"path":"/srv/=cmd|' /C calc'!A0\u0007","signature":"Eicar"}],"infected_total":3,"errors":[],"errors_total":0,"duration_ms":5}`)
	u := ok(protocol.ActionScanPath, r)
	var sr protocol.ScanResult
	if json.Unmarshal(u.Data, &sr) != nil || sr.InfectedTotal != 3 || sr.Infected[0].Path != "/srv/=cmd|' /C calc'!A0?" {
		t.Errorf("scan data %s", u.Data)
	}

	r = base()
	r.Data = json.RawMessage(`{"status":"running","engine_version":"1.5.4","signature_version":28141}`)
	ok(protocol.ActionClamdCheck, r)

	bad := map[string]struct {
		typ protocol.ActionType
		mut func(*protocol.ActionResult)
	}{
		"outcome":            {protocol.ActionClamdReload, func(r *protocol.ActionResult) { r.Outcome = "pwned" }},
		"output too long":    {protocol.ActionClamdStats, func(r *protocol.ActionResult) { r.Output = strings.Repeat("a", protocol.MaxResultOutput+1) }},
		"error too long":     {protocol.ActionClamdStats, func(r *protocol.ActionResult) { r.Error = strings.Repeat("a", protocol.MaxResultError+1) }},
		"data for reload":    {protocol.ActionClamdReload, func(r *protocol.ActionResult) { r.Data = json.RawMessage(`{"x":1}`) }},
		"unknown scan field": {protocol.ActionScanPath, func(r *protocol.ActionResult) { r.Data = json.RawMessage(`{"path":"/srv","evil":1}`) }},
		"scan relative path": {protocol.ActionScanPath, func(r *protocol.ActionResult) {
			r.Data = json.RawMessage(`{"path":"../etc","infected":[],"infected_total":0,"errors":[],"errors_total":0,"duration_ms":1}`)
		}},
		"scan total below list": {protocol.ActionScanPath, func(r *protocol.ActionResult) {
			r.Data = json.RawMessage(`{"path":"/srv","infected":[{"path":"/srv/a","signature":"x"}],"infected_total":0,"errors":[],"errors_total":0,"duration_ms":1}`)
		}},
		"scan trailing data": {protocol.ActionScanPath, func(r *protocol.ActionResult) {
			r.Data = json.RawMessage(`{"path":"/srv","infected":[],"infected_total":0,"errors":[],"errors_total":0,"duration_ms":1}{}`)
		}},
		"check bad status": {protocol.ActionClamdCheck, func(r *protocol.ActionResult) { r.Data = json.RawMessage(`{"status":"<script>"}`) }},
		"data too large": {protocol.ActionScanPath, func(r *protocol.ActionResult) {
			r.Data = json.RawMessage(`"` + strings.Repeat("a", protocol.MaxResultData) + `"`)
		}},
	}
	for name, c := range bad {
		r := base()
		c.mut(&r)
		if _, err := validateActionResult(c.typ, &r, now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
