package heartbeat

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Soup9x/Lake-Effect-Buoy/internal/agent/credstore"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/protocol"
)

// step is one canned server reply to a heartbeat.
type step func(w http.ResponseWriter, r *http.Request)

func jsonReply(code int, v any) step {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
}

func ok(interval int) step {
	return jsonReply(200, protocol.HeartbeatResponse{HeartbeatIntervalSeconds: interval, ServerTime: time.Now(), Actions: []protocol.Action{}})
}

func apiErr(code int, c string) step {
	return jsonReply(code, protocol.ErrorResponse{Error: protocol.ErrorBody{Code: c, Message: "m"}})
}

type harness struct {
	t      *testing.T
	srv    *httptest.Server
	store  credstore.Store
	mu     sync.Mutex
	steps  []step
	auths  []string
	bodies []protocol.HeartbeatRequest
	uas    []string
	waits  []time.Duration
	rotate step
	acts   []protocol.Action
	// result replies to each POST /actions/result in turn (default 200).
	resultSteps []step
	results     []protocol.ActionResult
}

func newHarness(t *testing.T, steps ...step) *harness {
	h := &harness{t: t, steps: steps}
	h.store = credstore.Store{Path: filepath.Join(t.TempDir(), "credential")}
	if err := h.store.Save("cav_agt_initial.secret"); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+protocol.PathHeartbeat, func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		defer h.mu.Unlock()
		var body protocol.HeartbeatRequest
		dec := json.NewDecoder(io.LimitReader(r.Body, protocol.MaxRequestBytes))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil {
			t.Errorf("bad heartbeat body: %v", err)
		}
		h.bodies = append(h.bodies, body)
		h.auths = append(h.auths, r.Header.Get("Authorization"))
		h.uas = append(h.uas, r.Header.Get("User-Agent"))
		i := len(h.auths) - 1
		if i >= len(h.steps) {
			ok(60)(w, r)
			return
		}
		h.steps[i](w, r)
	})
	mux.HandleFunc("POST "+protocol.PathActionResult, func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		defer h.mu.Unlock()
		var res protocol.ActionResult
		if err := json.NewDecoder(r.Body).Decode(&res); err != nil {
			t.Errorf("bad result body: %v", err)
		}
		h.results = append(h.results, res)
		if i := len(h.results) - 1; i < len(h.resultSteps) {
			h.resultSteps[i](w, r)
			return
		}
		jsonReply(200, struct{}{})(w, r)
	})
	mux.HandleFunc("POST "+protocol.PathRotate, func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		defer h.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer cav_agt_initial.secret" {
			t.Errorf("rotate with wrong auth %q", r.Header.Get("Authorization"))
		}
		h.rotate(w, r)
	})
	h.srv = httptest.NewServer(mux)
	t.Cleanup(h.srv.Close)
	return h
}

// run runs the loop until it has slept n times (or returned).
func (h *harness) run(n int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	a := &Agent{
		ServerURL: h.srv.URL,
		HTTP:      h.srv.Client(),
		Store:     h.store,
		Version:   "1.2.3",
		Collect: func(context.Context) protocol.HeartbeatRequest {
			return protocol.HeartbeatRequest{Hostname: "h", ClamAV: protocol.ClamAVStatus{Status: protocol.ClamdRunning}}
		},
		Dispatch: func(_ context.Context, act protocol.Action, report func(protocol.ActionResult)) {
			h.acts = append(h.acts, act)
			report(protocol.ActionResult{ID: act.ID, Outcome: protocol.OutcomeDone})
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Rand:   func() float64 { return 0.5 },
		Sleep: func(ctx context.Context, d time.Duration) error {
			h.waits = append(h.waits, d)
			if len(h.waits) >= n {
				cancel()
				return ctx.Err()
			}
			return nil
		},
	}
	return a.Run(ctx)
}

func TestNormalLoopAndClamp(t *testing.T) {
	h := newHarness(t, ok(20), ok(1), ok(100000), ok(0))
	if err := h.run(4); err != nil {
		t.Fatal(err)
	}
	// Rand=0.5 means zero jitter.
	want := []time.Duration{20 * time.Second, 15 * time.Second, time.Hour, 60 * time.Second}
	for i, w := range want {
		if h.waits[i] != w {
			t.Errorf("wait %d = %v, want %v", i, h.waits[i], w)
		}
	}
	if h.auths[0] != "Bearer cav_agt_initial.secret" || h.uas[0] != "clamav-agent/1.2.3" {
		t.Fatalf("headers %q %q", h.auths[0], h.uas[0])
	}
	if h.bodies[0].AgentVersion != "1.2.3" || h.bodies[0].SentAt.IsZero() {
		t.Fatalf("body %+v", h.bodies[0])
	}
}

func TestJitterRange(t *testing.T) {
	a := &Agent{}
	for _, r := range []float64{0, 0.999999} {
		a.Rand = func() float64 { return r }
		d := a.jitter(60 * time.Second)
		if d < 50*time.Second || d > 70*time.Second {
			t.Fatalf("jitter %v", d)
		}
	}
}

func TestRevokedStops(t *testing.T) {
	h := newHarness(t, apiErr(401, protocol.ErrAgentRevoked))
	if err := h.run(5); !errors.Is(err, ErrRevoked) {
		t.Fatalf("got %v", err)
	}
	if len(h.auths) != 1 || len(h.waits) != 0 {
		t.Fatalf("requests=%d waits=%d", len(h.auths), len(h.waits))
	}
}

func TestOther401KeepsGoingSlowly(t *testing.T) {
	plain := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(401) }
	html := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(401)
		_, _ = w.Write([]byte("<html>Unauthorized agent_revoked</html>"))
	}
	h := newHarness(t, apiErr(401, protocol.ErrUnauthorized), plain, html, apiErr(401, protocol.ErrInvalidToken), ok(60))
	if err := h.run(5); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		if h.waits[i] < 30*time.Minute || h.waits[i] > 60*time.Minute {
			t.Errorf("wait %d = %v", i, h.waits[i])
		}
	}
	if h.waits[4] != 60*time.Second {
		t.Errorf("after recovery wait %v", h.waits[4])
	}
}

func TestBackoffOnErrors(t *testing.T) {
	notJSON := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200); _, _ = w.Write([]byte("nope")) }
	huge := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"actions":["` + strings.Repeat("a", 2<<20) + `"]}`))
	}
	h := newHarness(t, apiErr(500, protocol.ErrInternal), apiErr(502, ""), apiErr(429, protocol.ErrRateLimited),
		notJSON, huge, apiErr(400, protocol.ErrInvalidRequest), ok(30))
	if err := h.run(7); err != nil {
		t.Fatal(err)
	}
	// Rand=0.5 subtracts 5 s of jitter from each backoff step.
	want := []time.Duration{55, 115, 235, 295, 295, 295, 30}
	for i, w := range want {
		if h.waits[i] != w*time.Second {
			t.Errorf("wait %d = %v, want %v", i, h.waits[i], w*time.Second)
		}
	}
}

func TestRetryAfter(t *testing.T) {
	ra := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "900")
		w.WriteHeader(429)
	}
	h := newHarness(t, ra)
	_ = h.run(1)
	if h.waits[0] != 900*time.Second {
		t.Fatal(h.waits[0])
	}
}

func TestNetworkErrorBacksOff(t *testing.T) {
	h := newHarness(t)
	h.srv.Close() // connection refused
	if err := h.run(2); err != nil {
		t.Fatal(err)
	}
	if h.waits[0] != 55*time.Second || h.waits[1] != 115*time.Second {
		t.Fatal(h.waits)
	}
}

func TestRotation(t *testing.T) {
	rot := jsonReply(200, protocol.HeartbeatResponse{HeartbeatIntervalSeconds: 60, RotateCredential: true})
	var h *harness
	checkPersisted := func(w http.ResponseWriter, r *http.Request) {
		// The new credential must already be on disk when first used.
		stored, err := h.store.Load()
		if err != nil || "Bearer "+stored != r.Header.Get("Authorization") {
			t.Errorf("stored %q, used %q", stored, r.Header.Get("Authorization"))
		}
		ok(60)(w, r)
	}
	h = newHarness(t, rot, checkPersisted)
	h.rotate = jsonReply(200, protocol.RotateResponse{Credential: "cav_agt_rotated.secret2"}) // gitleaks:allow fake test credential
	if err := h.run(2); err != nil {
		t.Fatal(err)
	}
	if h.auths[1] != "Bearer cav_agt_rotated.secret2" {
		t.Fatalf("second heartbeat used %q", h.auths[1])
	}
}

func TestRotationFailureKeepsOldCredential(t *testing.T) {
	rot := jsonReply(200, protocol.HeartbeatResponse{RotateCredential: true})
	h := newHarness(t, rot, ok(60))
	h.rotate = jsonReply(200, protocol.RotateResponse{Credential: "not-a-credential"})
	if err := h.run(2); err != nil {
		t.Fatal(err)
	}
	if got, _ := h.store.Load(); got != "cav_agt_initial.secret" || h.auths[1] != "Bearer cav_agt_initial.secret" {
		t.Fatalf("store %q auth %q", got, h.auths[1])
	}
}

func TestRotationRevoked(t *testing.T) {
	h := newHarness(t, jsonReply(200, protocol.HeartbeatResponse{RotateCredential: true}))
	h.rotate = apiErr(401, protocol.ErrAgentRevoked)
	if err := h.run(3); !errors.Is(err, ErrRevoked) {
		t.Fatal(err)
	}
}

func TestActionsDispatched(t *testing.T) {
	acts := []protocol.Action{{ID: "a1", Type: "run_command", Params: json.RawMessage(`{"cmd":"id"}`)}, {ID: "a2", Type: "x"}}
	h := newHarness(t, jsonReply(200, protocol.HeartbeatResponse{HeartbeatIntervalSeconds: 60, Actions: acts}))
	if err := h.run(1); err != nil {
		t.Fatal(err)
	}
	if len(h.acts) != 2 || h.acts[0].ID != "a1" {
		t.Fatalf("%+v", h.acts)
	}
}

func TestMissingCredential(t *testing.T) {
	a := &Agent{Store: credstore.Store{Path: filepath.Join(t.TempDir(), "none")}}
	if err := a.Run(context.Background()); !errors.Is(err, credstore.ErrNotFound) {
		t.Fatal(err)
	}
}

func withActions(ids ...string) step {
	var acts []protocol.Action
	for _, id := range ids {
		acts = append(acts, protocol.Action{ID: id, Type: protocol.ActionClamdCheck})
	}
	return jsonReply(200, protocol.HeartbeatResponse{HeartbeatIntervalSeconds: 15, ServerTime: time.Now(), Actions: acts})
}

// recorded returns the IDs of the results the server received, in order.
func (h *harness) recorded() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var ids []string
	for _, r := range h.results {
		ids = append(ids, r.ID)
	}
	return ids
}

func TestActionResultsSent(t *testing.T) {
	h := newHarness(t, withActions("a1", "a2"))
	if err := h.run(1); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(h.recorded(), ","); got != "a1,a2" {
		t.Fatalf("results %q", got)
	}
}

func TestActionResultsRetriedAfterNetworkTrouble(t *testing.T) {
	h := newHarness(t, withActions("a1"), ok(60))
	// The first attempt fails with a 503; the next round sends it again.
	h.resultSteps = []step{apiErr(503, "internal")}
	if err := h.run(2); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(h.recorded(), ","); got != "a1,a1" {
		t.Fatalf("results %q, want a1 sent twice", got)
	}
}

func TestRefusedActionResultDropped(t *testing.T) {
	h := newHarness(t, withActions("a1", "a2"), ok(60))
	h.resultSteps = []step{apiErr(409, "invalid_request")}
	if err := h.run(2); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(h.recorded(), ","); got != "a1,a2" {
		t.Fatalf("results %q, want a1 dropped and a2 sent", got)
	}
}

func TestRevokedWhileSendingResults(t *testing.T) {
	h := newHarness(t, withActions("a1"))
	h.resultSteps = []step{apiErr(401, protocol.ErrAgentRevoked)}
	if err := h.run(5); !errors.Is(err, ErrRevoked) {
		t.Fatalf("got %v, want ErrRevoked", err)
	}
}
