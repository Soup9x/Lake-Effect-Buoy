// Package heartbeat runs the agent's send loop: report status to the console,
// apply interval/rotation instructions, and hand actions to the dispatcher.
//
// Failure handling follows design section 0a.2 / CLAUDE.md rule 6:
//   - 401 with code agent_revoked: stop (Run returns ErrRevoked).
//   - any other 401: keep running, log at error level, retry after 30-60 min.
//   - network errors, 5xx, 429 and other statuses: exponential backoff from
//     60 s, capped at 5 min, then back to the normal interval on success.
package heartbeat

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"strconv"
	"time"

	"github.com/Soup9x/Lake-Effect-Buoy/internal/agent/credstore"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/agent/sysinfo"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/protocol"
)

// ErrRevoked means the server answered 401 agent_revoked. The agent must stop
// and must not be restarted automatically.
var ErrRevoked = errors.New("agent credential has been revoked by the console")

// Timing parameters.
const (
	MinInterval   = 15 * time.Second
	MaxInterval   = 3600 * time.Second
	Jitter        = 10 * time.Second
	BackoffStart  = 60 * time.Second
	BackoffMax    = 5 * time.Minute
	Unauth401Min  = 30 * time.Minute
	Unauth401Max  = 60 * time.Minute
	maxRetryAfter = time.Hour
	// MaxResponseBytes caps every response body read from the server.
	MaxResponseBytes = 1 << 20
)

// CredentialStore is implemented by credstore.Store.
type CredentialStore interface {
	Load() (string, error)
	Save(string) error
}

// Agent is the heartbeat loop. All fields except the test hooks are required.
type Agent struct {
	ServerURL string // validated base URL without trailing slash
	HTTP      *http.Client
	Store     CredentialStore
	Version   string
	// Collect builds the heartbeat body (SentAt is filled in by the loop).
	Collect func(ctx context.Context) protocol.HeartbeatRequest
	// Dispatch handles one action from the server and calls report exactly
	// once with its result (possibly later, from another goroutine).
	Dispatch func(ctx context.Context, a protocol.Action, report func(protocol.ActionResult))
	Logger   *slog.Logger

	// Test hooks. Sleep must return ctx.Err() when ctx is done.
	Sleep func(ctx context.Context, d time.Duration) error
	Rand  func() float64 // uniform in [0,1)

	cred    string
	results chan protocol.ActionResult
	unsent  []protocol.ActionResult
}

// maxUnsent caps results kept for retry while the console is unreachable.
const maxUnsent = 200

// result classifies one request.
type result int

const (
	resOK result = iota
	resRevoked
	resUnauthorized // a 401 that is not agent_revoked
	resTransient
	resRejected // the server refused the request itself (4xx); retrying will not help
)

// Run sends a heartbeat immediately, then keeps going until ctx is cancelled
// (returns nil) or the credential is revoked (returns ErrRevoked). A missing
// or unreadable credential is returned as an error before anything is sent.
func (a *Agent) Run(ctx context.Context) error {
	if a.Sleep == nil {
		a.Sleep = sleepCtx
	}
	if a.Rand == nil {
		a.Rand = rand.Float64
	}
	if a.Logger == nil {
		a.Logger = slog.Default()
	}
	cred, err := a.Store.Load()
	if err != nil {
		return err
	}
	a.cred = cred
	if a.results == nil {
		a.results = make(chan protocol.ActionResult, 64)
	}

	failures := 0
	for {
		// Results of scans that finished since the last heartbeat.
		if err := a.flushResults(ctx); errors.Is(err, ErrRevoked) {
			return ErrRevoked
		}
		resp, res, retryAfter, err := a.heartbeat(ctx)
		if ctx.Err() != nil {
			return nil
		}
		var wait time.Duration
		switch res {
		case resOK:
			if failures > 0 {
				a.Logger.Info("heartbeat succeeded again", "after_failures", failures)
			}
			failures = 0
			if resp.RotateCredential {
				if err := a.rotate(ctx); errors.Is(err, ErrRevoked) {
					return ErrRevoked
				} else if err != nil {
					a.Logger.Error("credential rotation failed; keeping current credential", "error", err)
				}
			}
			for _, act := range resp.Actions {
				a.Dispatch(ctx, act, a.report)
			}
			if err := a.flushResults(ctx); errors.Is(err, ErrRevoked) {
				return ErrRevoked
			}
			wait = a.jitter(ClampInterval(resp.HeartbeatIntervalSeconds))
			a.Logger.Debug("heartbeat sent", "next_in", wait.Round(time.Second))
		case resRevoked:
			a.Logger.Error("CONSOLE REPORTS THIS AGENT IS REVOKED (401 agent_revoked); stopping. Re-enroll to resume.", "error", err)
			return ErrRevoked
		case resUnauthorized:
			failures = 0
			wait = Unauth401Min + time.Duration(a.Rand()*float64(Unauth401Max-Unauth401Min))
			a.Logger.Error("HEARTBEAT REJECTED WITH 401 (not a revocation); will keep retrying slowly. Check the server, proxy and credential.",
				"error", err, "retry_in", wait.Round(time.Second))
		default:
			failures++
			wait = a.backoff(failures)
			if retryAfter > wait {
				wait = min(retryAfter, maxRetryAfter)
			}
			a.Logger.Warn("heartbeat failed; backing off", "error", err, "attempt", failures, "retry_in", wait.Round(time.Second))
		}
		if err := a.Sleep(ctx, wait); err != nil {
			return nil
		}
	}
}

// report queues an action result for the console. It blocks only if 64
// results are already waiting, which bounds memory.
func (a *Agent) report(r protocol.ActionResult) { a.results <- r }

// flushResults sends queued action results. Results the server refuses are
// dropped; on network trouble they are kept (up to maxUnsent) for the next
// round. Returns ErrRevoked if the console says this agent is revoked.
func (a *Agent) flushResults(ctx context.Context) error {
	for {
		select {
		case r := <-a.results:
			a.unsent = append(a.unsent, r)
			continue
		default:
		}
		break
	}
	if over := len(a.unsent) - maxUnsent; over > 0 {
		a.Logger.Error("dropping action results the console has not accepted yet", "count", over)
		a.unsent = a.unsent[over:]
	}
	for len(a.unsent) > 0 {
		r := a.unsent[0]
		var ack struct{}
		res, _, err := a.post(ctx, protocol.PathActionResult, r, &ack)
		switch res {
		case resOK:
			a.unsent = a.unsent[1:]
		case resRejected:
			a.Logger.Warn("console refused an action result; dropping it", "action_id", r.ID, "error", err)
			a.unsent = a.unsent[1:]
		case resRevoked:
			a.Logger.Error("CONSOLE REPORTS THIS AGENT IS REVOKED (401 agent_revoked) while sending results; stopping.")
			return ErrRevoked
		default:
			a.Logger.Warn("could not send action results; will retry", "pending", len(a.unsent), "error", err)
			return err
		}
	}
	return nil
}

// ClampInterval converts the server's interval to a duration in [15s, 1h].
// Zero (absent) means the default.
func ClampInterval(seconds int) time.Duration {
	if seconds <= 0 {
		return protocol.DefaultHeartbeatInterval
	}
	d := time.Duration(seconds) * time.Second
	return min(max(d, MinInterval), MaxInterval)
}

// jitter returns d ± 10 s.
func (a *Agent) jitter(d time.Duration) time.Duration {
	d += time.Duration((a.Rand()*2 - 1) * float64(Jitter))
	return max(d, time.Second)
}

// backoff returns 60 s, 120 s, 240 s, then 300 s, each minus up to 10 s of
// jitter so a fleet does not retry in lockstep.
func (a *Agent) backoff(failures int) time.Duration {
	d := BackoffStart
	for i := 1; i < failures && d < BackoffMax; i++ {
		d *= 2
	}
	d = min(d, BackoffMax)
	return d - time.Duration(a.Rand()*float64(Jitter))
}

func (a *Agent) heartbeat(ctx context.Context) (*protocol.HeartbeatResponse, result, time.Duration, error) {
	body := a.Collect(ctx)
	body.AgentVersion = a.Version
	body.SentAt = time.Now().UTC().Truncate(time.Second)
	var resp protocol.HeartbeatResponse
	res, retryAfter, err := a.post(ctx, protocol.PathHeartbeat, body, &resp)
	if res != resOK {
		return nil, res, retryAfter, err
	}
	return &resp, resOK, 0, nil
}

// rotate obtains a new credential and persists it BEFORE using it, so a crash
// can never leave the agent holding a credential that is not on disk.
func (a *Agent) rotate(ctx context.Context) error {
	var resp protocol.RotateResponse
	res, _, err := a.post(ctx, protocol.PathRotate, struct{}{}, &resp)
	switch res {
	case resOK:
	case resRevoked:
		a.Logger.Error("CONSOLE REPORTS THIS AGENT IS REVOKED (401 agent_revoked) during rotation; stopping.")
		return ErrRevoked
	default:
		return err
	}
	if err := credstore.Validate(resp.Credential); err != nil {
		return fmt.Errorf("server returned an invalid credential: %w", err)
	}
	if err := a.Store.Save(resp.Credential); err != nil {
		return fmt.Errorf("persist rotated credential: %w", err)
	}
	a.cred = resp.Credential
	a.Logger.Info("credential rotated")
	return nil
}

// post sends a JSON request with the bearer credential and decodes a 200
// response into out.
func (a *Agent) post(ctx context.Context, path string, in, out any) (result, time.Duration, error) {
	payload, err := json.Marshal(in)
	if err != nil {
		return resTransient, 0, err
	}
	if len(payload) > protocol.MaxRequestBytes {
		return resTransient, 0, fmt.Errorf("request body is %d bytes, over the protocol limit", len(payload))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.ServerURL+path, bytes.NewReader(payload))
	if err != nil {
		return resTransient, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+a.cred)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "clamav-agent/"+a.Version)

	resp, err := a.HTTP.Do(req)
	if err != nil {
		return resTransient, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		return resTransient, 0, fmt.Errorf("read response: %w", err)
	}
	if len(data) > MaxResponseBytes {
		return resTransient, 0, errors.New("response body exceeds 1 MB")
	}

	switch resp.StatusCode {
	case http.StatusOK:
		if err := json.Unmarshal(data, out); err != nil {
			return resTransient, 0, fmt.Errorf("decode response: %w", err)
		}
		return resOK, 0, nil
	case http.StatusUnauthorized:
		code, msg := errorCode(data)
		err := fmt.Errorf("HTTP 401 code=%q message=%q", code, msg)
		if code == protocol.ErrAgentRevoked {
			return resRevoked, 0, err
		}
		return resUnauthorized, 0, err
	case http.StatusBadRequest, http.StatusNotFound, http.StatusConflict, http.StatusGone,
		http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity:
		code, msg := errorCode(data)
		return resRejected, 0, fmt.Errorf("HTTP %d code=%q message=%q", resp.StatusCode, code, msg)
	default:
		code, msg := errorCode(data)
		return resTransient, retryAfter(resp), fmt.Errorf("HTTP %d code=%q message=%q", resp.StatusCode, code, msg)
	}
}

// errorCode extracts the protocol error code and message, sanitized for logs.
// A non-JSON body yields empty strings.
func errorCode(data []byte) (code, msg string) {
	var er protocol.ErrorResponse
	if json.Unmarshal(data, &er) != nil {
		return "", ""
	}
	return sysinfo.Clean(er.Error.Code), sysinfo.Clean(er.Error.Message)
}

func retryAfter(resp *http.Response) time.Duration {
	if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode != http.StatusServiceUnavailable {
		return 0
	}
	s, err := strconv.Atoi(resp.Header.Get("Retry-After"))
	if err != nil || s <= 0 {
		return 0
	}
	return time.Duration(s) * time.Second
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
