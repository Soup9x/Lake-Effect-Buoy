// Package actions dispatches server-requested actions through a static
// allowlist.
//
// SECURITY (CLAUDE.md rule 1): handlers are looked up in a map that is fixed
// at compile time and keyed by protocol.ActionType. Parameters are strictly
// decoded and validated by protocol.DecodeParams before any handler runs.
// Every handler only talks to clamd with a fixed protocol command (see
// package clamd); none starts a process, and process execution is banned in
// internal/agent (enforced by a test). scan_path additionally requires the
// path to resolve inside a scan root from the agent's LOCAL config.
package actions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/Soup9x/Lake-Effect-Buoy/internal/agent/clamd"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/protocol"
)

// DefaultScanTimeout bounds one scan.
const DefaultScanTimeout = 4 * time.Hour

// quickTimeout bounds the actions that are a single clamd exchange.
const quickTimeout = 30 * time.Second

// output is what a handler produces.
type output struct {
	Text string
	Data any
}

type handler func(d *Dispatcher, ctx context.Context, p protocol.ActionParams) (output, error)

// handlers is the agent-side allowlist. It must only contain types that
// protocol.IsAllowed accepts (tested).
var handlers = map[protocol.ActionType]handler{
	protocol.ActionClamdCheck:  clamdCheck,
	protocol.ActionClamdReload: clamdReload,
	protocol.ActionClamdStats:  clamdStats,
	protocol.ActionScanPath:    scanPath,
}

// background marks the handlers that run in the background, one at a time.
var background = map[protocol.ActionType]bool{protocol.ActionScanPath: true}

// Clamd is the subset of *clamd.Client the handlers use.
type Clamd interface {
	Status(ctx context.Context) protocol.ClamAVStatus
	Reload(ctx context.Context) error
	Stats(ctx context.Context) (string, error)
	ContScan(ctx context.Context, path string, timeout time.Duration, onLine func(string)) error
}

// Dispatcher runs actions.
type Dispatcher struct {
	Logger *slog.Logger
	Clamd  Clamd
	// ScanRoots are the directories scan_path may target (local config).
	ScanRoots   []string
	ScanTimeout time.Duration

	scanning atomic.Bool
	now      func() time.Time
}

// Dispatch validates and runs one action and calls report exactly once with
// the result: before returning for quick actions, from a background goroutine
// for scans. It never panics on malformed input and never interprets an
// unknown type.
func (d *Dispatcher) Dispatch(ctx context.Context, a protocol.Action, report func(protocol.ActionResult)) {
	logger := d.Logger
	if logger == nil {
		logger = slog.Default()
	}
	now := d.now
	if now == nil {
		now = time.Now
	}
	res := protocol.ActionResult{ID: cleanText(a.ID, 64, false), StartedAt: now().UTC()}
	typ := cleanText(string(a.Type), 64, false)
	finish := func(outcome string, out output, err error) {
		res.Outcome = outcome
		res.Output = cleanText(out.Text, protocol.MaxResultOutput, true)
		if out.Data != nil {
			if b, mErr := json.Marshal(out.Data); mErr == nil && len(b) <= protocol.MaxResultData {
				res.Data = b
			}
		}
		if err != nil {
			res.Error = cleanText(err.Error(), protocol.MaxResultError, false)
		}
		res.FinishedAt = now().UTC()
		switch outcome {
		case protocol.OutcomeDone:
			logger.Info("action done", "action_id", res.ID, "action_type", typ)
		case protocol.OutcomeFailed:
			logger.Warn("action failed", "action_id", res.ID, "action_type", typ, "error", res.Error)
		default:
			logger.Warn("action rejected", "action_id", res.ID, "action_type", typ, "outcome", outcome, "error", res.Error)
		}
		report(res)
	}

	params, err := protocol.DecodeParams(a)
	if err != nil {
		outcome := protocol.OutcomeInvalid
		if !protocol.IsAllowed(a.Type) {
			outcome = protocol.OutcomeRejected
		}
		finish(outcome, output{}, err)
		return
	}
	h, ok := handlers[a.Type]
	if !ok {
		// Allowed by the protocol but this agent build has no handler.
		finish(protocol.OutcomeRejected, output{}, errors.New("no handler for this action type in this agent version"))
		return
	}
	run := func() {
		out, err := h(d, ctx, params)
		if err != nil {
			finish(protocol.OutcomeFailed, out, err)
			return
		}
		finish(protocol.OutcomeDone, out, nil)
	}
	if !background[a.Type] {
		run()
		return
	}
	if !d.scanning.CompareAndSwap(false, true) {
		finish(protocol.OutcomeFailed, output{}, errors.New("another scan is already running on this endpoint"))
		return
	}
	go func() {
		defer d.scanning.Store(false)
		run()
	}()
}

func clamdCheck(d *Dispatcher, ctx context.Context, _ protocol.ActionParams) (output, error) {
	ctx, cancel := context.WithTimeout(ctx, quickTimeout)
	defer cancel()
	st := d.Clamd.Status(ctx)
	out := output{Data: st}
	switch {
	case st.Status != protocol.ClamdRunning:
		out.Text = "clamd: " + st.Status
		return out, fmt.Errorf("clamd is %s: %s", st.Status, st.Error)
	case st.SignatureVersion != 0 && st.SignatureDate != nil:
		out.Text = fmt.Sprintf("clamd running, ClamAV %s, signatures %d from %s", st.EngineVersion, st.SignatureVersion, st.SignatureDate.Format(time.RFC3339))
	default:
		out.Text = fmt.Sprintf("clamd running, ClamAV %s", st.EngineVersion)
	}
	if st.Error != "" {
		return out, errors.New(st.Error)
	}
	return out, nil
}

func clamdReload(d *Dispatcher, ctx context.Context, _ protocol.ActionParams) (output, error) {
	ctx, cancel := context.WithTimeout(ctx, quickTimeout)
	defer cancel()
	if err := d.Clamd.Reload(ctx); err != nil {
		return output{}, err
	}
	return output{Text: "clamd is reloading its signature databases"}, nil
}

func clamdStats(d *Dispatcher, ctx context.Context, _ protocol.ActionParams) (output, error) {
	ctx, cancel := context.WithTimeout(ctx, quickTimeout)
	defer cancel()
	s, err := d.Clamd.Stats(ctx)
	if err != nil {
		return output{}, err
	}
	return output{Text: s}, nil
}

// scanBudget leaves room in MaxResultData for the JSON around the lists.
const scanBudget = protocol.MaxResultData - 2048

func scanPath(d *Dispatcher, ctx context.Context, p protocol.ActionParams) (output, error) {
	requested := p.(*protocol.ScanPathParams).Path
	path, err := ResolveScanPath(requested, d.ScanRoots)
	if err != nil {
		return output{}, err
	}
	timeout := d.ScanTimeout
	if timeout <= 0 {
		timeout = DefaultScanTimeout
	}
	res := protocol.ScanResult{Path: cleanText(path, protocol.MaxScanPathLen, false), Infected: []protocol.ScanInfection{}, Errors: []protocol.ScanError{}}
	used := 0
	fits := func(n int) bool {
		if used+n > scanBudget {
			res.Truncated = true
			return false
		}
		used += n
		return true
	}
	start := time.Now()
	err = d.Clamd.ContScan(ctx, path, timeout, func(line string) {
		l, ok := clamd.ParseScanLine(line, path)
		if !ok {
			l = clamd.ScanLine{Kind: clamd.ScanError, Path: path, Detail: line}
		}
		fp := cleanText(l.Path, protocol.MaxScanPathLen, false)
		detail := cleanText(l.Detail, 200, false)
		switch l.Kind {
		case clamd.ScanFound:
			res.InfectedTotal++
			if fits(len(fp) + len(detail) + 40) {
				res.Infected = append(res.Infected, protocol.ScanInfection{Path: fp, Signature: detail})
			}
		case clamd.ScanError:
			res.ErrorsTotal++
			if fits(len(fp) + len(detail) + 40) {
				res.Errors = append(res.Errors, protocol.ScanError{Path: fp, Error: detail})
			}
		}
	})
	res.DurationMS = time.Since(start).Milliseconds()
	out := output{Data: res, Text: fmt.Sprintf("Scanned %s in %s: %d infected, %d could not be scanned",
		res.Path, time.Duration(res.DurationMS)*time.Millisecond, res.InfectedTotal, res.ErrorsTotal)}
	if res.Truncated {
		out.Text += " (lists cut to fit the size limit)"
	}
	if err != nil {
		return out, err
	}
	if res.ErrorsTotal == 1 && res.InfectedTotal == 0 && len(res.Errors) == 1 && strings.Contains(res.Errors[0].Error, "COMMAND UNAVAILABLE") {
		return out, errors.New("clamd refused the scan (COMMAND UNAVAILABLE)")
	}
	return out, nil
}

// cleanText caps s at max bytes (on a rune boundary) and replaces control
// characters and invalid UTF-8 with '?'. multiline keeps \n and \t.
func cleanText(s string, max int, multiline bool) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == utf8.RuneError:
			r = '?'
		case multiline && (r == '\n' || r == '\t'):
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0):
			r = '?'
		}
		if b.Len()+utf8.RuneLen(r) > max {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}
