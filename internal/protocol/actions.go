package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// ActionType is the closed set of things the server may ask an agent to do.
//
// SECURITY: this is the allowlist required by CLAUDE.md rule 1. Adding a type
// is a security change: it needs a typed params struct with Validate(), a
// handler in internal/agent/actions, and malicious-input tests, all in the
// same change. There is no generic "run command" type and there never will be.
// Every handler talks to clamd with a fixed protocol command; none starts a
// process.
type ActionType string

const (
	// ActionClamdCheck pings clamd and reads its version and signature date.
	ActionClamdCheck ActionType = "clamd_check"
	// ActionClamdReload asks clamd to reload its signature databases (RELOAD).
	ActionClamdReload ActionType = "clamd_reload"
	// ActionClamdStats returns clamd's STATS output.
	ActionClamdStats ActionType = "clamd_stats"
	// ActionScanPath asks clamd to scan a path (CONTSCAN). The agent only
	// accepts paths under the scan roots in its LOCAL config; the server
	// cannot widen them.
	ActionScanPath ActionType = "scan_path"
)

var allowedActions = map[ActionType]func() ActionParams{
	ActionClamdCheck:  func() ActionParams { return &NoParams{} },
	ActionClamdReload: func() ActionParams { return &NoParams{} },
	ActionClamdStats:  func() ActionParams { return &NoParams{} },
	ActionScanPath:    func() ActionParams { return &ScanPathParams{} },
}

// ActionTypes lists the allowlist in a stable order (for the UI).
var ActionTypes = []ActionType{ActionClamdCheck, ActionClamdReload, ActionClamdStats, ActionScanPath}

// ActionParams is implemented by every typed parameter struct.
type ActionParams interface {
	Validate() error
}

// NoParams is the parameter struct of actions that take none.
type NoParams struct{}

func (*NoParams) Validate() error { return nil }

// ScanPathParams is the parameter struct of scan_path.
type ScanPathParams struct {
	Path string `json:"path"`
}

func (p *ScanPathParams) Validate() error { return ValidateScanPath(p.Path) }

// MaxScanPathLen caps a scan path.
const MaxScanPathLen = 1024

// ValidateScanPath checks a scan path's shape, independent of the agent's OS:
// an absolute Unix path ("/srv/www") or Windows drive path ("D:\Data"), no
// "." or ".." components, no control characters, valid UTF-8. The agent
// additionally requires it to resolve inside one of its local scan roots.
func ValidateScanPath(p string) error {
	switch {
	case p == "":
		return errors.New("path is required")
	case len(p) > MaxScanPathLen:
		return fmt.Errorf("path is longer than %d bytes", MaxScanPathLen)
	case !utf8.ValidString(p):
		return errors.New("path is not valid UTF-8")
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return errors.New("path contains a control character")
		}
	}
	unix := strings.HasPrefix(p, "/")
	windows := len(p) >= 3 && isASCIILetter(p[0]) && p[1] == ':' && p[2] == '\\'
	if !unix && !windows {
		return errors.New(`path must be absolute, like /srv/www or D:\Data`)
	}
	if unix && strings.HasPrefix(p, "//") {
		return errors.New("path must not start with //")
	}
	if windows && strings.ContainsRune(p, '/') {
		return errors.New(`a Windows path must use \ only`)
	}
	sep := "/"
	if windows {
		sep = `\`
	}
	for _, part := range strings.Split(p, sep) {
		if part == "." || part == ".." {
			return errors.New(`path must not contain "." or ".." components`)
		}
	}
	return nil
}

func isASCIILetter(b byte) bool { return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') }

// Action is a unit of work sent in a heartbeat response.
type Action struct {
	ID     string          `json:"id"`
	Type   ActionType      `json:"type"`
	Params json.RawMessage `json:"params"`
}

// ErrUnknownAction is reported back when an agent receives a type it does not
// know. The agent never attempts to interpret it.
type ErrUnknownAction struct{ Type ActionType }

func (e ErrUnknownAction) Error() string {
	return fmt.Sprintf("action type %q is not in the allowlist", e.Type)
}

// IsAllowed reports whether t is a known action type.
func IsAllowed(t ActionType) bool {
	_, ok := allowedActions[t]
	return ok
}

// DecodeParams strictly decodes and validates an action's parameters. Unknown
// types, unknown fields, trailing data and invalid values are all rejected.
// Empty params mean {}.
func DecodeParams(a Action) (ActionParams, error) {
	newParams, ok := allowedActions[a.Type]
	if !ok {
		return nil, ErrUnknownAction{Type: a.Type}
	}
	raw := a.Params
	if len(strings.TrimSpace(string(raw))) == 0 {
		raw = json.RawMessage(`{}`)
	}
	p := newParams()
	dec := json.NewDecoder(bytesReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(p); err != nil {
		return nil, fmt.Errorf("decode params for %q: %w", a.Type, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("decode params for %q: trailing data", a.Type)
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("invalid params for %q: %w", a.Type, err)
	}
	return p, nil
}

// ---- results ----

// PathActionResult is where an agent reports the result of one action.
const PathActionResult = BasePath + "/actions/result"

// Action outcomes reported by the agent.
const (
	OutcomeDone     = "done"
	OutcomeFailed   = "failed"
	OutcomeRejected = "rejected_unknown_action"
	OutcomeInvalid  = "rejected_invalid_params"
)

// Result size limits. The whole request must also fit MaxRequestBytes.
const (
	MaxResultOutput = 16 << 10
	MaxResultData   = 40 << 10
	MaxResultError  = 500
)

// ActionResult reports what happened to one action.
type ActionResult struct {
	ID      string `json:"id"`
	Outcome string `json:"outcome"`
	// Output is human-readable text (e.g. clamd STATS), capped at MaxResultOutput.
	Output string `json:"output,omitempty"`
	// Data is the structured result: ClamAVStatus for clamd_check,
	// ScanResult for scan_path. Capped at MaxResultData.
	Data       json.RawMessage `json:"data,omitempty"`
	Error      string          `json:"error,omitempty"`
	StartedAt  time.Time       `json:"started_at"`
	FinishedAt time.Time       `json:"finished_at"`
}

// ScanResult is the Data of a scan_path result.
type ScanResult struct {
	Path string `json:"path"`
	// Infected lists infected files; InfectedTotal counts all of them even
	// when the list was cut to fit the size limit.
	Infected      []ScanInfection `json:"infected"`
	InfectedTotal int             `json:"infected_total"`
	// Errors lists files clamd could not scan (often permissions).
	Errors      []ScanError `json:"errors"`
	ErrorsTotal int         `json:"errors_total"`
	Truncated   bool        `json:"truncated,omitempty"`
	DurationMS  int64       `json:"duration_ms"`
}

type ScanInfection struct {
	Path      string `json:"path"`
	Signature string `json:"signature"`
}

type ScanError struct {
	Path  string `json:"path"`
	Error string `json:"error"`
}
