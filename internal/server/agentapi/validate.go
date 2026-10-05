package agentapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/Soup9x/Lake-Effect-Buoy/internal/protocol"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/server/store"
)

var (
	reVersion   = regexp.MustCompile(`^[0-9A-Za-z.+_~-]{1,64}$`)
	reMachineID = regexp.MustCompile(`^[0-9A-Za-z{}_-]{1,128}$`)
	reArch      = regexp.MustCompile(`^[a-z0-9_]{1,16}$`)
)

// printable rejects control characters and caps length.
func printable(field, s string, min, max int) error {
	if n := len(s); n < min || n > max {
		return fmt.Errorf("%s must be %d..%d bytes", field, min, max)
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return fmt.Errorf("%s contains non-printable characters", field)
		}
	}
	return nil
}

func validHostname(s string) error {
	if err := printable("hostname", s, 1, 253); err != nil {
		return err
	}
	if strings.ContainsAny(s, " <>\"'`&;|$\\/") {
		return errors.New("hostname contains invalid characters")
	}
	return nil
}

func validateEnroll(r *protocol.EnrollRequest) error {
	var errs []error
	if !strings.HasPrefix(r.EnrollmentToken, protocol.EnrollTokenPrefix) || len(r.EnrollmentToken) > 128 {
		errs = append(errs, errors.New("enrollment_token is malformed"))
	}
	if !reMachineID.MatchString(r.MachineID) {
		errs = append(errs, errors.New("machine_id is invalid"))
	}
	errs = append(errs, validHostname(r.Hostname))
	if r.OSFamily != "linux" && r.OSFamily != "windows" {
		errs = append(errs, errors.New("os_family must be linux or windows"))
	}
	errs = append(errs, printable("os_name", r.OSName, 0, 200), printable("os_version", r.OSVersion, 0, 100))
	if !reArch.MatchString(r.Arch) {
		errs = append(errs, errors.New("arch is invalid"))
	}
	if !reVersion.MatchString(r.AgentVersion) {
		errs = append(errs, errors.New("agent_version is invalid"))
	}
	return errors.Join(errs...)
}

func validateHeartbeat(r *protocol.HeartbeatRequest, now time.Time) error {
	var errs []error
	errs = append(errs, validHostname(r.Hostname),
		printable("os_name", r.OSName, 0, 200), printable("os_version", r.OSVersion, 0, 100))
	if !reVersion.MatchString(r.AgentVersion) {
		errs = append(errs, errors.New("agent_version is invalid"))
	}
	errs = append(errs, validateClamAV(&r.ClamAV, now))
	return errors.Join(errs...)
}

// validateClamAV checks a clamd status report (heartbeat, clamd_check result).
func validateClamAV(c *protocol.ClamAVStatus, now time.Time) error {
	var errs []error
	switch c.Status {
	case protocol.ClamdRunning, protocol.ClamdNotResponding, protocol.ClamdNotInstalled, protocol.ClamdUnknown:
	default:
		errs = append(errs, errors.New("clamav.status is invalid"))
	}
	if c.EngineVersion != "" && !reVersion.MatchString(c.EngineVersion) {
		errs = append(errs, errors.New("clamav.engine_version is invalid"))
	}
	if c.SignatureVersion < 0 || c.SignatureVersion > 100_000_000 {
		errs = append(errs, errors.New("clamav.signature_version is out of range"))
	}
	if c.SignatureDate != nil {
		if c.SignatureDate.Year() < 2000 || c.SignatureDate.After(now.Add(48*time.Hour)) {
			errs = append(errs, errors.New("clamav.signature_date is out of range"))
		}
	}
	errs = append(errs, printable("clamav.error", c.Error, 0, 500))
	return errors.Join(errs...)
}

// Result list limits (the agent cuts its lists well below these).
const (
	maxScanListLen = 2000
	maxScanTotal   = 1_000_000_000
)

// validateActionResult checks an agent's result against the action's type
// and returns what to store. Text is sanitised rather than rejected (it is
// the agent's report, not input that drives anything); structure is strict.
func validateActionResult(typ protocol.ActionType, r *protocol.ActionResult, now time.Time) (store.ActionResultUpdate, error) {
	var u store.ActionResultUpdate
	switch r.Outcome {
	case protocol.OutcomeDone:
		u.Status = store.ActionDone
	case protocol.OutcomeFailed:
		u.Status = store.ActionFailed
	case protocol.OutcomeRejected, protocol.OutcomeInvalid:
		u.Status = store.ActionRejected
	default:
		return u, errors.New("outcome is invalid")
	}
	if len(r.Output) > protocol.MaxResultOutput {
		return u, errors.New("output is too long")
	}
	if len(r.Error) > protocol.MaxResultError {
		return u, errors.New("error is too long")
	}
	if len(r.Data) > protocol.MaxResultData {
		return u, errors.New("data is too large")
	}
	u.Output = sanitizeText(r.Output, true)
	u.Error = sanitizeText(r.Error, false)

	if len(r.Data) > 0 && string(r.Data) != "null" {
		var err error
		switch typ {
		case protocol.ActionClamdCheck:
			u.Data, err = validateCheckData(r.Data, now)
		case protocol.ActionScanPath:
			u.Data, err = validateScanData(r.Data)
		default:
			err = fmt.Errorf("%s results carry no data", typ)
		}
		if err != nil {
			return u, fmt.Errorf("data: %w", err)
		}
	}

	// Agent clocks drift; keep plausible times, else use the server's.
	u.StartedAt, u.FinishedAt = r.StartedAt.UTC(), r.FinishedAt.UTC()
	plausible := func(t time.Time) bool { return !t.Before(now.Add(-30*24*time.Hour)) && !t.After(now.Add(time.Hour)) }
	if !plausible(u.StartedAt) || !plausible(u.FinishedAt) || u.FinishedAt.Before(u.StartedAt) {
		u.StartedAt, u.FinishedAt = now.UTC(), now.UTC()
	}
	return u, nil
}

func strictDecode(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

func validateCheckData(raw []byte, now time.Time) ([]byte, error) {
	var st protocol.ClamAVStatus
	if err := strictDecode(raw, &st); err != nil {
		return nil, err
	}
	if err := validateClamAV(&st, now); err != nil {
		return nil, err
	}
	return json.Marshal(st)
}

func validateScanData(raw []byte) ([]byte, error) {
	var sr protocol.ScanResult
	if err := strictDecode(raw, &sr); err != nil {
		return nil, err
	}
	if err := protocol.ValidateScanPath(sr.Path); err != nil {
		return nil, fmt.Errorf("path: %w", err)
	}
	if len(sr.Infected) > maxScanListLen || len(sr.Errors) > maxScanListLen {
		return nil, errors.New("too many entries")
	}
	if sr.InfectedTotal < len(sr.Infected) || sr.InfectedTotal > maxScanTotal ||
		sr.ErrorsTotal < len(sr.Errors) || sr.ErrorsTotal > maxScanTotal || sr.DurationMS < 0 {
		return nil, errors.New("counts are inconsistent")
	}
	for i := range sr.Infected {
		in := &sr.Infected[i]
		if len(in.Path) > protocol.MaxScanPathLen || len(in.Signature) > 200 {
			return nil, errors.New("an infection entry is too long")
		}
		in.Path, in.Signature = sanitizeText(in.Path, false), sanitizeText(in.Signature, false)
	}
	for i := range sr.Errors {
		e := &sr.Errors[i]
		if len(e.Path) > protocol.MaxScanPathLen || len(e.Error) > 200 {
			return nil, errors.New("an error entry is too long")
		}
		e.Path, e.Error = sanitizeText(e.Path, false), sanitizeText(e.Error, false)
	}
	if sr.Infected == nil {
		sr.Infected = []protocol.ScanInfection{}
	}
	if sr.Errors == nil {
		sr.Errors = []protocol.ScanError{}
	}
	return json.Marshal(sr)
}

// sanitizeText replaces control characters (except \n and \t when multiline)
// with '?'. JSON decoding has already replaced invalid UTF-8.
func sanitizeText(s string, multiline bool) string {
	return strings.Map(func(r rune) rune {
		if multiline && (r == '\n' || r == '\t') {
			return r
		}
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == ' ' || r == ' ' {
			return '?'
		}
		return r
	}, s)
}
