package clamd

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// VersionInfo is the parsed reply to VERSION.
type VersionInfo struct {
	Engine           string
	SignatureVersion int        // 0 when clamd did not report signatures
	SignatureDate    *time.Time // UTC; nil when absent or unparsable
}

var engineRe = regexp.MustCompile(`^[0-9][0-9A-Za-z.+_-]{0,31}$`)

// clamd prints the signature date with ctime(3) in its local time zone,
// e.g. "Tue Sep 30 08:01:00 2026" (day padded with a space).
const ctimeLayout = "Mon Jan _2 15:04:05 2006"

// maxSignatureVersion is a sanity bound; daily.cvd is in the tens of thousands.
const maxSignatureVersion = 10_000_000

// ErrVersionDisabled means clamd answered VERSION with COMMAND UNAVAILABLE:
// the command is switched off in clamd.conf (ClamAV 1.5 packages may ship it
// that way).
var ErrVersionDisabled = errors.New(`clamd: the VERSION command is disabled; set "EnableVersionCommand yes" in clamd.conf and restart clamd`)

// ParseVersion parses "ClamAV 1.4.1/27410/Tue Sep 30 08:01:00 2026" or the
// bare "ClamAV 1.4.1" (no signature databases loaded). The date is
// interpreted in time.Local and returned in UTC.
func ParseVersion(reply string) (VersionInfo, error) {
	return parseVersionIn(reply, time.Local)
}

func parseVersionIn(reply string, loc *time.Location) (VersionInfo, error) {
	s := strings.TrimRight(reply, "\x00\r\n ")
	if s == "COMMAND UNAVAILABLE" {
		return VersionInfo{}, ErrVersionDisabled
	}
	rest, ok := strings.CutPrefix(s, "ClamAV ")
	if !ok {
		return VersionInfo{}, fmt.Errorf("clamd: unexpected VERSION reply %q", truncate(s, 60))
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 1 && len(parts) != 3 {
		return VersionInfo{}, fmt.Errorf("clamd: malformed VERSION reply %q", truncate(s, 60))
	}
	engine := strings.TrimSpace(parts[0])
	if !engineRe.MatchString(engine) {
		return VersionInfo{}, fmt.Errorf("clamd: invalid engine version %q", truncate(engine, 40))
	}
	info := VersionInfo{Engine: engine}
	if len(parts) == 1 {
		return info, nil
	}
	sv, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil || sv <= 0 || sv > maxSignatureVersion {
		return VersionInfo{Engine: engine}, fmt.Errorf("clamd: invalid signature version %q", truncate(parts[1], 20))
	}
	info.SignatureVersion = sv
	t, err := time.ParseInLocation(ctimeLayout, strings.TrimSpace(parts[2]), loc)
	if err != nil {
		return info, errors.New("clamd: unparsable signature date")
	}
	u := t.UTC()
	info.SignatureDate = &u
	return info, nil
}
