package clamd

import "strings"

// Kinds of scan result lines.
const (
	ScanOK    = "ok"
	ScanFound = "found"
	ScanError = "error"
)

// ScanLine is one parsed line of CONTSCAN output.
type ScanLine struct {
	Kind   string // ScanOK, ScanFound or ScanError
	Path   string
	Detail string // the signature name (found) or error message (error)
}

// ParseScanLine parses clamd's "<path>: OK", "<path>: <signature> FOUND" and
// "<path>: <message> ERROR" lines. root is the path that was scanned: every
// result path starts with it, so the ": " separator is looked for after it,
// which keeps a ": " inside a directory name from splitting the line early.
// ok is false for lines in another format.
func ParseScanLine(line, root string) (ScanLine, bool) {
	var kind string
	switch {
	case strings.HasSuffix(line, " FOUND"):
		kind, line = ScanFound, strings.TrimSuffix(line, " FOUND")
	case strings.HasSuffix(line, " ERROR"):
		kind, line = ScanError, strings.TrimSuffix(line, " ERROR")
	case strings.HasSuffix(line, ": OK"):
		return ScanLine{Kind: ScanOK, Path: strings.TrimSuffix(line, ": OK")}, true
	default:
		return ScanLine{}, false
	}
	from := 0
	if strings.HasPrefix(line, root) {
		from = len(root)
	}
	i := strings.Index(line[from:], ": ")
	if i < 0 {
		return ScanLine{}, false
	}
	i += from
	return ScanLine{Kind: kind, Path: line[:i], Detail: strings.TrimSpace(line[i+2:])}, true
}
