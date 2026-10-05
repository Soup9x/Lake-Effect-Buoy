package actions

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrNoScanRoots means this endpoint allows no scans.
var ErrNoScanRoots = errors.New("scans are not enabled on this endpoint: no scan_roots in its agent config (set them with the installer's --scan-roots or clamav-agent set-scan-roots)")

// ResolveScanPath returns the path clamd should scan for the requested path,
// or an error unless it is one of roots or inside one. Symlinks are resolved
// on both sides first, so a link inside a root cannot lead outside it. The
// path must exist.
func ResolveScanPath(requested string, roots []string) (string, error) {
	if len(roots) == 0 {
		return "", ErrNoScanRoots
	}
	if !filepath.IsAbs(requested) {
		return "", fmt.Errorf("%q is not an absolute path on this endpoint", requested)
	}
	p, err := filepath.EvalSymlinks(filepath.Clean(requested))
	if err != nil {
		return "", fmt.Errorf("cannot scan %q: %w", requested, unwrapPathError(err))
	}
	if _, err := os.Stat(p); err != nil {
		return "", fmt.Errorf("cannot scan %q: %w", requested, unwrapPathError(err))
	}
	for _, root := range roots {
		r, err := filepath.EvalSymlinks(filepath.Clean(root))
		if err != nil {
			continue // a configured root that does not exist allows nothing
		}
		if within(r, p) {
			return p, nil
		}
	}
	return "", fmt.Errorf("%q is outside this endpoint's scan roots (%s)", requested, strings.Join(roots, ", "))
}

// within reports whether p is root or below it. filepath.Rel compares
// case-insensitively on Windows.
func within(root, p string) bool {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

func unwrapPathError(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}
