package clamd

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/Soup9x/Lake-Effect-Buoy/internal/protocol"
)

// DefaultTimeout bounds every clamd exchange (dial + command + reply).
const DefaultTimeout = 5 * time.Second

// maxReply caps how much of a clamd reply is read.
const maxReply = 1024

// MaxErrorLen caps ClamAVStatus.Error.
const MaxErrorLen = 200

// Client talks to one clamd endpoint.
type Client struct {
	Addr    Address
	Timeout time.Duration
	// Installed reports whether ClamAV appears to be installed; used to tell
	// not_installed from not_responding. Defaults to an OS-specific check.
	Installed func() bool
}

// New returns a client for a validated address.
func New(addr Address) *Client {
	return &Client{Addr: addr, Timeout: DefaultTimeout, Installed: Installed}
}

func (c *Client) timeout() time.Duration {
	if c.Timeout <= 0 {
		return DefaultTimeout
	}
	return c.Timeout
}

// dial connects to clamd, re-validating the address (it may have been built
// by hand), and sets the connection deadline from ctx.
func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	if c.Addr.Network == "tcp" {
		if _, err := ParseAddress(c.Addr.String()); err != nil {
			return nil, err
		}
	} else if c.Addr.Network != "unix" {
		return nil, fmt.Errorf("clamd: unsupported network %q", c.Addr.Network)
	}
	d := net.Dialer{
		// Check the actual resolved address, so "localhost" cannot be
		// redirected off-host via a tampered hosts file.
		Control: func(network, address string, _ syscall.RawConn) error {
			return checkLoopbackDial(network, address)
		},
	}
	conn, err := d.DialContext(ctx, c.Addr.Network, c.Addr.Addr)
	if err != nil {
		return nil, &DialError{Err: err}
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	return conn, nil
}

// command sends one fixed z-command and returns the NUL-terminated reply.
// cmd is always a constant from this package.
func (c *Client) command(ctx context.Context, cmd string) (string, error) {
	return c.commandN(ctx, cmd, maxReply)
}

// commandN is command with a reply size limit.
func (c *Client) commandN(ctx context.Context, cmd string, limit int64) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()
	conn, err := c.dial(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte("z" + cmd + "\x00")); err != nil {
		return "", fmt.Errorf("clamd: write %s: %w", cmd, err)
	}
	r := bufio.NewReader(io.LimitReader(conn, limit))
	reply, err := r.ReadBytes(0)
	if err != nil && (!errors.Is(err, io.EOF) || len(reply) == 0) {
		return "", fmt.Errorf("clamd: read %s reply: %w", cmd, err)
	}
	return string(bytes.TrimRight(reply, "\x00\r\n ")), nil
}

// DialError wraps a failure to connect to clamd.
type DialError struct{ Err error }

func (e *DialError) Error() string { return "clamd: connect: " + e.Err.Error() }
func (e *DialError) Unwrap() error { return e.Err }

// Ping sends PING and expects PONG.
func (c *Client) Ping(ctx context.Context) error {
	reply, err := c.command(ctx, "PING")
	if err != nil {
		return err
	}
	if reply != "PONG" {
		return fmt.Errorf("clamd: unexpected PING reply %q", truncate(reply, 40))
	}
	return nil
}

// Reload sends RELOAD, which makes clamd reload its signature databases.
func (c *Client) Reload(ctx context.Context) error {
	reply, err := c.command(ctx, "RELOAD")
	if err != nil {
		return err
	}
	switch reply {
	case "RELOADING":
		return nil
	case "COMMAND UNAVAILABLE":
		return errors.New(`clamd: the RELOAD command is disabled; set "EnableReloadCommand yes" in clamd.conf and restart clamd`)
	}
	return fmt.Errorf("clamd: unexpected RELOAD reply %q", truncate(reply, 60))
}

// maxStatsReply caps the STATS reply.
const maxStatsReply = 16 << 10

// Stats sends STATS and returns clamd's report (pools, threads, queue,
// memory) as text.
func (c *Client) Stats(ctx context.Context) (string, error) {
	reply, err := c.commandN(ctx, "STATS", maxStatsReply)
	if err != nil {
		return "", err
	}
	if reply == "COMMAND UNAVAILABLE" {
		return "", errors.New(`clamd: the STATS command is disabled; set "EnableStatsCommand yes" in clamd.conf and restart clamd`)
	}
	if !strings.HasPrefix(reply, "POOLS:") {
		return "", fmt.Errorf("clamd: unexpected STATS reply %q", truncate(reply, 60))
	}
	return strings.TrimSuffix(reply, "END"), nil
}

// maxScanLine caps one line of scan output.
const maxScanLine = 8 << 10

// ContScan asks clamd to scan path (CONTSCAN: recursive, does not stop at
// the first infection) and calls onLine with each reply line, until clamd
// closes the connection or timeout passes. path is data appended to the
// fixed command; it must be absolute and free of control characters, which
// is checked here again so it can never smuggle in a second command.
func (c *Client) ContScan(ctx context.Context, path string, timeout time.Duration, onLine func(string)) error {
	windowsAbs := len(path) >= 3 && path[1] == ':' && path[2] == '\\'
	if !strings.HasPrefix(path, "/") && !windowsAbs {
		return errors.New("clamd: scan path must be absolute")
	}
	for _, r := range path {
		if r < 0x20 || r == 0x7f {
			return errors.New("clamd: scan path contains a control character")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := c.dial(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	// Close the connection if ctx is cancelled, which also stops clamd's scan.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if _, err := conn.Write([]byte("zCONTSCAN " + path + "\x00")); err != nil {
		return fmt.Errorf("clamd: write CONTSCAN: %w", err)
	}
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 4096), maxScanLine)
	sc.Split(splitNUL)
	for sc.Scan() {
		if line := strings.TrimRight(sc.Text(), "\r\n "); line != "" {
			onLine(line)
		}
	}
	if err := sc.Err(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("clamd: scan stopped: %w", ctx.Err())
		}
		return fmt.Errorf("clamd: read scan results: %w", err)
	}
	return nil
}

// splitNUL is a bufio.SplitFunc for NUL-terminated replies.
func splitNUL(data []byte, atEOF bool) (int, []byte, error) {
	if i := bytes.IndexByte(data, 0); i >= 0 {
		return i + 1, data[:i], nil
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

// Version sends VERSION and parses the reply.
func (c *Client) Version(ctx context.Context) (VersionInfo, error) {
	reply, err := c.command(ctx, "VERSION")
	if err != nil {
		return VersionInfo{}, err
	}
	return ParseVersion(reply)
}

// Status queries clamd once and maps the outcome onto the protocol status.
func (c *Client) Status(ctx context.Context) protocol.ClamAVStatus {
	if err := c.Ping(ctx); err != nil {
		var de *DialError
		if errors.As(err, &de) && c.Installed != nil && !c.Installed() {
			return protocol.ClamAVStatus{Status: protocol.ClamdNotInstalled, Error: capError(err)}
		}
		if errors.Is(err, os.ErrPermission) {
			err = fmt.Errorf("%w (is the agent user in the clamd socket's group?)", err)
		}
		return protocol.ClamAVStatus{Status: protocol.ClamdNotResponding, Error: capError(err)}
	}
	st := protocol.ClamAVStatus{Status: protocol.ClamdRunning}
	v, err := c.Version(ctx)
	if v.Engine != "" {
		st.EngineVersion = v.Engine
		st.SignatureVersion = v.SignatureVersion
		st.SignatureDate = v.SignatureDate
	}
	if err != nil {
		st.Error = capError(err)
	}
	return st
}

func capError(err error) string { return truncate(err.Error(), MaxErrorLen) }

func truncate(s string, n int) string {
	// Keep it valid UTF-8, printable, and at most n bytes (so also at most
	// n characters) for the server's validators.
	var b []byte
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == 0xfffd {
			r = '?'
		}
		if len(b)+utf8.RuneLen(r) > n {
			break
		}
		b = utf8.AppendRune(b, r)
	}
	return string(b)
}
