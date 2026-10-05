package clamd

import (
	"bufio"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Soup9x/Lake-Effect-Buoy/internal/protocol"
)

// fakeClamd serves canned replies on l. Tests may listen; the agent never does.
func fakeClamd(t *testing.T, l net.Listener, replies map[string]string, seen chan<- string) {
	t.Helper()
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				cmd, err := bufio.NewReader(c).ReadString(0)
				if err != nil {
					return
				}
				if seen != nil {
					seen <- cmd
				}
				if r, ok := replies[cmd]; ok {
					_, _ = c.Write([]byte(r))
				}
			}(c)
		}
	}()
}

func unixListener(t *testing.T) (net.Listener, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets")
	}
	// Short path: unix socket paths are limited to ~108 bytes.
	dir, err := os.MkdirTemp("", "cd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	p := filepath.Join(dir, "clamd.sock")
	l, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	return l, p
}

func TestParseAddress(t *testing.T) {
	good := map[string]Address{
		"unix:///run/clamav/clamd.ctl": {"unix", "/run/clamav/clamd.ctl"},
		"tcp://127.0.0.1:3310":         {"tcp", "127.0.0.1:3310"},
		"tcp://127.8.9.10:3310":        {"tcp", "127.8.9.10:3310"},
		"tcp://[::1]:3310":             {"tcp", "[::1]:3310"},
		"tcp://localhost:3310":         {"tcp", "localhost:3310"},
	}
	for in, want := range good {
		if runtime.GOOS == "windows" && want.Network == "unix" {
			continue
		}
		got, err := ParseAddress(in)
		if err != nil || got != want {
			t.Errorf("ParseAddress(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	bad := []string{
		"", "/run/clamav/clamd.ctl", "unix://", "unix://relative/sock", "unix:///run/../etc/x",
		"tcp://10.0.0.5:3310", "tcp://192.168.1.1:3310", "tcp://0.0.0.0:3310", "tcp://[::]:3310",
		"tcp://example.com:3310", "tcp://localhost.example.com:3310", "tcp://127.0.0.1",
		"tcp://127.0.0.1:0", "tcp://127.0.0.1:70000", "tcp://user@127.0.0.1:3310",
		"tcp://127.0.0.1:3310/path", "tcp://127.0.0.1:3310?x=1", "http://127.0.0.1:3310",
		"tcp://[::ffff:10.0.0.1]:3310", "tcp://[fe80::1%25lo]:3310",
	}
	for _, in := range bad {
		if a, err := ParseAddress(in); err == nil {
			t.Errorf("ParseAddress(%q) accepted: %v", in, a)
		}
	}
}

func TestDialTimeCheckRefusesNonLoopback(t *testing.T) {
	// A hand-built Address bypassing ParseAddress must still be refused.
	c := New(Address{Network: "tcp", Addr: "10.1.2.3:3310"})
	c.Timeout = time.Second
	if err := c.Ping(context.Background()); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("got %v", err)
	}
	if err := checkLoopbackDial("tcp", "10.1.2.3:3310"); err == nil {
		t.Fatal("dial check accepted non-loopback")
	}
	if err := checkLoopbackDial("tcp6", "[::1]:3310"); err != nil {
		t.Fatal(err)
	}
}

func TestStatusUnixSocket(t *testing.T) {
	l, p := unixListener(t)
	seen := make(chan string, 4)
	fakeClamd(t, l, map[string]string{
		"zPING\x00":    "PONG\x00",
		"zVERSION\x00": "ClamAV 1.4.1/27410/Tue Sep 30 08:01:00 2026\x00",
	}, seen)
	addr, err := ParseAddress("unix://" + p)
	if err != nil {
		t.Fatal(err)
	}
	st := New(addr).Status(context.Background())
	if st.Status != protocol.ClamdRunning || st.EngineVersion != "1.4.1" || st.SignatureVersion != 27410 || st.SignatureDate == nil || st.Error != "" {
		t.Fatalf("status = %+v", st)
	}
	// Only the two allowed commands were sent.
	close(seen)
	for cmd := range seen {
		if cmd != "zPING\x00" && cmd != "zVERSION\x00" {
			t.Fatalf("unexpected command %q", cmd)
		}
	}
}

func TestStatusTCPNoSignatures(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fakeClamd(t, l, map[string]string{
		"zPING\x00":    "PONG\x00",
		"zVERSION\x00": "ClamAV 1.4.1\x00",
	}, nil)
	addr, err := ParseAddress("tcp://" + l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	st := New(addr).Status(context.Background())
	if st.Status != protocol.ClamdRunning || st.EngineVersion != "1.4.1" || st.SignatureVersion != 0 || st.SignatureDate != nil {
		t.Fatalf("status = %+v", st)
	}
}

func TestStatusBadPong(t *testing.T) {
	l, p := unixListener(t)
	fakeClamd(t, l, map[string]string{"zPING\x00": "UNKNOWN COMMAND\x00"}, nil)
	st := New(Address{"unix", p}).Status(context.Background())
	if st.Status != protocol.ClamdNotResponding || st.Error == "" {
		t.Fatalf("status = %+v", st)
	}
}

func TestStatusHangingClamdTimesOut(t *testing.T) {
	l, p := unixListener(t)
	fakeClamd(t, l, map[string]string{}, nil) // never replies
	c := New(Address{"unix", p})
	c.Timeout = 200 * time.Millisecond
	start := time.Now()
	st := c.Status(context.Background())
	if st.Status != protocol.ClamdNotResponding || time.Since(start) > 3*time.Second {
		t.Fatalf("status = %+v after %v", st, time.Since(start))
	}
}

func TestStatusMissingSocket(t *testing.T) {
	addr := Address{"unix", filepath.Join(t.TempDir(), "nope.sock")}
	c := New(addr)
	c.Installed = func() bool { return true }
	if st := c.Status(context.Background()); st.Status != protocol.ClamdNotResponding {
		t.Fatalf("installed: %+v", st)
	}
	c.Installed = func() bool { return false }
	st := c.Status(context.Background())
	if st.Status != protocol.ClamdNotInstalled || len(st.Error) > MaxErrorLen {
		t.Fatalf("not installed: %+v", st)
	}
}

func TestStatusConnectionRefusedTCP(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	a := l.Addr().String()
	_ = l.Close()
	c := New(Address{"tcp", a})
	c.Installed = func() bool { return true }
	if st := c.Status(context.Background()); st.Status != protocol.ClamdNotResponding {
		t.Fatalf("%+v", st)
	}
}

func TestParseVersion(t *testing.T) {
	if _, err := ParseVersion("COMMAND UNAVAILABLE\x00"); !errors.Is(err, ErrVersionDisabled) || len(err.Error()) > MaxErrorLen {
		t.Fatalf("disabled VERSION: %v", err)
	}
	loc := time.FixedZone("X", 2*3600)
	v, err := parseVersionIn("ClamAV 1.4.1/27410/Tue Sep 30 08:01:00 2026\x00", loc)
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 9, 30, 6, 1, 0, 0, time.UTC)
	if v.Engine != "1.4.1" || v.SignatureVersion != 27410 || !v.SignatureDate.Equal(want) || v.SignatureDate.Location() != time.UTC {
		t.Fatalf("%+v", v)
	}
	// ctime pads single-digit days with a space.
	v, err = parseVersionIn("ClamAV 0.103.12/27001/Wed Sep  3 21:05:01 2025", time.UTC)
	if err != nil || v.SignatureDate.Day() != 3 || v.Engine != "0.103.12" {
		t.Fatalf("%+v %v", v, err)
	}
	v, err = parseVersionIn("ClamAV 1.5.0-rc", time.UTC)
	if err != nil || v.Engine != "1.5.0-rc" || v.SignatureVersion != 0 || v.SignatureDate != nil {
		t.Fatalf("%+v %v", v, err)
	}
	for _, bad := range []string{
		"", "PONG", "ClamAV", "ClamAV ", "ClamAV 1.4.1/27410", "ClamAV 1.4.1/x/Tue Sep 30 08:01:00 2026",
		"ClamAV 1.4.1/-5/Tue Sep 30 08:01:00 2026", "ClamAV <script>/1/x", "clamav 1.4.1",
		"ClamAV 1.4.1/1/2/3/4",
	} {
		if v, err := parseVersionIn(bad, time.UTC); err == nil {
			t.Errorf("accepted %q: %+v", bad, v)
		}
	}
	// A bad date keeps engine and signature version but reports an error.
	v, err = parseVersionIn("ClamAV 1.4.1/27410/garbage", time.UTC)
	if err == nil || v.Engine != "1.4.1" || v.SignatureVersion != 27410 || v.SignatureDate != nil {
		t.Fatalf("%+v %v", v, err)
	}
}

func TestTruncate(t *testing.T) {
	s := truncate(strings.Repeat("é", 300)+"\n", MaxErrorLen)
	if len(s) > MaxErrorLen {
		t.Fatal(len(s))
	}
	if got := truncate("a\x00b\nc", 10); got != "a?b?c" {
		t.Fatal(got)
	}
}

func FuzzParseVersion(f *testing.F) {
	for _, s := range []string{
		"ClamAV 1.4.1/27410/Tue Sep 30 08:01:00 2026",
		"ClamAV 1.4.1",
		"ClamAV 0.103.12/27001/Wed Sep  3 21:05:01 2025\x00",
		"ClamAV //",
		"",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		v, err := ParseVersion(s)
		if err != nil && v.Engine == "" && (v.SignatureVersion != 0 || v.SignatureDate != nil) {
			t.Fatalf("partial result without engine: %+v", v)
		}
		if v.Engine != "" && !engineRe.MatchString(v.Engine) {
			t.Fatalf("invalid engine accepted: %q", v.Engine)
		}
		if v.SignatureVersion < 0 || v.SignatureVersion > maxSignatureVersion {
			t.Fatalf("signature version out of range: %d", v.SignatureVersion)
		}
		if v.SignatureDate != nil && v.SignatureDate.Location() != time.UTC {
			t.Fatal("date not UTC")
		}
	})
}

func TestParseScanLine(t *testing.T) {
	cases := []struct {
		line, root string
		want       ScanLine
		ok         bool
	}{
		{"/srv/www: OK", "/srv/www", ScanLine{Kind: ScanOK, Path: "/srv/www"}, true},
		{"/srv/www/a.exe: Win.Test.EICAR_HDB-1 FOUND", "/srv/www", ScanLine{ScanFound, "/srv/www/a.exe", "Win.Test.EICAR_HDB-1"}, true},
		{"/srv/www/x: lstat() failed: Permission denied. ERROR", "/srv/www", ScanLine{ScanError, "/srv/www/x", "lstat() failed: Permission denied."}, true},
		// A ": " inside the scanned root does not split the line early.
		{"/srv/a: b/c.txt: Eicar FOUND", "/srv/a: b", ScanLine{ScanFound, "/srv/a: b/c.txt", "Eicar"}, true},
		{`C:\Data\x.doc: Doc.Macro FOUND`, `C:\Data`, ScanLine{ScanFound, `C:\Data\x.doc`, "Doc.Macro"}, true},
		{"garbage", "/srv", ScanLine{}, false},
		{"no separator FOUND", "/srv", ScanLine{}, false},
	}
	for _, c := range cases {
		got, ok := ParseScanLine(c.line, c.root)
		if ok != c.ok || got != c.want {
			t.Errorf("%q: got %+v %v, want %+v %v", c.line, got, ok, c.want, c.ok)
		}
	}
}

func TestReloadStatsContScan(t *testing.T) {
	l, sock := unixListener(t)
	seen := make(chan string, 10)
	fakeClamd(t, l, map[string]string{
		"zRELOAD\x00":                 "RELOADING\x00",
		"zSTATS\x00":                  "POOLS: 1\n\nSTATE: VALID PRIMARY\nTHREADS: live 1  idle 0 max 10\nQUEUE: 0 items\nEND\x00",
		"zCONTSCAN /srv/www\x00":      "/srv/www/a: Eicar FOUND\x00/srv/www/b: Permission denied. ERROR\x00",
		"zCONTSCAN /srv/disabled\x00": "COMMAND UNAVAILABLE\x00",
	}, seen)
	c := New(Address{Network: "unix", Addr: sock})
	ctx := context.Background()
	if err := c.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	stats, err := c.Stats(ctx)
	if err != nil || !strings.Contains(stats, "THREADS: live 1") || strings.Contains(stats, "END") {
		t.Fatalf("stats %q %v", stats, err)
	}
	var lines []string
	if err := c.ContScan(ctx, "/srv/www", time.Minute, func(l string) { lines = append(lines, l) }); err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 || lines[0] != "/srv/www/a: Eicar FOUND" {
		t.Fatalf("lines %q", lines)
	}
	// A path that could smuggle a second command never reaches clamd.
	for _, bad := range []string{"/srv/www\x00zSHUTDOWN", "/srv\nSHUTDOWN", "relative"} {
		if err := c.ContScan(ctx, bad, time.Minute, func(string) {}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	close(seen)
	for cmd := range seen {
		if strings.Contains(cmd, "SHUTDOWN") {
			t.Fatalf("clamd received %q", cmd)
		}
	}
}

func TestReloadStatsDisabled(t *testing.T) {
	l, sock := unixListener(t)
	fakeClamd(t, l, map[string]string{"zRELOAD\x00": "COMMAND UNAVAILABLE\x00", "zSTATS\x00": "COMMAND UNAVAILABLE\x00"}, nil)
	c := New(Address{Network: "unix", Addr: sock})
	if err := c.Reload(context.Background()); err == nil || !strings.Contains(err.Error(), "EnableReloadCommand") {
		t.Errorf("reload: %v", err)
	}
	if _, err := c.Stats(context.Background()); err == nil || !strings.Contains(err.Error(), "EnableStatsCommand") {
		t.Errorf("stats: %v", err)
	}
}
