package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/Soup9x/Lake-Effect-Buoy/internal/agent/actions"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/agent/clamd"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/agent/config"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/agent/credstore"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/agent/enroll"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/agent/heartbeat"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/agent/logging"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/agent/sysinfo"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/agent/transport"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/protocol"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/release"
)

// pathFlags registers the shared --config and --credential flags.
func pathFlags(fs *flag.FlagSet) (cfg, cred *string) {
	cfg = fs.String("config", config.ConfigPath(), "config file path")
	cred = fs.String("credential", config.CredentialPath(), "credential file path")
	return cfg, cred
}

func parseFlags(fs *flag.FlagSet, args []string) bool {
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return false
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "unexpected arguments: %v\n", fs.Args())
		return false
	}
	return true
}

// ---- enroll ----

func enrollCmd(args []string) int {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	cfgPath, credPath := pathFlags(fs)
	server := fs.String("server", "", "console base URL (https://...)")
	clamdAddr := fs.String("clamd", config.DefaultClamdAddress, "clamd address: unix:///path or tcp://127.0.0.1:PORT")
	replace := fs.Bool("replace", false, "re-enroll, replacing an existing agent for this machine")
	pin := fs.String("ca-cert-pin", "", "optional base64 SHA-256 SPKI pin for the console's certificate chain")
	caFile := fs.String("ca-cert-file", "", "optional absolute path to a PEM file with the console's private CA; only these CAs are then trusted")
	insecure := fs.Bool("insecure-http-for-testing", false, "allow an http:// server URL (TESTING ONLY)")
	if !parseFlags(fs, args) {
		return exitUsage
	}
	if *server == "" {
		fmt.Fprintln(os.Stderr, "enroll: --server is required")
		return exitUsage
	}
	cfg := config.Config{
		ServerURL:              *server,
		Clamd:                  config.ClamdConfig{Address: *clamdAddr},
		CACertPin:              *pin,
		CACertFile:             *caFile,
		LogLevel:               "info",
		InsecureHTTPForTesting: *insecure,
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, "enroll:", err)
		return exitUsage
	}
	if cfg.InsecureHTTPForTesting {
		fmt.Fprintln(os.Stderr, "WARNING: insecure_http_for_testing is set. The credential will be sent without TLS. NEVER use this in production.")
	}
	if (credstore.Store{Path: *credPath}).Exists() && !*replace {
		fmt.Fprintln(os.Stderr, "enroll:", enroll.ErrAlreadyEnrolled)
		return exitError
	}
	token, err := readToken(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "enroll:", err)
		return exitUsage
	}
	pinBytes, _ := cfg.Pin()
	roots, err := cfg.RootCAs()
	if err != nil {
		fmt.Fprintln(os.Stderr, "enroll:", err)
		return exitUsage
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := enroll.Run(ctx, enroll.Options{
		Config:         cfg,
		ConfigPath:     *cfgPath,
		CredentialPath: *credPath,
		Token:          token,
		Version:        version,
		Replace:        *replace,
		HTTP:           transport.NewClient(transport.Options{SPKIPin: pinBytes, RootCAs: roots}),
		Info:           sysinfo.Collect(),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "enroll:", err)
		return exitError
	}
	fmt.Printf("Enrolled in tenant %q (agent id %s).\nConfig: %s\nCredential: %s\n", res.TenantName, res.AgentID, *cfgPath, *credPath)
	return exitOK
}

// readToken reads the enrollment token from CAV_ENROLL_TOKEN or stdin, never
// from argv (which other users can see in the process list).
func readToken(stdin *os.File) (string, error) {
	if t := strings.TrimSpace(os.Getenv("CAV_ENROLL_TOKEN")); t != "" {
		_ = os.Unsetenv("CAV_ENROLL_TOKEN")
		return t, enroll.ValidateToken(t)
	}
	fd := int(stdin.Fd())
	if term.IsTerminal(fd) {
		fmt.Fprint(os.Stderr, "Enrollment token: ")
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		t := strings.TrimSpace(string(b))
		return t, enroll.ValidateToken(t)
	}
	line, err := bufio.NewReader(io.LimitReader(stdin, 1024)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	t := strings.TrimSpace(line)
	if t == "" {
		return "", errors.New("no enrollment token: set CAV_ENROLL_TOKEN or pipe it on stdin")
	}
	return t, enroll.ValidateToken(t)
}

// ---- run ----

func runCmd(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	cfgPath, credPath := pathFlags(fs)
	if !parseFlags(fs, args) {
		return exitUsage
	}
	if isWindowsService() {
		return runService(func(ctx context.Context) int { return runAgent(ctx, *cfgPath, *credPath) })
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runAgent(ctx, *cfgPath, *credPath)
}

// runAgent runs until ctx is done (exit 0) or the agent must stop for good
// (exit 78: revoked, not enrolled, or unusable config).
func runAgent(ctx context.Context, cfgPath, credPath string) int {
	var level slog.LevelVar
	logger, closer := logging.New(&level, config.LogDir())
	defer func() { _ = closer.Close() }()
	slog.SetDefault(logger)

	cfg, err := config.Load(cfgPath)
	if err != nil {
		logger.Error("cannot load configuration; not starting", "path", cfgPath, "error", err)
		return exitConfig
	}
	level.Set(logging.ParseLevel(cfg.LogLevel))
	logger.Info("clamav-agent starting", "version", version, "server", cfg.ServerURL, "clamd", cfg.Clamd.Address,
		"pinned", cfg.CACertPin != "", "ca_cert_file", cfg.CACertFile)
	if cfg.InsecureHTTPForTesting {
		logger.Error("INSECURE: insecure_http_for_testing is enabled; the credential may be sent without TLS. NEVER use this in production.")
	}
	pin, _ := cfg.Pin() // validated by Load
	roots, err := cfg.RootCAs()
	if err != nil {
		logger.Error("cannot load ca_cert_file; not starting", "error", err)
		return exitConfig
	}
	addr, _ := clamd.ParseAddress(cfg.Clamd.Address)
	cc := clamd.New(addr)
	disp := &actions.Dispatcher{Logger: logger, Clamd: cc, ScanRoots: cfg.ScanRoots}

	lastStatus := ""
	agent := &heartbeat.Agent{
		ServerURL: cfg.ServerURL,
		HTTP:      transport.NewClient(transport.Options{SPKIPin: pin, RootCAs: roots}),
		Store:     credstore.Store{Path: credPath},
		Version:   version,
		Logger:    logger,
		Collect: func(ctx context.Context) protocol.HeartbeatRequest {
			info := sysinfo.Collect()
			st := cc.Status(ctx)
			if st.Status != lastStatus {
				logger.Info("clamd status", "status", st.Status, "engine", st.EngineVersion, "signatures", st.SignatureVersion, "error", st.Error)
				lastStatus = st.Status
			}
			return protocol.HeartbeatRequest{
				Hostname:  info.Hostname,
				OSName:    info.OSName,
				OSVersion: info.OSVersion,
				ClamAV:    st,
			}
		},
		Dispatch: disp.Dispatch,
	}
	err = agent.Run(ctx)
	switch {
	case err == nil:
		logger.Info("clamav-agent stopped")
		return exitOK
	case errors.Is(err, heartbeat.ErrRevoked):
		logger.Error("agent revoked; exiting with code 78 so the service manager does not restart it")
		return exitConfig
	default:
		logger.Error("cannot start heartbeat loop", "error", err)
		return exitConfig
	}
}

// ---- set-scan-roots ----

// setScanRootsCmd replaces scan_roots in the local config. It is the only
// way to widen what the console may scan, and it needs local root access.
func setScanRootsCmd(args []string) int {
	fs := flag.NewFlagSet("set-scan-roots", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	cfgPath := fs.String("config", config.ConfigPath(), "config file path")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	roots := []string{}
	seen := map[string]bool{}
	for _, r := range fs.Args() {
		if err := config.ValidateScanRoot(r); err != nil {
			fmt.Fprintln(os.Stderr, "set-scan-roots:", err)
			return exitUsage
		}
		r = filepath.Clean(r)
		if seen[r] {
			continue
		}
		seen[r] = true
		if st, err := os.Stat(r); err != nil || !st.IsDir() {
			fmt.Fprintf(os.Stderr, "WARNING: %s is not an existing directory; scans under it will fail until it exists\n", r)
		}
		roots = append(roots, r)
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "set-scan-roots:", err)
		return exitError
	}
	cfg.ScanRoots = roots
	if err := config.Save(*cfgPath, cfg); err != nil {
		fmt.Fprintln(os.Stderr, "set-scan-roots:", err)
		return exitError
	}
	if len(roots) == 0 {
		fmt.Println("Scans are now disabled on this machine.")
	} else {
		fmt.Printf("The console may now scan: %s\n", strings.Join(roots, ", "))
	}
	fmt.Println("Restart the agent to apply it (Linux: systemctl restart clamav-agent; Windows: Restart-Service ClamAVAgent).")
	return exitOK
}

// ---- status ----

func statusCmd(args []string) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	cfgPath, credPath := pathFlags(fs)
	if !parseFlags(fs, args) {
		return exitUsage
	}
	healthy := true
	fmt.Printf("version:      %s\n", version)
	fmt.Printf("config:       %s\n", *cfgPath)
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		healthy = false
		fmt.Printf("  ERROR:      %v\n", err)
	} else {
		fmt.Printf("  server_url: %s\n", cfg.ServerURL)
		fmt.Printf("  clamd:      %s\n", cfg.Clamd.Address)
		fmt.Printf("  cert pin:   %v\n", cfg.CACertPin != "")
		if len(cfg.ScanRoots) == 0 {
			fmt.Printf("  scan_roots: none (scans from the console are refused)\n")
		} else {
			fmt.Printf("  scan_roots: %s\n", strings.Join(cfg.ScanRoots, ", "))
		}
		if cfg.CACertFile != "" {
			fmt.Printf("  ca_cert:    %s", cfg.CACertFile)
			if _, err := cfg.RootCAs(); err != nil {
				healthy = false
				fmt.Printf(" (ERROR: %v)", err)
			}
			fmt.Println()
		}
		fmt.Printf("  log_level:  %s\n", cfg.LogLevel)
		if cfg.InsecureHTTPForTesting {
			fmt.Printf("  WARNING:    insecure_http_for_testing is enabled\n")
		}
	}
	// Never print the credential itself.
	fmt.Printf("credential:   %s: ", *credPath)
	if _, err := (credstore.Store{Path: *credPath}).Load(); err != nil {
		healthy = false
		fmt.Printf("%v\n", err)
	} else {
		fmt.Printf("present\n")
	}
	if cfg != nil {
		addr, _ := clamd.ParseAddress(cfg.Clamd.Address)
		st := clamd.New(addr).Status(context.Background())
		fmt.Printf("clamd status: %s\n", st.Status)
		if st.EngineVersion != "" {
			fmt.Printf("  engine:     %s\n", st.EngineVersion)
		}
		if st.SignatureVersion != 0 {
			fmt.Printf("  signatures: %d\n", st.SignatureVersion)
		}
		if st.SignatureDate != nil {
			fmt.Printf("  sig date:   %s\n", st.SignatureDate.Format(time.RFC3339))
		}
		if st.Error != "" {
			fmt.Printf("  error:      %s\n", st.Error)
		}
		if st.Status != protocol.ClamdRunning {
			healthy = false
		}
	}
	if !healthy {
		return exitError
	}
	return exitOK
}

// ---- verify / version ----

func verifyCmd(args []string) int {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: clamav-agent verify FILE SIGFILE")
		return exitUsage
	}
	res, err := release.VerifyFile(args[0], args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify:", err)
		return exitError
	}
	fmt.Printf("Signature OK (key %s)\nTrusted comment: %s\n", res.KeyID, sysinfo.Clean(strings.ReplaceAll(res.TrustedComment, "\t", " ")))
	return exitOK
}

func versionCmd() int {
	fmt.Printf("clamav-agent %s (%s/%s, %s)\n", version, runtime.GOOS, runtime.GOARCH, runtime.Version())
	if pk, err := release.PublicKey(); err != nil {
		fmt.Println("release key: none (placeholder; development build)")
	} else {
		suffix := ""
		if release.IsTestKey() {
			suffix = " (TEST KEY injected at build time)"
		}
		fmt.Printf("release key: %016X%s\n", pk.ID(), suffix)
	}
	return exitOK
}
