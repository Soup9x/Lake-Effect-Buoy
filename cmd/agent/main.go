// Command clamav-agent is the endpoint agent of the ClamAV MSP console.
//
// It reports local clamd status to the console over outbound HTTPS and never
// listens on a network port.
package main

import (
	"fmt"
	"os"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// Exit codes.
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
	// exitConfig (EX_CONFIG) is used for a revoked credential and for
	// unusable configuration. The systemd unit sets
	// RestartPreventExitStatus=78 so the agent is not restarted in a loop.
	exitConfig = 78
)

func main() {
	os.Exit(realMain(os.Args[1:]))
}

func realMain(args []string) int {
	if len(args) == 0 {
		usage()
		return exitUsage
	}
	switch args[0] {
	case "enroll":
		return enrollCmd(args[1:])
	case "run":
		return runCmd(args[1:])
	case "set-scan-roots":
		return setScanRootsCmd(args[1:])
	case "status":
		return statusCmd(args[1:])
	case "verify":
		return verifyCmd(args[1:])
	case "version", "--version", "-v":
		return versionCmd()
	case "help", "-h", "--help":
		usage()
		return exitOK
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", args[0])
		usage()
		return exitUsage
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: clamav-agent <command> [flags]

commands:
  enroll --server URL [--config PATH] [--clamd ADDR] [--replace]
         enroll this machine; the token is read from CAV_ENROLL_TOKEN or stdin
  run [--config PATH]           run the heartbeat loop (foreground / service)
  status [--config PATH]        show configuration, credential presence and clamd status
  set-scan-roots [--config PATH] [DIR ...]
                                set the only directories the console may ask this machine
                                to scan (none: scans are refused); restart the agent after
  verify FILE SIGFILE           verify a minisign signature with the release key
  version                       print the version
`)
}
