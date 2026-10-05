// Package clamd is a minimal client for the local clamd daemon.
//
// It only ever sends the fixed commands PING, VERSION, RELOAD, STATS and
// CONTSCAN <path> (the path validated by the caller and again here), and only
// connects to a Unix socket or a loopback TCP address. It never listens.
package clamd

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// Address is a validated clamd endpoint.
type Address struct {
	Network string // "unix" or "tcp"
	Addr    string // socket path, or host:port
}

func (a Address) String() string {
	if a.Network == "unix" {
		return "unix://" + a.Addr
	}
	return "tcp://" + a.Addr
}

// ParseAddress accepts unix:///absolute/path (not on Windows) or
// tcp://HOST:PORT where HOST is a loopback IP or literally "localhost".
func ParseAddress(s string) (Address, error) {
	switch {
	case strings.HasPrefix(s, "unix://"):
		if runtime.GOOS == "windows" {
			return Address{}, errors.New("clamd: unix:// addresses are not supported on Windows; use tcp://127.0.0.1:3310")
		}
		p := strings.TrimPrefix(s, "unix://")
		if p == "" || !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return Address{}, fmt.Errorf("clamd: unix socket path %q must be absolute and clean", p)
		}
		if strings.ContainsAny(p, "\x00\n\r") {
			return Address{}, errors.New("clamd: invalid characters in socket path")
		}
		return Address{Network: "unix", Addr: p}, nil
	case strings.HasPrefix(s, "tcp://"):
		u, err := url.Parse(s)
		if err != nil {
			return Address{}, fmt.Errorf("clamd: %w", err)
		}
		if u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
			return Address{}, fmt.Errorf("clamd: tcp address %q must be tcp://HOST:PORT only", s)
		}
		host, port := u.Hostname(), u.Port()
		if port == "" {
			return Address{}, errors.New("clamd: tcp address needs a port")
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return Address{}, fmt.Errorf("clamd: invalid port %q", port)
		}
		if err := checkLoopbackHost(host); err != nil {
			return Address{}, err
		}
		return Address{Network: "tcp", Addr: net.JoinHostPort(host, port)}, nil
	default:
		return Address{}, fmt.Errorf("clamd: address %q must start with unix:// or tcp://", s)
	}
}

// checkLoopbackHost allows "localhost" and loopback IP literals only. Any
// other hostname is refused so DNS can never point the agent off-host.
func checkLoopbackHost(host string) error {
	if host == "localhost" {
		return nil
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("clamd: host %q is not a loopback IP or \"localhost\"", host)
	}
	if !ip.Unmap().IsLoopback() || ip.Zone() != "" {
		return fmt.Errorf("clamd: refusing non-loopback address %s", host)
	}
	return nil
}

// checkLoopbackDial is the dial-time check on the resolved address.
func checkLoopbackDial(network, address string) error {
	if !strings.HasPrefix(network, "tcp") {
		return nil
	}
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("clamd: cannot check dial address %q: %w", address, err)
	}
	if !ap.Addr().Unmap().IsLoopback() {
		return fmt.Errorf("clamd: refusing to connect to non-loopback address %s", address)
	}
	return nil
}
