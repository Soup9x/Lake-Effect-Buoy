// Package config loads and validates the agent's local YAML configuration.
//
// The config holds no secrets; the credential lives in a separate file (see
// package credstore).
package config

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Soup9x/Lake-Effect-Buoy/internal/agent/clamd"
)

// maxConfigBytes caps the config file size.
const maxConfigBytes = 64 << 10

// maxCACertBytes caps the ca_cert_file size.
const maxCACertBytes = 64 << 10

// Config is the on-disk agent configuration.
type Config struct {
	ServerURL string      `yaml:"server_url"`
	Clamd     ClamdConfig `yaml:"clamd"`
	// CACertPin is an optional base64 SHA-256 of a certificate's
	// SubjectPublicKeyInfo. When set, the server's verified chain must
	// contain a certificate with this key, in addition to normal checks.
	CACertPin string `yaml:"ca_cert_pin,omitempty"`
	// CACertFile is an optional absolute path to a PEM file holding the
	// certificate(s) of the CA that issued the console's certificate, for a
	// console with a private CA. When set, ONLY these CAs are trusted for the
	// console; the system trust store is not used. The installer writes it
	// after checking the CA's fingerprint.
	CACertFile string `yaml:"ca_cert_file,omitempty"`
	// ScanRoots are the only directories the console may ask this agent to
	// scan (scan_path), with everything under them. Set locally (installer
	// --scan-roots, or clamav-agent set-scan-roots); the server cannot change
	// it. Empty means scans are refused.
	ScanRoots []string `yaml:"scan_roots,omitempty"`
	LogLevel  string   `yaml:"log_level,omitempty"`
	// InsecureHTTPForTesting allows an http:// server URL. Never use it in
	// production; the agent logs a loud warning whenever it is set.
	InsecureHTTPForTesting bool `yaml:"insecure_http_for_testing,omitempty"`
}

// ClamdConfig locates the local clamd.
type ClamdConfig struct {
	Address string `yaml:"address"`
}

// Load reads and strictly validates the config at path. Unknown keys are
// errors, so typos do not silently fall back to defaults.
func Load(path string) (*Config, error) {
	f, err := os.Open(path) //nolint:gosec // local config path from flag/default
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	if len(data) > maxConfigBytes {
		return nil, fmt.Errorf("config: %s is too large", path)
	}
	return Parse(data)
}

// Parse decodes and validates YAML config bytes.
func Parse(data []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	// Reject a second YAML document rather than ignoring it.
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("config: multiple YAML documents are not allowed")
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Validate checks every field and normalises ServerURL (no trailing slash).
func (c *Config) Validate() error {
	u, err := ValidateServerURL(c.ServerURL, c.InsecureHTTPForTesting)
	if err != nil {
		return err
	}
	c.ServerURL = u
	if _, err := clamd.ParseAddress(c.Clamd.Address); err != nil {
		return fmt.Errorf("config: clamd.address: %w", err)
	}
	if c.CACertPin != "" {
		if _, err := c.Pin(); err != nil {
			return err
		}
	}
	if c.CACertFile != "" && (!filepath.IsAbs(c.CACertFile) || strings.ContainsRune(c.CACertFile, 0)) {
		return errors.New("config: ca_cert_file must be an absolute path")
	}
	for i, r := range c.ScanRoots {
		if err := ValidateScanRoot(r); err != nil {
			return fmt.Errorf("config: scan_roots: %w", err)
		}
		c.ScanRoots[i] = filepath.Clean(r)
	}
	switch c.LogLevel {
	case "":
		c.LogLevel = "info"
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("config: log_level %q must be debug, info, warn or error", c.LogLevel)
	}
	return nil
}

// ValidateServerURL checks a console base URL and returns it without a
// trailing slash. https is required unless allowHTTP is set (testing only).
func ValidateServerURL(raw string, allowHTTP bool) (string, error) {
	if raw == "" {
		return "", errors.New("config: server_url is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("config: server_url: %w", err)
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && allowHTTP:
	case u.Scheme == "http":
		return "", errors.New("config: server_url must use https (insecure_http_for_testing is not set)")
	default:
		return "", fmt.Errorf("config: server_url scheme %q must be https", u.Scheme)
	}
	if u.Host == "" || u.Hostname() == "" {
		return "", errors.New("config: server_url needs a host")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", errors.New("config: server_url must not contain credentials, a query or a fragment")
	}
	if strings.ContainsAny(raw, " \t\r\n") {
		return "", errors.New("config: server_url contains whitespace")
	}
	return strings.TrimRight(u.String(), "/"), nil
}

// Pin returns the decoded SPKI SHA-256 pin, or nil when none is set.
func (c *Config) Pin() ([]byte, error) {
	if c.CACertPin == "" {
		return nil, nil
	}
	b, err := base64.StdEncoding.DecodeString(c.CACertPin)
	if err != nil || len(b) != sha256.Size {
		return nil, errors.New("config: ca_cert_pin must be the base64 SHA-256 of a SubjectPublicKeyInfo (44 characters)")
	}
	return b, nil
}

// ValidateScanRoot checks one scan root: an absolute path on this system,
// without control characters.
func ValidateScanRoot(r string) error {
	if !filepath.IsAbs(r) {
		return fmt.Errorf("%q is not an absolute path", r)
	}
	for _, c := range r {
		if c < 0x20 || c == 0x7f {
			return fmt.Errorf("%q contains a control character", r)
		}
	}
	return nil
}

// RootCAs returns the CAs from ca_cert_file, or nil (use the system trust
// store) when it is not set. The file must hold only PEM certificates.
func (c *Config) RootCAs() (*x509.CertPool, error) {
	if c.CACertFile == "" {
		return nil, nil
	}
	return LoadCACertFile(c.CACertFile)
}

// LoadCACertFile reads a PEM file of one or more CERTIFICATE blocks.
func LoadCACertFile(path string) (*x509.CertPool, error) {
	f, err := os.Open(path) //nolint:gosec // local path from the agent's own config
	if err != nil {
		return nil, fmt.Errorf("config: ca_cert_file: %w", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxCACertBytes+1))
	if err != nil {
		return nil, fmt.Errorf("config: ca_cert_file: %w", err)
	}
	if len(data) > maxCACertBytes {
		return nil, fmt.Errorf("config: ca_cert_file %s is too large", path)
	}
	pool := x509.NewCertPool()
	n := 0
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			if len(bytes.TrimSpace(rest)) != 0 {
				return nil, fmt.Errorf("config: ca_cert_file %s contains data that is not PEM", path)
			}
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("config: ca_cert_file %s contains a %q block; only certificates are allowed", path, block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("config: ca_cert_file %s: %w", path, err)
		}
		pool.AddCert(cert)
		n++
	}
	if n == 0 {
		return nil, fmt.Errorf("config: ca_cert_file %s contains no certificates", path)
	}
	return pool, nil
}

// Marshal renders the config as YAML with a short header.
func (c *Config) Marshal() ([]byte, error) {
	body, err := yaml.Marshal(c)
	if err != nil {
		return nil, err
	}
	header := "# clamav-agent configuration. Written by `clamav-agent enroll`.\n" +
		"# The credential is stored separately and is never placed in this file.\n"
	return append([]byte(header), body...), nil
}

// Save atomically writes the config to path (temp file + rename). The
// directory is created if missing.
func Save(path string, c *Config) error {
	data, err := c.Marshal()
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // config dir holds no secrets
		return fmt.Errorf("config: create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".agent.yaml.tmp-*")
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("config: write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("config: sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	// The config holds no secrets; the agent user only needs to read it.
	if err := os.Chmod(tmp.Name(), 0o644); err != nil { //nolint:gosec // no secrets; the agent user must read it
		return fmt.Errorf("config: chmod: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("config: rename: %w", err)
	}
	return nil
}
