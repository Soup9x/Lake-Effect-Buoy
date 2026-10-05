package config

import (
	"bytes"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const goodYAML = `server_url: https://console.example.com/
clamd:
  address: tcp://127.0.0.1:3310
ca_cert_pin: "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
log_level: debug
`

func TestParseGood(t *testing.T) {
	c, err := Parse([]byte(goodYAML))
	if err != nil {
		t.Fatal(err)
	}
	if c.ServerURL != "https://console.example.com" || c.Clamd.Address != "tcp://127.0.0.1:3310" || c.LogLevel != "debug" {
		t.Fatalf("%+v", c)
	}
	if pin, err := c.Pin(); err != nil || len(pin) != 32 {
		t.Fatal(pin, err)
	}
	c, err = Parse([]byte("server_url: https://h:8443/console\nclamd:\n  address: unix:///run/clamav/clamd.ctl\n"))
	if err != nil || c.LogLevel != "info" || c.ServerURL != "https://h:8443/console" {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestParseBad(t *testing.T) {
	cases := map[string]string{
		"http":          "server_url: http://h\nclamd: {address: tcp://127.0.0.1:3310}\n",
		"no url":        "clamd: {address: tcp://127.0.0.1:3310}\n",
		"ftp":           "server_url: ftp://h\nclamd: {address: tcp://127.0.0.1:3310}\n",
		"userinfo":      "server_url: https://u:p@h\nclamd: {address: tcp://127.0.0.1:3310}\n",
		"query":         "server_url: https://h/?a=b\nclamd: {address: tcp://127.0.0.1:3310}\n",
		"no host":       "server_url: https:///x\nclamd: {address: tcp://127.0.0.1:3310}\n",
		"remote clamd":  "server_url: https://h\nclamd: {address: tcp://10.0.0.1:3310}\n",
		"no clamd":      "server_url: https://h\n",
		"unknown field": "server_url: https://h\nclamd: {address: tcp://127.0.0.1:3310}\nextra: 1\n",
		"typo nested":   "server_url: https://h\nclamd: {adress: tcp://127.0.0.1:3310}\n",
		"bad pin":       "server_url: https://h\nclamd: {address: tcp://127.0.0.1:3310}\nca_cert_pin: abc\n",
		"bad level":     "server_url: https://h\nclamd: {address: tcp://127.0.0.1:3310}\nlog_level: trace\n",
		"two docs":      "server_url: https://h\nclamd: {address: tcp://127.0.0.1:3310}\n---\nserver_url: https://evil\n",
		"relative CA":   "server_url: https://h\nclamd: {address: tcp://127.0.0.1:3310}\nca_cert_file: ca.pem\n",
		"relative root": "server_url: https://h\nclamd: {address: tcp://127.0.0.1:3310}\nscan_roots: [srv]\n",
		"control root":  "server_url: https://h\nclamd: {address: tcp://127.0.0.1:3310}\nscan_roots: [\"/srv\\nx\"]\n",
	}
	for name, y := range cases {
		if c, err := Parse([]byte(y)); err == nil {
			t.Errorf("%s: accepted %+v", name, c)
		}
	}
}

func TestInsecureHTTPForTesting(t *testing.T) {
	c, err := Parse([]byte("server_url: http://127.0.0.1:8080\nclamd: {address: tcp://127.0.0.1:3310}\ninsecure_http_for_testing: true\n"))
	if err != nil || !c.InsecureHTTPForTesting {
		t.Fatal(c, err)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sub", "agent.yaml")
	c, _ := Parse([]byte(goodYAML))
	if err := Save(p, c); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, c) {
		t.Fatalf("%+v != %+v", got, c)
	}
	b, _ := os.ReadFile(p)
	if strings.Contains(string(b), "insecure") {
		t.Fatal("insecure flag written when false")
	}
	entries, _ := os.ReadDir(filepath.Dir(p))
	if len(entries) != 1 {
		t.Fatalf("temp files left behind: %v", entries)
	}
}

func TestCACertFile(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	c, err := Parse([]byte("server_url: https://h\nclamd: {address: tcp://127.0.0.1:3310}\nca_cert_file: " + ca + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.RootCAs(); err == nil {
		t.Fatal("missing ca_cert_file accepted")
	}

	srv := httptest.NewTLSServer(http.NotFoundHandler())
	srv.Close()
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	write := func(b []byte) {
		t.Helper()
		if err := os.WriteFile(ca, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(certPEM)
	if pool, err := c.RootCAs(); err != nil || pool == nil {
		t.Fatalf("valid CA rejected: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")})
	for name, b := range map[string][]byte{
		"empty":     nil,
		"not PEM":   []byte("hello"),
		"trailing":  append(append([]byte{}, certPEM...), "junk"...),
		"key block": append(append([]byte{}, certPEM...), keyPEM...),
		"bad cert":  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")}),
		"too large": append(append([]byte{}, certPEM...), bytes.Repeat([]byte("\n"), maxCACertBytes)...),
	} {
		write(b)
		if _, err := c.RootCAs(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if c, _ := Parse([]byte(goodYAML)); c.CACertFile != "" {
		t.Fatal("ca_cert_file set without being configured")
	} else if pool, err := c.RootCAs(); pool != nil || err != nil {
		t.Fatalf("no ca_cert_file: %v %v", pool, err)
	}
}

func TestScanRoots(t *testing.T) {
	c, err := Parse([]byte("server_url: https://h\nclamd: {address: tcp://127.0.0.1:3310}\nscan_roots: [/srv/www/, /home]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.ScanRoots, []string{"/srv/www", "/home"}) {
		t.Fatalf("roots %q", c.ScanRoots)
	}
	if c, _ := Parse([]byte(goodYAML)); len(c.ScanRoots) != 0 {
		t.Fatal("scan roots set by default")
	}
}
