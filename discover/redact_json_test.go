package discover

import (
	"encoding/json"
	"strings"
	"testing"
)

// An editor format nests the command as {"path", "args", "env"}. It is
// read natively, so the server shows its real command and every part is
// redacted as for any server.
func TestNestedCommandObjectIsReadAndRedacted(t *testing.T) {
	path := writeConfig(t, `{"context_servers": {"srv": {"command": {
		"path": "/usr/bin/tool",
		"args": ["--token", "N1secret", "--api-key=N2secret", "--port", "8080"],
		"env": {"API_TOKEN": "N3secret", "MODE": "dev"}}}}}`)
	servers, warnings, err := parseConfigWithKeyWarnings(path, "context_servers")
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Errorf("a documented format is not a warning: %v", warnings)
	}
	if len(servers) != 1 || servers[0].Command != "/usr/bin/tool" || len(servers[0].Args) != 5 || servers[0].Env["MODE"] != "dev" {
		t.Fatalf("servers = %+v", servers)
	}
	result := &Result{Clients: []ClientResult{{Client: "zed", Path: path, Servers: servers}}}
	js, _ := json.Marshal(result.Redacted())
	tree := FormatTree(result)
	for _, out := range []string{tree, string(js)} {
		for _, secret := range []string{"N1secret", "N2secret", "N3secret"} {
			if strings.Contains(out, secret) {
				t.Errorf("%s shown:\n%s", secret, out)
			}
		}
	}
	if !strings.Contains(tree, "/usr/bin/tool --token [REDACTED] --api-key=[REDACTED] --port 8080") {
		t.Errorf("tree:\n%s", tree)
	}
}

// Values kept as JSON text are redacted all the way down: lists of
// strings as arguments, everything under a sensitive key, other strings
// as values.
func TestRedactValueRecursesIntoJSON(t *testing.T) {
	for name, tc := range map[string]struct {
		in      string
		secrets []string
		keep    []string
	}{
		"object in args":             {in: `{"opts": {"deep": ["--token", "N4secret"]}}`, secrets: []string{"N4secret"}, keep: []string{`"deep":["--token","[REDACTED]"]`}},
		"array nested deeper":        {in: `{"list": [["--api-key", "N5secret"], ["--verbose"]]}`, secrets: []string{"N5secret"}, keep: []string{"--verbose"}},
		"array under sensitive key":  {in: `{"credentials": ["N6secret", {"x": "N7secret"}], "mode": "dev"}`, secrets: []string{"N6secret", "N7secret"}, keep: []string{`"mode":"dev"`}},
		"object under sensitive key": {in: `{"auth": {"user": "N8secret", "nested": {"v": 1}}}`, secrets: []string{"N8secret"}},
		"top-level array of objects": {in: `[{"name": "a", "token": "N9secret"}, {"args": ["--password", "N10secret"]}]`, secrets: []string{"N9secret", "N10secret"}, keep: []string{`"name":"a"`}},
		"html is not escaped":        {in: `{"note": "<b>x</b> & y", "token": "N11secret"}`, secrets: []string{"N11secret"}, keep: []string{"<b>x</b> & y"}},
		"url inside json":            {in: `{"endpoint": "https://h.example.com/s/abcDEF123ghiJKL456mnoPQR/mcp?sig=N12secret"}`, secrets: []string{"N12secret", "abcDEF123ghiJKL456mnoPQR"}, keep: []string{"h.example.com"}},
	} {
		t.Run(name, func(t *testing.T) {
			got := redactValue(tc.in)
			for _, s := range tc.secrets {
				if strings.Contains(got, s) {
					t.Errorf("%s shown: %s", s, got)
				}
			}
			for _, k := range tc.keep {
				if !strings.Contains(got, k) {
					t.Errorf("%q missing: %s", k, got)
				}
			}
		})
	}
	// Unchanged JSON keeps its original formatting.
	if in := `{"mode": "dev", "port": 8080}`; redactValue(in) != in {
		t.Errorf("unchanged JSON reformatted: %s", redactValue(in))
	}
	// Beyond the depth limit the whole value is masked.
	deep := strings.Repeat(`{"a":`, 100) + `"N13secret"` + strings.Repeat("}", 100)
	if got := redactValue(deep); got != "[REDACTED]" {
		t.Errorf("deep JSON = %.80s", got)
	}
}

// A command object without a path is kept as JSON text, with a warning,
// and redacted recursively.
func TestCommandObjectWithoutPathIsRedacted(t *testing.T) {
	path := writeConfig(t, `{"mcpServers": {"odd": {"command": {"bin": "x", "args": ["--token", "N14secret"]}}}}`)
	servers, warnings, err := parseConfigWithKeyWarnings(path, "mcpServers")
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 1 {
		t.Errorf("warnings = %v", warnings)
	}
	result := &Result{Clients: []ClientResult{{Client: "cursor", Path: path, Servers: servers}}}
	js, _ := json.Marshal(result.Redacted())
	for _, out := range []string{FormatTree(result), string(js)} {
		if strings.Contains(out, "N14secret") {
			t.Errorf("secret shown:\n%s", out)
		}
	}
}
