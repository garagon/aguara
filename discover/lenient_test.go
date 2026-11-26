package discover

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// One value of an unexpected type used to make the whole server map fail
// to decode, so every server in the file disappeared from discover and
// the file from scan --auto. Entries are now read leniently, the odd ones
// are reported, and the rest of the file is kept.
const oddValuesConfig = `{"mcpServers": {
  "good": {"command": "npx", "args": ["-y", "server"]},
  "typed": {"command": "node", "args": ["server.js", 3, true, null, ["nested"], {"k": "v"}],
            "env": {"PORT": 8080, "DEBUG": true, "EMPTY": null, "NESTED": {"a": 1}, "NAME": "x"}},
  "scalar-args": {"command": "tool", "args": "--single"},
  "not-an-object": "just a string",
  "object-command": {"command": {"bin": "/usr/bin/tool", "args": ["a"]}}
}}`

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mcp.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseServersLeniently(t *testing.T) {
	path := writeConfig(t, oddValuesConfig)
	servers, warnings, err := parseConfigWithKeyWarnings(path, "mcpServers")
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]MCPServer{}
	for _, s := range servers {
		byName[s.Name] = s
	}
	for _, name := range []string{"good", "typed", "scalar-args", "object-command"} {
		if _, ok := byName[name]; !ok {
			t.Errorf("server %q missing; got %v", name, servers)
		}
	}
	if _, ok := byName["not-an-object"]; ok {
		t.Error("a server that is not an object is skipped")
	}
	typed := byName["typed"]
	if got := strings.Join(typed.Args, " "); got != `server.js 3 true  ["nested"] {"k":"v"}` {
		t.Errorf("typed args = %q", got)
	}
	if typed.Env["PORT"] != "8080" || typed.Env["DEBUG"] != "true" || typed.Env["EMPTY"] != "" || typed.Env["NESTED"] != `{"a":1}` || typed.Env["NAME"] != "x" {
		t.Errorf("typed env = %v", typed.Env)
	}
	if got := byName["scalar-args"].Args; len(got) != 1 || got[0] != "--single" {
		t.Errorf("a string args value is read as one argument, got %v", got)
	}
	if byName["object-command"].Command != `{"bin":"/usr/bin/tool","args":["a"]}` {
		t.Errorf("object command = %q", byName["object-command"].Command)
	}
	joined := strings.Join(warnings, "\n")
	for _, want := range []string{
		`server "not-an-object" is not an object; skipped`,
		`server "typed": args[4] is an array`,
		`server "typed": args[5] is an object`,
		`server "typed": env "NESTED" is an object`,
		`server "scalar-args": args is a string`,
		`server "object-command": command is an object`,
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("warnings missing %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "/usr/bin/tool") || strings.Contains(joined, "8080") {
		t.Error("warnings must not repeat values, which can be secrets")
	}
	// Numbers and booleans are read as text without a warning.
	if strings.Contains(joined, `"PORT"`) || strings.Contains(joined, `"DEBUG"`) {
		t.Errorf("scalars are coerced silently:\n%s", joined)
	}
}

// A file the JSON reader rejects (a comment, a trailing comma, extreme
// nesting) is listed with a warning instead of being dropped, so it is
// visible and scan --auto still scans it as a file.
func TestScanListsUnparsableFiles(t *testing.T) {
	for name, tc := range map[string]struct{ content, warning string }{
		"comment":        {"{\n  // local servers\n  \"mcpServers\": {\"x\": {\"command\": \"npx\"}}\n}", "could not be parsed as JSON (near line 2); no servers read. Some clients accept JSONC"},
		"trailing comma": {`{"mcpServers": {"x": {"command": "npx"},}}`, "could not be parsed as JSON (near line 1)"},
		"deep nesting":   {strings.Repeat("[", 20000) + strings.Repeat("]", 20000), "could not be parsed as JSON"},
		"not an object":  {`["mcpServers"]`, "the file is an array, not a JSON object"},
	} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
			if err := os.MkdirAll(filepath.Join(home, ".cursor"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(home, ".cursor", "mcp.json"), []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			result, err := Scan()
			if err != nil {
				t.Fatal(err)
			}
			var cursor *ClientResult
			for i := range result.Clients {
				if result.Clients[i].Client == "cursor" {
					cursor = &result.Clients[i]
				}
			}
			if cursor == nil || len(cursor.Servers) != 0 || len(cursor.Warnings) != 1 || !strings.Contains(cursor.Warnings[0], tc.warning) {
				t.Fatalf("cursor client = %+v", cursor)
			}
			if tree := FormatTree(result); !strings.Contains(tree, "mcp.json") || !strings.Contains(tree, "Found 1 MCP configuration") {
				t.Errorf("tree:\n%s", tree)
			}
		})
	}
}

// OpenClaw reads JSON5 comments itself; a file still invalid after that is
// listed with a warning too.
func TestScanListsUnparsableOpenClawFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	if err := os.MkdirAll(filepath.Join(home, ".openclaw"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".openclaw", "openclaw.json"), []byte(`{"gateway": {"port": 1,}} }`), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Scan()
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Clients) != 1 || result.Clients[0].Client != "openclaw" || len(result.Clients[0].Servers) != 0 || len(result.Clients[0].Warnings) != 1 {
		t.Fatalf("clients = %+v", result.Clients)
	}
}

func TestScanKeepsClientsWithOddValues(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	if err := os.MkdirAll(filepath.Join(home, ".cursor"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".cursor", "mcp.json"), []byte(oddValuesConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Scan()
	if err != nil {
		t.Fatal(err)
	}
	var cursor *ClientResult
	for i := range result.Clients {
		if result.Clients[i].Client == "cursor" {
			cursor = &result.Clients[i]
		}
	}
	if cursor == nil || len(cursor.Servers) != 4 || len(cursor.Warnings) == 0 {
		t.Fatalf("cursor client = %+v", cursor)
	}
	// A file whose server map is unusable is still listed, so scan --auto
	// still scans it.
	if err := os.WriteFile(filepath.Join(home, ".cursor", "mcp.json"), []byte(`{"mcpServers": ["oops"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err = Scan()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range result.Clients {
		if c.Client == "cursor" {
			found = len(c.Servers) == 0 && len(c.Warnings) == 1
		}
	}
	if !found {
		t.Fatalf("a file with an unusable server map is listed with a warning: %+v", result.Clients)
	}
}
