package discover

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Secrets that appear in fixture configs below. None of them may reach
// terminal or JSON output.
var fixtureSecrets = []string{
	"ghp_abcdefghijklmnopqrstuvwxyz0123456789",
	"ghp_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
	"hunter2",
	"s3cret",
	"abc123xyz",
	"xyz-bearer-token",
	"sk-live-1234567890abcdef",
	"plainpass",
	"opencode-secret",
	"supersecretvalue",
}

const fixtureConfig = `{"mcpServers": {
  "gh": {"command": "npx", "args": ["-y", "server-github", "--token=ghp_abcdefghijklmnopqrstuvwxyz0123456789"],
         "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "DB": "postgres://admin:hunter2@db.internal:5432/app", "MODE": "prod"}},
  "remote": {"url": "https://user:s3cret@mcp.example.com/sse?api_key=abc123xyz&region=eu", "headers": {"Authorization": "Bearer xyz-bearer-token", "X-Region": "eu"}},
  "proxy": {"command": "npx", "args": ["mcp-remote", "https://mcp.example.com/mcp", "--header", "Authorization: Bearer sk-live-1234567890abcdef"]},
  "db": {"command": "db-mcp", "args": ["--password", "plainpass", "--port", "5432", "--secret=supersecretvalue"]},
  "http": {"type": "http", "url": "https://api.example.com/mcp"},
  "local": {"type": "stdio", "command": "node", "args": ["server.js"]},
  "gemini": {"httpUrl": "https://gemini.example.com/mcp"},
  "windsurf": {"serverUrl": "https://windsurf.example.com/sse"},
  "odd": {"command": "x", "headers": {"n": 1}, "url": 7}
}}`

func fixtureResult(t *testing.T) *Result {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mcp.json")
	if err := os.WriteFile(path, []byte(fixtureConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	servers, err := parseConfigWithKey(path, "mcpServers")
	if err != nil {
		t.Fatal(err)
	}
	return &Result{Clients: []ClientResult{{Client: "cursor", Path: path, Servers: servers}}}
}

func TestDiscoverOutputNeverContainsSecrets(t *testing.T) {
	result := fixtureResult(t)
	if len(result.Clients[0].Servers) != 9 {
		t.Fatalf("an unexpected field type must not drop the server map: %+v", result.Clients[0].Servers)
	}
	tree := FormatTree(result)
	js, err := json.Marshal(result.Redacted())
	if err != nil {
		t.Fatal(err)
	}
	for _, out := range []string{tree, string(js)} {
		for _, secret := range fixtureSecrets {
			if strings.Contains(out, secret) {
				t.Errorf("secret %q printed:\n%s", secret, out)
			}
		}
		if !strings.Contains(out, "[REDACTED]") {
			t.Errorf("output does not show that something was redacted:\n%s", out)
		}
	}
	for _, want := range []string{
		"--token=[REDACTED]",
		"Authorization: [REDACTED]",
		"--password [REDACTED] --port 5432 --secret=[REDACTED]",
		"remote https://[REDACTED]@mcp.example.com/sse?api_key=[REDACTED]&region=[REDACTED]",
		"http https://api.example.com/mcp",
		"http https://gemini.example.com/mcp",
		"remote https://windsurf.example.com/sse",
		"node server.js",
	} {
		if !strings.Contains(tree, want) {
			t.Errorf("tree missing %q:\n%s", want, tree)
		}
	}
	// The source result is not modified.
	for _, s := range result.Clients[0].Servers {
		if s.Name == "gh" && !strings.Contains(s.Args[2], "ghp_abc") {
			t.Errorf("FormatTree mutated the result: %+v", s)
		}
	}
}

func TestDiscoverRedactedJSONFields(t *testing.T) {
	red := fixtureResult(t).Redacted()
	byName := map[string]MCPServer{}
	for _, s := range red.Clients[0].Servers {
		byName[s.Name] = s
	}
	if got := byName["gh"].Env["DB"]; got != "postgres://[REDACTED]@db.internal:5432/app" {
		t.Errorf("DB = %q", got)
	}
	if got := byName["gh"].Env["GITHUB_PERSONAL_ACCESS_TOKEN"]; got != "***REDACTED***" {
		t.Errorf("sensitive env key keeps its existing placeholder, got %q", got)
	}
	if got := byName["gh"].Env["MODE"]; got != "prod" {
		t.Errorf("MODE = %q", got)
	}
	remote := byName["remote"]
	if remote.Transport != "remote" || remote.Command != "" {
		t.Errorf("remote server: %+v", remote)
	}
	if remote.Headers["Authorization"] != "[REDACTED]" || remote.Headers["X-Region"] != "[REDACTED]" {
		t.Errorf("headers = %v", remote.Headers)
	}
	if s := byName["http"]; s.Transport != "http" || s.URL != "https://api.example.com/mcp" {
		t.Errorf("typed remote server: %+v", s)
	}
	if s := byName["local"]; s.Transport != "" || s.URL != "" {
		t.Errorf("stdio server must look as before: %+v", s)
	}
	if s := byName["odd"]; s.Command != "x" || s.URL != "" || s.Headers != nil {
		t.Errorf("non-string remote fields are ignored: %+v", s)
	}
}

// Servers are listed in name order, whatever the map order.
func TestDiscoverServersAreSorted(t *testing.T) {
	for range 5 {
		var names []string
		for _, s := range fixtureResult(t).Clients[0].Servers {
			names = append(names, s.Name)
		}
		if strings.Join(names, ",") != "db,gemini,gh,http,local,odd,proxy,remote,windsurf" {
			t.Fatalf("order = %v", names)
		}
	}
}

func TestRedactValue(t *testing.T) {
	for in, want := range map[string]string{
		"plain value":                        "plain value",
		"https://example.com/path?q=1":       "https://example.com/path?q=[REDACTED]",
		"https://u:p@example.com":            "https://[REDACTED]@example.com",
		"https://example.com/?token=abc&x=1": "https://example.com/?token=[REDACTED]&x=[REDACTED]",
		"see docs/?token=abc&x=1":            "see docs/?token=[REDACTED]&x=1",
		"Bearer abc.def-123":                 "Bearer [REDACTED]",
		"key AKIAABCDEFGHIJKLMNOP":           "key [REDACTED]",
		"sk-ant-api03-abcdefghijklmnopqrstu": "[REDACTED]",
		"[REDACTED]":                         "[REDACTED]",
		"":                                   "",
	} {
		if got := redactValue(in); got != want {
			t.Errorf("redactValue(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRedactArgs(t *testing.T) {
	got := redactArgs([]string{"--api-key", "abc", "--verbose", "--token", "--next", "-k=v", "--auth=x", "pos"})
	want := []string{"--api-key", "[REDACTED]", "--verbose", "--token", "--next", "-k=v", "--auth=[REDACTED]", "pos"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("redactArgs = %v, want %v", got, want)
	}
	if redactArgs(nil) != nil {
		t.Error("nil args stay nil so JSON keeps \"args\": null")
	}
}

func TestParseOpenCodeRemoteServer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "opencode.json")
	cfg := `{"mcp": {"remote": {"type": "remote", "url": "https://mcp.example.com?key=opencode-secret", "headers": {"Authorization": "Bearer opencode-secret"}}, "local": {"type": "local", "command": ["node", "s.js"]}}}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	servers, err := parseOpenCodeConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	tree := FormatTree(&Result{Clients: []ClientResult{{Client: "opencode", Path: path, Servers: servers}}})
	if strings.Contains(tree, "opencode-secret") || !strings.Contains(tree, "remote https://mcp.example.com?key=[REDACTED]") {
		t.Errorf("tree:\n%s", tree)
	}
	if !strings.Contains(tree, "node s.js") {
		t.Errorf("local server missing:\n%s", tree)
	}
}
