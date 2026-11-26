package discover

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// secretPositions puts a distinct secret in every place a server
// definition can carry one. Each secret must appear in no output format.
var secretPositions = []struct {
	name   string
	server MCPServer
	secret string
}{
	{"flag joined", MCPServer{Command: "npx", Args: []string{"--token=S01secret"}}, "S01secret"},
	{"flag then value", MCPServer{Command: "npx", Args: []string{"--api-key", "S02secret"}}, "S02secret"},
	{"flag value starting with a dash", MCPServer{Command: "npx", Args: []string{"--password", "-S03secret"}}, "S03secret"},
	{"pass option", MCPServer{Command: "db", Args: []string{"--pass", "S04secret"}}, "S04secret"},
	{"passphrase option", MCPServer{Command: "db", Args: []string{"--passphrase", "S05secret"}}, "S05secret"},
	{"session option", MCPServer{Command: "db", Args: []string{"--session", "S06secret"}}, "S06secret"},
	{"docker -e assignment", MCPServer{Command: "docker", Args: []string{"run", "-e", "DB_PASS=S07secret", "image"}}, "S07secret"},
	{"env flag assignment", MCPServer{Command: "docker", Args: []string{"--env=API_KEY=S08secret"}}, "S08secret"},
	{"header flag joined", MCPServer{Command: "npx", Args: []string{"mcp-remote", "--header=Authorization: Bearer S09secret"}}, "S09secret"},
	{"header after flag", MCPServer{Command: "npx", Args: []string{"mcp-remote", "--header", "X-Api-Key: S10secret"}}, "S10secret"},
	{"url sig parameter", MCPServer{Command: "npx", Args: []string{"https://mcp.example.com/sse?sig=S11secret"}}, "S11secret"},
	{"url fragment token", MCPServer{Command: "npx", Args: []string{"https://mcp.example.com/cb#access_token=S12secret"}}, "S12secret"},
	{"url bare query", MCPServer{Command: "npx", Args: []string{"https://mcp.example.com/sse?S13secret"}}, "S13secret"},
	{"url bare fragment", MCPServer{Command: "npx", Args: []string{"https://mcp.example.com/sse#S14secret"}}, "S14secret"},
	{"url userinfo", MCPServer{Command: "npx", Args: []string{"https://user:S15secret@mcp.example.com/sse"}}, "S15secret"},
	{"env sensitive name", MCPServer{Command: "x", Env: map[string]string{"DB_PASS": "S16secret"}}, "S16secret"},
	{"env connection string", MCPServer{Command: "x", Env: map[string]string{"CONN": "Server=db;User Id=sa;Password=S17secret;Encrypt=true"}}, "S17secret"},
	{"env embedded json", MCPServer{Command: "x", Env: map[string]string{"CONFIG": `{"region": "eu", "apiKey": "S18secret"}`}}, "S18secret"},
	{"env database url", MCPServer{Command: "x", Env: map[string]string{"DATABASE": "postgres://app:S19secret@db.internal/app"}}, "S19secret"},
	{"env extra arguments", MCPServer{Command: "x", Env: map[string]string{"EXTRA_ARGS": "--verbose --token S20secret"}}, "S20secret"},
	{"server url query", MCPServer{Transport: "sse", URL: "https://mcp.example.com/sse?region=eu&key=S21secret"}, "S21secret"},
	{"server url fragment", MCPServer{Transport: "http", URL: "https://mcp.example.com/mcp#S22secret"}, "S22secret"},
	{"server url signature", MCPServer{Transport: "http", URL: "https://store.example.com/mcp?X-Amz-Signature=S23secret"}, "S23secret"},
	{"header map credential", MCPServer{Transport: "http", URL: "https://mcp.example.com", Headers: map[string]string{"Authorization": "S24secret"}}, "S24secret"},
	{"header map other value", MCPServer{Transport: "http", URL: "https://mcp.example.com", Headers: map[string]string{"X-Trace": "Bearer S25secret"}}, "S25secret"},
	{"command url", MCPServer{Command: "https://mcp.example.com/run?token=S26secret"}, "S26secret"},
	{"server url path credential", MCPServer{Transport: "http", URL: "https://host.example.com/api/mcp/s/S27abcDEF123ghiJKL456/mcp"}, "S27abcDEF123ghiJKL456"},
	{"arg url path credential", MCPServer{Command: "npx", Args: []string{"mcp-remote", "https://host.example.com/api/mcp/s/S28abcDEF123ghiJKL456/mcp"}}, "S28abcDEF123ghiJKL456"},
	{"bot token in url path", MCPServer{Command: "npx", Args: []string{"https://api.telegram.org/bot123456789:S29dqTcvCH1vGWJxfSeofSAs0K5PALDsaw/sendMessage"}}, "S29dqTcvCH1vGWJxfSeofSAs0K5PALDsaw"},
	{"header map unknown name", MCPServer{Transport: "http", URL: "https://mcp.example.com", Headers: map[string]string{"X-Access": "S30secret"}}, "S30secret"},
	{"header map short name", MCPServer{Transport: "http", URL: "https://mcp.example.com", Headers: map[string]string{"X-Pw": "S31secret"}}, "S31secret"},
	{"header argument unknown name", MCPServer{Command: "npx", Args: []string{"mcp-remote", "https://mcp.example.com/mcp", "--header", "X-Access: S32secret"}}, "S32secret"},
	{"header argument joined unknown name", MCPServer{Command: "npx", Args: []string{"mcp-remote", "--header=X-Pw: S33secret"}}, "S33secret"},
	{"command string env prefix", MCPServer{Command: "env API_TOKEN=S34secret node server.js"}, "S34secret"},
	{"command string container -e", MCPServer{Command: `docker run --rm -e "DB_PASS=S35secret" ghcr.io/acme/mcp:1.2`}, "S35secret"},
	{"windows token option", MCPServer{Command: "tool.exe", Args: []string{"/token:S36secret"}}, "S36secret"},
	{"windows p option", MCPServer{Command: "tool.exe", Args: []string{"/user:alice", "/p:S37secret"}}, "S37secret"},
	{"env name without case boundary", MCPServer{Command: "x", Env: map[string]string{"DBPass": "S38secret"}}, "S38secret"},
	{"env name sensitive suffix", MCPServer{Command: "x", Env: map[string]string{"REDISPASS": "S39secret"}}, "S39secret"},
	{"requirepass", MCPServer{Command: "redis-server", Args: []string{"--requirepass", "S40secret"}}, "S40secret"},
	{"short flag with a token value", MCPServer{Command: "x", Args: []string{"-a", "ghp_S41abcdefghijklmnopqrstuvwxyz0123"}}, "S41abcdefghijklmnopqrstuvwxyz0123"},
	{"env json array of arguments", MCPServer{Command: "x", Env: map[string]string{"EXTRA": `["--api-key", "S42secret", "--verbose"]`}}, "S42secret"},
	{"env json array of objects", MCPServer{Command: "x", Env: map[string]string{"SERVERS": `[{"name": "a", "token": "S43secret"}]`}}, "S43secret"},
}

// Names that only contain the letters of a sensitive word, and short
// flags whose meaning cannot be known, keep their values visible unless a
// value itself looks like a token.
func TestDiscoverHarmlessNamesStayVisible(t *testing.T) {
	srv := MCPServer{
		Name:    "visible",
		Command: "env NODE_ENV=production node server.js",
		Args:    []string{"--keyboard", "us", "-a", "plainvalue", "/user:alice", "--authority", "example.org"},
		Env: map[string]string{
			"Compass": "north", "Keyboard": "dvorak", "Monkey": "george", "Signal": "sigterm",
			"Bypass": "proxy-off", "Passport": "booking", "PASSTHROUGH": "on", "DESIGN": "flat",
			"Monkey_Token_Look": "x", "Hotkey": "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
		},
	}
	red := (&Result{Clients: []ClientResult{{Client: "cursor", Servers: []MCPServer{srv}}}}).Redacted().Clients[0].Servers[0]
	if red.Command != srv.Command {
		t.Errorf("command = %q", red.Command)
	}
	if got := strings.Join(red.Args, " "); got != "--keyboard us -a plainvalue /user:alice --authority example.org" {
		t.Errorf("args = %q", got)
	}
	for _, name := range []string{"Compass", "Keyboard", "Monkey", "Signal", "Bypass", "Passport", "PASSTHROUGH", "DESIGN"} {
		if red.Env[name] != srv.Env[name] {
			t.Errorf("env %s = %q, want it visible", name, red.Env[name])
		}
	}
	if red.Env["Monkey_Token_Look"] != "***REDACTED***" {
		t.Errorf("a TOKEN word still counts: %q", red.Env["Monkey_Token_Look"])
	}
	if red.Env["Hotkey"] != "[REDACTED]" {
		t.Errorf("a token-shaped value is redacted under a harmless name: %q", red.Env["Hotkey"])
	}
}

// Path segments that look like credentials are redacted; ordinary path
// segments stay readable. A UUID in a path is redacted too: hosted MCP
// endpoints use it as a per-user capability.
func TestRedactURLPathSegments(t *testing.T) {
	for _, keep := range []string{
		"https://mcp.example.com/v1/mcp",
		"https://api.example.com/2024-06-01/servers/sse",
		"https://cdn.example.com/docs/release-notes-2024-final.md",
		"https://example.com/my-server-v2-production/sse",
		"https://example.com/repos/garagon/aguara/contents/README.md",
		"https://example.com/files/aGVsbG8x/index.html",
		"https://example.com/internationalization/settings",
		"https://example.com/node_modules/package/dist/index.js",
	} {
		if got := redactURL(keep); got != keep {
			t.Errorf("redactURL(%q) = %q, want it unchanged", keep, got)
		}
	}
	for in, want := range map[string]string{
		"https://host.example.com/api/mcp/s/abcDEF123ghiJKL456mnoPQR/mcp": "https://host.example.com/api/mcp/s/[REDACTED]/mcp",
		"https://example.com/t/dGhpc2lzYXNlY3JldDEyMw/sse":                "https://example.com/t/[REDACTED]/sse",
		"https://example.com/w/123e4567-e89b-12d3-a456-426614174000/mcp":  "https://example.com/w/[REDACTED]/mcp",
		"https://example.com/k/sk-ant-api03-abcdefghijklmnopqrstuv/mcp":   "https://example.com/k/[REDACTED]/mcp",
		"https://example.com/hooks/a1b2c3d4e5f6g7h8i9j0k1l2.m3n4o5":       "https://example.com/hooks/[REDACTED]",
	} {
		if got := redactValue(in); got != want {
			t.Errorf("redactValue(%q) = %q, want %q", in, got, want)
		}
	}
	if got := redactValue("https://api.telegram.org/bot123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw/sendMessage"); got != "https://api.telegram.org/bot[REDACTED]/sendMessage" {
		t.Errorf("bot token in path = %q", got)
	}
}

// Header values are masked unless the header's value is never a secret.
func TestRedactHeadersAllowList(t *testing.T) {
	got := redactHeaders(map[string]string{
		"Accept": "application/json", "content-type": "application/json", "User-Agent": "agent/1.0",
		"MCP-Protocol-Version": "2025-06-18", "X-Access": "secret", "X-Region": "eu", "Authorization": "Bearer x",
	})
	for name, want := range map[string]string{
		"Accept": "application/json", "content-type": "application/json", "User-Agent": "agent/1.0",
		"MCP-Protocol-Version": "2025-06-18", "X-Access": "[REDACTED]", "X-Region": "[REDACTED]", "Authorization": "[REDACTED]",
	} {
		if got[name] != want {
			t.Errorf("header %s = %q, want %q", name, got[name], want)
		}
	}
}

func TestDiscoverSecretInEveryPositionIsRedacted(t *testing.T) {
	result := &Result{}
	for i, tc := range secretPositions {
		srv := tc.server
		srv.Name = fmt.Sprintf("srv%02d", i)
		result.Clients = append(result.Clients, ClientResult{Client: "cursor", Path: "/home/u/.cursor/mcp.json", Servers: []MCPServer{srv}})
	}
	js, err := json.Marshal(result.Redacted())
	if err != nil {
		t.Fatal(err)
	}
	outputs := map[string]string{"terminal": FormatTree(result), "json": string(js), "markdown": FormatMarkdown(result)}
	for _, tc := range secretPositions {
		for format, out := range outputs {
			if strings.Contains(out, tc.secret) {
				t.Errorf("%s: %s output contains the secret", tc.name, format)
			}
		}
	}
	// What is not secret stays visible.
	for _, want := range []string{"npx", "docker run -e DB_PASS=[REDACTED] image", "mcp-remote", "https://mcp.example.com/sse",
		"region=[REDACTED]", "X-Trace", "--verbose --token [REDACTED]", "User Id=sa", "Encrypt=true"} {
		if !strings.Contains(outputs["terminal"]+outputs["json"], want) {
			t.Errorf("visible text %q missing", want)
		}
	}
	if got := redactEnv(map[string]string{"CONFIG": `{"region": "eu", "apiKey": "x"}`})["CONFIG"]; got != `{"region": "eu", "apiKey": "[REDACTED]"}` {
		t.Errorf("embedded JSON = %q", got)
	}
}

// Words such as PASS and SIG count only as whole words, so harmless names
// that contain the letters stay visible.
func TestSensitiveNameWordBoundaries(t *testing.T) {
	for name, want := range map[string]bool{
		"DB_PASS": true, "dbPass": true, "--pass": true, "--passphrase": true, "PASSWD": true,
		"--session": true, "sessionId": true, "sig": true, "X-Amz-Signature": true,
		"API_KEY": true, "Cookie": true, "Password": true,
		"PASSTHROUGH": false, "BYPASS": false, "DESIGN": false, "SIGNAL": false,
		"SESSIONS_DIR": false, "region": false, "port": false, "MODE": false,
		"DBPass": true, "REDISPASS": true, "requirepass": true, "SSHKEY": true, "apiKey": true, "BASICAUTH": true,
		"Compass": false, "Keyboard": false, "keyboard": false, "Monkey": false, "Signal": false,
		"Bypass": false, "Passport": false, "AUTHOR": false, "authority": false, "KEYBOARD_LAYOUT": false,
	} {
		if got := sensitiveName(name); got != want {
			t.Errorf("sensitiveName(%q) = %v, want %v", name, got, want)
		}
	}
	env := redactEnv(map[string]string{"PASSTHROUGH": "visible", "DESIGN_SYSTEM": "visible", "DB_PASS": "hidden"})
	if env["PASSTHROUGH"] != "visible" || env["DESIGN_SYSTEM"] != "visible" || env["DB_PASS"] != "***REDACTED***" {
		t.Errorf("redactEnv = %v", env)
	}
}

func TestRedactURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://mcp.example.com/sse":                           "https://mcp.example.com/sse",
		"https://mcp.example.com/sse?sig=abc":                   "https://mcp.example.com/sse?sig=[REDACTED]",
		"https://mcp.example.com/sse?a=1&b=&c":                  "https://mcp.example.com/sse?a=[REDACTED]&b=&[REDACTED]",
		"https://mcp.example.com/cb#access_token=abc;state=x":   "https://mcp.example.com/cb#access_token=[REDACTED];state=[REDACTED]",
		"https://mcp.example.com/sse?abc#def":                   "https://mcp.example.com/sse?[REDACTED]#[REDACTED]",
		"https://u:p@mcp.example.com/x?y=1":                     "https://[REDACTED]@mcp.example.com/x?y=[REDACTED]",
		"see https://a.example.com/?t=1 and https://b.example/": "see https://a.example.com/?t=[REDACTED] and https://b.example/",
	} {
		if got := redactURL(in); got != want {
			t.Errorf("redactURL(%q) = %q, want %q", in, got, want)
		}
		if got := redactValue(redactValue(in)); got != redactValue(in) {
			t.Errorf("redactValue is not idempotent on %q: %q", in, got)
		}
	}
}
