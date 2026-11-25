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
