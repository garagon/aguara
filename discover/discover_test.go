package discover

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTestConfig(t *testing.T, dir, filename string, servers map[string]mcpServerJSON) string {
	t.Helper()
	cfg := mcpConfigJSON{MCPServers: servers}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeOpenClawConfig(t *testing.T, dir string, content string) string {
	t.Helper()
	path := filepath.Join(dir, "openclaw.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// --- parseConfigWithKey tests ---

func TestParseConfigFile(t *testing.T) {
	dir := t.TempDir()
	path := writeTestConfig(t, dir, "mcp.json", map[string]mcpServerJSON{
		"filesystem": {Command: "npx", Args: []string{"-y", "@mcp/server-filesystem", "/data"}},
		"database":   {Command: "node", Args: []string{"./db-server.js"}, Env: map[string]string{"DB_URL": "postgres://localhost"}},
	})

	servers, err := parseConfigWithKey(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 2 {
		t.Fatalf("got %d servers, want 2", len(servers))
	}

	found := map[string]bool{}
	for _, s := range servers {
		found[s.Name] = true
		if s.Name == "filesystem" {
			if s.Command != "npx" {
				t.Errorf("filesystem command = %q, want npx", s.Command)
			}
		}
		if s.Name == "database" {
			if s.Env["DB_URL"] != "postgres://localhost" {
				t.Errorf("database env = %v", s.Env)
			}
		}
	}
	if !found["filesystem"] || !found["database"] {
		t.Error("missing expected servers")
	}
}

func TestParseConfigFile_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(path, []byte("not json"), 0o644)

	_, err := parseConfigWithKey(path, "")
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParseConfigFile_NoFile(t *testing.T) {
	_, err := parseConfigWithKey("/nonexistent/path.json", "")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestParseConfigWithKey_ServersKey(t *testing.T) {
	dir := t.TempDir()
	config := map[string]any{
		"servers": map[string]mcpServerJSON{
			"my-tool": {Command: "node", Args: []string{"server.js"}},
		},
	}
	data, _ := json.MarshalIndent(config, "", "  ")
	path := filepath.Join(dir, "mcp.json")
	_ = os.WriteFile(path, data, 0o644)

	servers, err := parseConfigWithKey(path, "servers")
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 1 {
		t.Fatalf("got %d servers, want 1", len(servers))
	}
	if servers[0].Name != "my-tool" {
		t.Errorf("name = %q, want my-tool", servers[0].Name)
	}
	if servers[0].Command != "node" {
		t.Errorf("command = %q, want node", servers[0].Command)
	}
}

func TestParseConfigWithKey_ServersKeyFallbackToMCPServers(t *testing.T) {
	dir := t.TempDir()
	config := map[string]any{
		"mcpServers": map[string]mcpServerJSON{
			"fallback-tool": {Command: "python", Args: []string{"serve.py"}},
		},
	}
	data, _ := json.MarshalIndent(config, "", "  ")
	path := filepath.Join(dir, "mcp.json")
	_ = os.WriteFile(path, data, 0o644)

	servers, err := parseConfigWithKey(path, "servers")
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 1 {
		t.Fatalf("got %d servers, want 1", len(servers))
	}
	if servers[0].Name != "fallback-tool" {
		t.Errorf("name = %q, want fallback-tool", servers[0].Name)
	}
}

func TestParseConfigWithKey_EmptyKeyDefaultsToMCPServers(t *testing.T) {
	dir := t.TempDir()
	path := writeTestConfig(t, dir, "mcp.json", map[string]mcpServerJSON{
		"test-srv": {Command: "test"},
	})

	servers, err := parseConfigWithKey(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 1 {
		t.Fatalf("got %d servers, want 1", len(servers))
	}
	if servers[0].Name != "test-srv" {
		t.Errorf("name = %q, want test-srv", servers[0].Name)
	}
}

// --- parseOpenCodeConfig tests ---

func TestParseOpenCodeConfig(t *testing.T) {
	dir := t.TempDir()
	config := map[string]any{
		"mcp": map[string]any{
			"my-server": map[string]any{
				"command":     []string{"npx", "-y", "@mcp/server"},
				"environment": map[string]string{"API_KEY": "secret"},
			},
			"simple": map[string]any{
				"command": []string{"mcp-tool"},
			},
		},
	}
	data, _ := json.MarshalIndent(config, "", "  ")
	path := filepath.Join(dir, "opencode.json")
	_ = os.WriteFile(path, data, 0o644)

	servers, err := parseOpenCodeConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 2 {
		t.Fatalf("got %d servers, want 2", len(servers))
	}

	found := map[string]MCPServer{}
	for _, s := range servers {
		found[s.Name] = s
	}

	srv := found["my-server"]
	if srv.Command != "npx" {
		t.Errorf("my-server command = %q, want npx", srv.Command)
	}
	if len(srv.Args) != 2 || srv.Args[0] != "-y" || srv.Args[1] != "@mcp/server" {
		t.Errorf("my-server args = %v, want [-y @mcp/server]", srv.Args)
	}
	if srv.Env["API_KEY"] != "secret" {
		t.Errorf("my-server env = %v", srv.Env)
	}

	simple := found["simple"]
	if simple.Command != "mcp-tool" {
		t.Errorf("simple command = %q, want mcp-tool", simple.Command)
	}
	if len(simple.Args) != 0 {
		t.Errorf("simple args = %v, want empty", simple.Args)
	}
}

func TestParseOpenCodeConfig_NoMCPKey(t *testing.T) {
	dir := t.TempDir()
	data := []byte(`{"theme": "dark"}`)
	path := filepath.Join(dir, "opencode.json")
	_ = os.WriteFile(path, data, 0o644)

	servers, err := parseOpenCodeConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 0 {
		t.Errorf("got %d servers, want 0", len(servers))
	}
}

// --- parseClaudeCodeConfig tests ---

func TestParseClaudeCodeConfig(t *testing.T) {
	dir := t.TempDir()
	config := map[string]any{
		"mcpServers": map[string]any{
			"global-srv": map[string]any{
				"command": "npx",
				"args":    []string{"@mcp/global"},
			},
		},
		"projects": map[string]any{
			"/home/user/project-a": map[string]any{
				"mcpServers": map[string]any{
					"project-srv": map[string]any{
						"command": "node",
						"args":    []string{"local.js"},
					},
				},
			},
			"/home/user/project-b": map[string]any{
				"mcpServers": map[string]any{
					"global-srv": map[string]any{
						"command": "npx",
						"args":    []string{"@mcp/global"},
					},
					"another-srv": map[string]any{
						"command": "python",
						"args":    []string{"serve.py"},
					},
				},
			},
		},
	}
	data, _ := json.MarshalIndent(config, "", "  ")
	path := filepath.Join(dir, ".claude.json")
	_ = os.WriteFile(path, data, 0o644)

	servers, err := parseClaudeCodeConfig(path)
	if err != nil {
		t.Fatal(err)
	}

	// Should have 3 unique servers: global-srv, project-srv, another-srv
	// global-srv appears in both top-level and project-b but should be deduped
	if len(servers) != 3 {
		t.Fatalf("got %d servers, want 3 (deduped)", len(servers))
	}

	found := map[string]bool{}
	for _, s := range servers {
		found[s.Name] = true
	}
	for _, name := range []string{"global-srv", "project-srv", "another-srv"} {
		if !found[name] {
			t.Errorf("missing server %q", name)
		}
	}
}

func TestParseClaudeCodeConfig_TopLevelOnly(t *testing.T) {
	dir := t.TempDir()
	config := map[string]any{
		"mcpServers": map[string]any{
			"only-srv": map[string]any{
				"command": "echo",
			},
		},
	}
	data, _ := json.MarshalIndent(config, "", "  ")
	path := filepath.Join(dir, ".claude.json")
	_ = os.WriteFile(path, data, 0o644)

	servers, err := parseClaudeCodeConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 1 {
		t.Fatalf("got %d servers, want 1", len(servers))
	}
	if servers[0].Name != "only-srv" {
		t.Errorf("name = %q, want only-srv", servers[0].Name)
	}
}

func TestParseClaudeCodeConfig_NoServers(t *testing.T) {
	dir := t.TempDir()
	data := []byte(`{"theme": "dark"}`)
	path := filepath.Join(dir, ".claude.json")
	_ = os.WriteFile(path, data, 0o644)

	servers, err := parseClaudeCodeConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 0 {
		t.Errorf("got %d servers, want 0", len(servers))
	}
}

// --- OpenClaw tests ---

func TestScanOpenClawConfig_Valid(t *testing.T) {
	dir := t.TempDir()
	path := writeOpenClawConfig(t, dir, `{
		"gateway": {"port": 18789, "bind": "127.0.0.1"},
		"agents": {
			"assistant": {"sandbox": true},
			"coder": {"sandbox": false}
		},
		"tools": {"profile": "standard", "allow": ["read", "write"]},
		"channels": {"slack": {"token": "xoxb-test"}},
		"dmPolicy": "restricted"
	}`)

	result, err := scanOpenClawConfig(path)
	if err != nil {
		t.Fatal(err)
	}

	if result.Client != "openclaw" {
		t.Errorf("client = %q, want openclaw", result.Client)
	}

	// Expect: 1 gateway + 2 agents + 1 channel = 4 servers
	if len(result.Servers) != 4 {
		t.Errorf("got %d servers, want 4", len(result.Servers))
	}

	found := map[string]bool{}
	for _, s := range result.Servers {
		found[s.Name] = true
	}
	if !found["openclaw-gateway"] {
		t.Error("missing openclaw-gateway entry")
	}
	if !found["channel-slack"] {
		t.Error("missing channel-slack entry")
	}
}

func TestScanOpenClawConfig_JSON5Comments(t *testing.T) {
	dir := t.TempDir()
	path := writeOpenClawConfig(t, dir, `{
		// This is a line comment
		"gateway": {"port": 18789, "bind": "127.0.0.1"},
		/* Block comment */
		"agents": {"bot": {"sandbox": true}},
		"tools": {"profile": "minimal"},
		"channels": {}
	}`)

	result, err := scanOpenClawConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if result.Client != "openclaw" {
		t.Errorf("client = %q, want openclaw", result.Client)
	}
	// 1 gateway + 1 agent = 2
	if len(result.Servers) != 2 {
		t.Errorf("got %d servers, want 2", len(result.Servers))
	}
}

func TestScanOpenClawConfig_NoAgents(t *testing.T) {
	dir := t.TempDir()
	path := writeOpenClawConfig(t, dir, `{
		"gateway": {"port": 18789},
		"tools": {"profile": "standard"},
		"channels": {}
	}`)

	result, err := scanOpenClawConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	// Only gateway entry when no agents or channels
	if len(result.Servers) != 1 {
		t.Errorf("got %d servers, want 1 (gateway only)", len(result.Servers))
	}
}

func TestScanOpenClawConfig_MissingFile(t *testing.T) {
	_, err := scanOpenClawConfig("/nonexistent/openclaw.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestScanOpenClawConfig_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := writeOpenClawConfig(t, dir, "not json at all")

	_, err := scanOpenClawConfig(path)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestStripJSON5Comments(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "line comment",
			input: `{"key": "value" // comment` + "\n}",
			want:  `{"key": "value" ` + "\n}",
		},
		{
			name:  "block comment",
			input: `{"key": /* removed */ "value"}`,
			want:  `{"key":  "value"}`,
		},
		{
			name:  "comment-like inside string",
			input: `{"url": "http://example.com"}`,
			want:  `{"url": "http://example.com"}`,
		},
		{
			name:  "escaped quote in string",
			input: `{"msg": "say \"hello\" // not a comment"}`,
			want:  `{"msg": "say \"hello\" // not a comment"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(StripJSON5Comments([]byte(tt.input)))
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// --- KnownClients tests ---

func TestKnownClients_Count(t *testing.T) {
	clients := KnownClients()
	if len(clients) != 17 {
		t.Errorf("got %d clients, want 17", len(clients))
	}

	names := map[string]bool{}
	for _, c := range clients {
		if names[c.Name] {
			t.Errorf("duplicate client name: %s", c.Name)
		}
		names[c.Name] = true
	}
}

// --- FormatTree tests ---

func TestFormatTree(t *testing.T) {
	result := &Result{
		Clients: []ClientResult{
			{
				Client: "cursor",
				Path:   "/home/user/.cursor/mcp.json",
				Servers: []MCPServer{
					{Name: "filesystem", Command: "npx", Args: []string{"@mcp/server-filesystem"}},
					{Name: "database", Command: "node", Args: []string{"./db.js"}},
				},
			},
		},
	}

	output := FormatTree(result)

	if !strings.Contains(output, "Cursor") {
		t.Error("should contain client display name")
	}
	if !strings.Contains(output, "filesystem") {
		t.Error("should contain server name")
	}
	if !strings.Contains(output, "2 MCP servers") {
		t.Error("should contain total count")
	}
}

func TestFormatTree_Empty(t *testing.T) {
	result := &Result{}
	output := FormatTree(result)
	if !strings.Contains(output, "No MCP configurations found") {
		t.Error("empty result should show 'no configs found'")
	}
	for _, name := range []string{"OpenCode", "Zed", "Amp", "Gemini CLI", "Claude Code", "BoltAI", "JetBrains"} {
		if !strings.Contains(output, name) {
			t.Errorf("empty message should list %s", name)
		}
	}
}

// --- Result helper tests ---

func TestResult_TotalServers(t *testing.T) {
	result := &Result{
		Clients: []ClientResult{
			{Servers: []MCPServer{{Name: "a"}, {Name: "b"}}},
			{Servers: []MCPServer{{Name: "c"}}},
		},
	}
	if got := result.TotalServers(); got != 3 {
		t.Errorf("TotalServers() = %d, want 3", got)
	}
}

func TestResult_TotalClients(t *testing.T) {
	result := &Result{
		Clients: []ClientResult{
			{Client: "a", Servers: []MCPServer{{Name: "s1"}}},
			{Client: "b", Servers: nil},
			{Client: "c", Servers: []MCPServer{{Name: "s2"}}},
		},
	}
	if got := result.TotalClients(); got != 2 {
		t.Errorf("TotalClients() = %d, want 2", got)
	}
}

func TestResult_AllServers(t *testing.T) {
	result := &Result{
		Clients: []ClientResult{
			{Client: "a", Servers: []MCPServer{{Name: "s1"}, {Name: "s2"}}},
			{Client: "b", Servers: []MCPServer{{Name: "s3"}}},
		},
	}
	all := result.AllServers()
	if len(all) != 3 {
		t.Fatalf("AllServers() returned %d, want 3", len(all))
	}
}

func TestClientDisplayName_AllClients(t *testing.T) {
	expected := map[string]string{
		"claude-desktop": "Claude Desktop",
		"cursor":         "Cursor",
		"vscode":         "VS Code",
		"cline":          "Cline",
		"windsurf":       "Windsurf",
		"openclaw":       "OpenClaw",
		"opencode":       "OpenCode",
		"zed":            "Zed",
		"amp":            "Amp",
		"gemini-cli":     "Gemini CLI",
		"copilot-cli":    "Copilot CLI",
		"amazon-q":       "Amazon Q",
		"claude-code":    "Claude Code",
		"roo-code":       "Roo Code",
		"kilo-code":      "Kilo Code",
		"boltai":         "BoltAI",
		"jetbrains":      "JetBrains",
	}
	for name, want := range expected {
		if got := clientDisplayName(name); got != want {
			t.Errorf("clientDisplayName(%q) = %q, want %q", name, got, want)
		}
	}
}
