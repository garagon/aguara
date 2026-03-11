package discover

import (
	"fmt"
	"strings"
)

// sensitiveEnvKeys matches env variable names that likely contain secrets.
var sensitiveEnvKeys = []string{
	"KEY", "SECRET", "TOKEN", "PASSWORD", "CREDENTIAL",
	"AUTH", "PRIVATE", "API_KEY", "APIKEY",
}

// redactEnv returns a copy of the env map with sensitive values masked.
func redactEnv(env map[string]string) map[string]string {
	if len(env) == 0 {
		return env
	}
	redacted := make(map[string]string, len(env))
	for k, v := range env {
		upper := strings.ToUpper(k)
		masked := false
		for _, sensitive := range sensitiveEnvKeys {
			if strings.Contains(upper, sensitive) {
				redacted[k] = "***REDACTED***"
				masked = true
				break
			}
		}
		if !masked {
			redacted[k] = v
		}
	}
	return redacted
}

// MCPServer represents a discovered MCP server from a client config.
type MCPServer struct {
	Name    string            `json:"name"`
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env,omitempty"`
}

// ClientResult holds the discovered MCP servers for a single client.
type ClientResult struct {
	Client  string      `json:"client"`
	Path    string      `json:"path"`
	Servers []MCPServer `json:"servers"`
}

// Result holds the full discovery output.
type Result struct {
	Clients []ClientResult `json:"clients"`
}

// TotalServers returns the total number of MCP servers found.
func (r *Result) TotalServers() int {
	n := 0
	for _, c := range r.Clients {
		n += len(c.Servers)
	}
	return n
}

// TotalClients returns the number of clients that have at least one server.
func (r *Result) TotalClients() int {
	n := 0
	for _, c := range r.Clients {
		if len(c.Servers) > 0 {
			n++
		}
	}
	return n
}

// Redacted returns a copy of the result with sensitive env values masked.
func (r *Result) Redacted() *Result {
	out := &Result{Clients: make([]ClientResult, len(r.Clients))}
	for i, c := range r.Clients {
		servers := make([]MCPServer, len(c.Servers))
		for j, s := range c.Servers {
			servers[j] = MCPServer{
				Name:    s.Name,
				Command: s.Command,
				Args:    s.Args,
				Env:     redactEnv(s.Env),
			}
		}
		out.Clients[i] = ClientResult{Client: c.Client, Path: c.Path, Servers: servers}
	}
	return out
}

// AllServers returns a flat list of all discovered servers with their client name.
func (r *Result) AllServers() []struct {
	Client string
	Server MCPServer
} {
	var all []struct {
		Client string
		Server MCPServer
	}
	for _, c := range r.Clients {
		for _, s := range c.Servers {
			all = append(all, struct {
				Client string
				Server MCPServer
			}{Client: c.Client, Server: s})
		}
	}
	return all
}

// Scan checks all known MCP client config paths and extracts server definitions.
func Scan() (*Result, error) {
	result := &Result{}

	for _, client := range KnownClients() {
		for _, path := range client.Paths {
			var servers []MCPServer
			var err error

			switch {
			case client.Name == "openclaw":
				cr, oerr := scanOpenClawConfig(path)
				if oerr != nil {
					continue
				}
				if len(cr.Servers) > 0 {
					result.Clients = append(result.Clients, *cr)
				}
				continue
			case client.ConfigKey == "opencode":
				servers, err = parseOpenCodeConfig(path)
			case client.ConfigKey == "claude-code":
				servers, err = parseClaudeCodeConfig(path)
			default:
				servers, err = parseConfigWithKey(path, client.ConfigKey)
			}

			if err != nil {
				continue
			}
			if len(servers) > 0 {
				result.Clients = append(result.Clients, ClientResult{
					Client:  client.Name,
					Path:    path,
					Servers: servers,
				})
			}
		}
	}

	return result, nil
}

// FormatTree returns a human-readable tree of discovered MCP servers.
func FormatTree(result *Result) string {
	if len(result.Clients) == 0 {
		return "No MCP configurations found.\n\nChecked paths for: Claude Desktop, Cursor, VS Code, Cline, Windsurf, OpenClaw, " +
			"OpenCode, Zed, Amp, Gemini CLI, Copilot CLI, Amazon Q, Claude Code, Roo Code, Kilo Code, BoltAI, JetBrains"
	}

	var b strings.Builder

	fmt.Fprintf(&b, "Found %d MCP configuration(s):\n\n", result.TotalClients())

	for _, cr := range result.Clients {
		fmt.Fprintf(&b, "  %s  %s\n", clientDisplayName(cr.Client), cr.Path)
		for i, srv := range cr.Servers {
			prefix := "├──"
			if i == len(cr.Servers)-1 {
				prefix = "└──"
			}
			cmdStr := srv.Command
			if len(srv.Args) > 0 {
				cmdStr += " " + strings.Join(srv.Args, " ")
			}
			fmt.Fprintf(&b, "    %s %-20s %s\n", prefix, srv.Name, cmdStr)
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "Total: %d MCP servers across %d clients\n", result.TotalServers(), result.TotalClients())
	return b.String()
}

// FormatMarkdown returns a Markdown-formatted table of discovered MCP servers.
func FormatMarkdown(result *Result) string {
	if len(result.Clients) == 0 {
		return "No MCP configurations found.\n"
	}

	var b strings.Builder

	fmt.Fprintf(&b, "## MCP Clients Discovered\n\n")
	b.WriteString("| Client | Config Path | Servers |\n")
	b.WriteString("|--------|------------|--------|\n")

	for _, cr := range result.Clients {
		escapedPath := strings.ReplaceAll(cr.Path, "|", "\\|")
		fmt.Fprintf(&b, "| %s | `%s` | %d |\n", clientDisplayName(cr.Client), escapedPath, len(cr.Servers))
	}

	b.WriteString("\n")
	serverWord := "servers"
	if result.TotalServers() == 1 {
		serverWord = "server"
	}
	clientWord := "clients"
	if result.TotalClients() == 1 {
		clientWord = "client"
	}
	fmt.Fprintf(&b, "**Total:** %d MCP %s across %d %s\n", result.TotalServers(), serverWord, result.TotalClients(), clientWord)
	return b.String()
}

func clientDisplayName(name string) string {
	switch name {
	case "claude-desktop":
		return "Claude Desktop"
	case "cursor":
		return "Cursor"
	case "vscode":
		return "VS Code"
	case "cline":
		return "Cline"
	case "windsurf":
		return "Windsurf"
	case "openclaw":
		return "OpenClaw"
	case "opencode":
		return "OpenCode"
	case "zed":
		return "Zed"
	case "amp":
		return "Amp"
	case "gemini-cli":
		return "Gemini CLI"
	case "copilot-cli":
		return "Copilot CLI"
	case "amazon-q":
		return "Amazon Q"
	case "claude-code":
		return "Claude Code"
	case "roo-code":
		return "Roo Code"
	case "kilo-code":
		return "Kilo Code"
	case "boltai":
		return "BoltAI"
	case "jetbrains":
		return "JetBrains"
	default:
		return name
	}
}
