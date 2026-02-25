package discover

import (
	"encoding/json"
	"fmt"
	"os"
)

// mcpConfigJSON represents the common structure of MCP client config files.
type mcpConfigJSON struct {
	MCPServers map[string]mcpServerJSON `json:"mcpServers"`
}

type mcpServerJSON struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env,omitempty"`
}

// parseConfigWithKey parses a config file using the specified JSON key for the server map.
// If key is empty, defaults to "mcpServers".
// For VS Code ("servers" key), also tries "mcpServers" as fallback.
func parseConfigWithKey(path, key string) ([]MCPServer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if key == "" {
		key = "mcpServers"
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	servers := extractServersFromKey(raw, key)

	// Fallback: if primary key is "servers", also try "mcpServers" (VS Code compat)
	if len(servers) == 0 && key == "servers" {
		servers = extractServersFromKey(raw, "mcpServers")
	}

	return servers, nil
}

func extractServersFromKey(raw map[string]json.RawMessage, key string) []MCPServer {
	serversRaw, ok := raw[key]
	if !ok {
		return nil
	}

	var serverMap map[string]mcpServerJSON
	if err := json.Unmarshal(serversRaw, &serverMap); err != nil {
		return nil
	}

	var servers []MCPServer
	for name, srv := range serverMap {
		servers = append(servers, MCPServer{
			Name:    name,
			Command: srv.Command,
			Args:    srv.Args,
			Env:     srv.Env,
		})
	}
	return servers
}

type openCodeServer struct {
	Command     []string          `json:"command"`
	Environment map[string]string `json:"environment"`
}

// parseOpenCodeConfig parses OpenCode's config format where servers are under "mcp"
// and commands are arrays: {"mcp": {"name": {"command": ["cmd", "arg1"], "environment": {...}}}}
func parseOpenCodeConfig(path string) ([]MCPServer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	mcpRaw, ok := raw["mcp"]
	if !ok {
		return nil, nil
	}

	var mcpMap map[string]openCodeServer
	if err := json.Unmarshal(mcpRaw, &mcpMap); err != nil {
		return nil, fmt.Errorf("parsing mcp key in %s: %w", path, err)
	}

	var servers []MCPServer
	for name, srv := range mcpMap {
		s := MCPServer{Name: name, Env: srv.Environment}
		if len(srv.Command) > 0 {
			s.Command = srv.Command[0]
			if len(srv.Command) > 1 {
				s.Args = srv.Command[1:]
			}
		}
		servers = append(servers, s)
	}
	return servers, nil
}

// parseClaudeCodeConfig parses Claude Code's ~/.claude.json where mcpServers
// may be nested under scope keys: {"projects": {"/path": {"mcpServers": {...}}}, "mcpServers": {...}}
func parseClaudeCodeConfig(path string) ([]MCPServer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	seen := map[string]bool{}
	var servers []MCPServer

	// Top-level mcpServers
	if topRaw, ok := raw["mcpServers"]; ok {
		servers = append(servers, extractUniqueServers(topRaw, seen)...)
	}

	// Nested under "projects" — each project scope may have mcpServers
	if projectsRaw, ok := raw["projects"]; ok {
		var projects map[string]json.RawMessage
		if json.Unmarshal(projectsRaw, &projects) == nil {
			for _, projRaw := range projects {
				var proj map[string]json.RawMessage
				if json.Unmarshal(projRaw, &proj) == nil {
					if mcpRaw, ok := proj["mcpServers"]; ok {
						servers = append(servers, extractUniqueServers(mcpRaw, seen)...)
					}
				}
			}
		}
	}

	return servers, nil
}

func extractUniqueServers(raw json.RawMessage, seen map[string]bool) []MCPServer {
	var serverMap map[string]mcpServerJSON
	if err := json.Unmarshal(raw, &serverMap); err != nil {
		return nil
	}

	var servers []MCPServer
	for name, srv := range serverMap {
		if seen[name] {
			continue
		}
		seen[name] = true
		servers = append(servers, MCPServer{
			Name:    name,
			Command: srv.Command,
			Args:    srv.Args,
			Env:     srv.Env,
		})
	}
	return servers
}

// OpenClaw types for config parsing.
type openClawConfig struct {
	Gateway  ocGateway          `json:"gateway"`
	Agents   map[string]ocAgent `json:"agents"`
	Tools    ocTools            `json:"tools"`
	Channels map[string]any     `json:"channels"`
}

type ocGateway struct {
	Port int    `json:"port"`
	Bind string `json:"bind"`
}

type ocTools struct {
	Profile string   `json:"profile"`
	Allow   []string `json:"allow"`
	Deny    []string `json:"deny"`
}

type ocAgent struct {
	Sandbox bool `json:"sandbox"`
}

// scanOpenClawConfig parses an OpenClaw config file and maps it to ClientResult
// for compatibility with the existing discovery model.
func scanOpenClawConfig(path string) (*ClientResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	clean := StripJSON5Comments(data)

	var cfg openClawConfig
	if err := json.Unmarshal(clean, &cfg); err != nil {
		return nil, err
	}

	var servers []MCPServer

	// Map the gateway as a server entry
	bind := cfg.Gateway.Bind
	if bind == "" {
		bind = "127.0.0.1"
	}
	servers = append(servers, MCPServer{
		Name:    "openclaw-gateway",
		Command: "openclaw",
		Args:    []string{"gateway", bind},
	})

	// Map each agent as a server entry
	for name := range cfg.Agents {
		servers = append(servers, MCPServer{
			Name:    name,
			Command: "openclaw",
			Args:    []string{"agent", name},
		})
	}

	// Map channels as server entries
	for name := range cfg.Channels {
		servers = append(servers, MCPServer{
			Name:    "channel-" + name,
			Command: "openclaw",
			Args:    []string{"channel", name},
		})
	}

	return &ClientResult{
		Client:  "openclaw",
		Path:    path,
		Servers: servers,
	}, nil
}

// StripJSON5Comments removes // and /* */ comments from JSON5 data,
// being careful not to strip inside string literals.
func StripJSON5Comments(data []byte) []byte {
	var out []byte
	i := 0
	n := len(data)

	for i < n {
		// String literal — copy verbatim
		if data[i] == '"' {
			out = append(out, data[i])
			i++
			for i < n {
				if data[i] == '\\' && i+1 < n {
					out = append(out, data[i], data[i+1])
					i += 2
					continue
				}
				out = append(out, data[i])
				if data[i] == '"' {
					i++
					break
				}
				i++
			}
			continue
		}

		// Line comment
		if i+1 < n && data[i] == '/' && data[i+1] == '/' {
			i += 2
			for i < n && data[i] != '\n' {
				i++
			}
			continue
		}

		// Block comment
		if i+1 < n && data[i] == '/' && data[i+1] == '*' {
			i += 2
			for i+1 < n {
				if data[i] == '*' && data[i+1] == '/' {
					i += 2
					break
				}
				i++
			}
			continue
		}

		out = append(out, data[i])
		i++
	}

	return out
}
