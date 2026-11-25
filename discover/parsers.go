package discover

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// mcpConfigJSON represents the common structure of MCP client config files.
type mcpConfigJSON struct {
	MCPServers map[string]mcpServerJSON `json:"mcpServers"`
}

type mcpServerJSON struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env,omitempty"`

	// Remote servers. Raw values, so an unexpected type in one of these
	// fields does not make the whole server map fail to parse, which
	// would also hide the configuration from scan --auto.
	Type      json.RawMessage `json:"type,omitempty"`
	Transport json.RawMessage `json:"transport,omitempty"`
	URL       json.RawMessage `json:"url,omitempty"`
	ServerURL json.RawMessage `json:"serverUrl,omitempty"`
	HTTPURL   json.RawMessage `json:"httpUrl,omitempty"`
	Headers   json.RawMessage `json:"headers,omitempty"`
}

// server converts a parsed entry, filling Transport and URL for a remote
// server.
func (srv mcpServerJSON) server(name string) MCPServer {
	s := MCPServer{Name: name, Command: srv.Command, Args: srv.Args, Env: srv.Env, Headers: jsonStringMap(srv.Headers)}
	s.Transport = firstString(srv.Type, srv.Transport)
	s.URL = firstString(srv.URL, srv.ServerURL, srv.HTTPURL)
	switch {
	case s.Transport == "stdio":
		s.Transport = ""
	case s.Transport == "" && s.URL != "":
		s.Transport = "remote"
		if jsonString(srv.HTTPURL) != "" {
			s.Transport = "http"
		}
	}
	return s
}

// jsonString returns raw as a string when it is a JSON string, else "".
func jsonString(raw json.RawMessage) string {
	var v string
	if len(raw) == 0 || json.Unmarshal(raw, &v) != nil {
		return ""
	}
	return v
}

func firstString(raws ...json.RawMessage) string {
	for _, raw := range raws {
		if v := jsonString(raw); v != "" {
			return v
		}
	}
	return ""
}

// jsonStringMap returns the string-valued members of a JSON object.
func jsonStringMap(raw json.RawMessage) map[string]string {
	var obj map[string]json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &obj) != nil || len(obj) == 0 {
		return nil
	}
	out := make(map[string]string, len(obj))
	for k, v := range obj {
		if s := jsonString(v); s != "" {
			out[k] = s
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// sortedKeys returns the keys of m in order, so servers are listed the
// same way on every run.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
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
	for _, name := range sortedKeys(serverMap) {
		servers = append(servers, serverMap[name].server(name))
	}
	return servers
}

type openCodeServer struct {
	Command     []string          `json:"command"`
	Environment map[string]string `json:"environment"`
	Type        json.RawMessage   `json:"type,omitempty"`
	URL         json.RawMessage   `json:"url,omitempty"`
	Headers     json.RawMessage   `json:"headers,omitempty"`
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
	for _, name := range sortedKeys(mcpMap) {
		srv := mcpMap[name]
		s := MCPServer{Name: name, Env: srv.Environment, Headers: jsonStringMap(srv.Headers)}
		if len(srv.Command) > 0 {
			s.Command = srv.Command[0]
			if len(srv.Command) > 1 {
				s.Args = srv.Command[1:]
			}
		}
		// OpenCode spells a remote server "type": "remote" with a url.
		if s.URL = jsonString(srv.URL); s.URL != "" {
			s.Transport = jsonString(srv.Type)
			if s.Transport == "" || s.Transport == "local" {
				s.Transport = "remote"
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
			for _, key := range sortedKeys(projects) {
				var proj map[string]json.RawMessage
				if json.Unmarshal(projects[key], &proj) == nil {
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
	for _, name := range sortedKeys(serverMap) {
		if seen[name] {
			continue
		}
		seen[name] = true
		servers = append(servers, serverMap[name].server(name))
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
