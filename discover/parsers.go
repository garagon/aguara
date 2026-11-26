package discover

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
)

// mcpConfigJSON represents the common structure of MCP client config files.
type mcpConfigJSON struct {
	MCPServers map[string]mcpServerJSON `json:"mcpServers"`
}

// mcpServerJSON is the usual shape of one server entry. Discovery does not
// decode into it (see decodeServer, which reads entries leniently); tests
// use it to write configurations.
type mcpServerJSON struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env,omitempty"`
}

// warnFunc records a problem with one entry of a configuration file. A
// message names the field and the JSON type, never the value, which can be
// a secret.
type warnFunc func(format string, args ...any)

// jsonType names the JSON type of raw for a warning.
func jsonType(raw json.RawMessage) string {
	switch t := bytes.TrimSpace(raw); {
	case len(t) == 0:
		return "empty"
	case t[0] == '{':
		return "an object"
	case t[0] == '[':
		return "an array"
	case t[0] == '"':
		return "a string"
	case t[0] == 't' || t[0] == 'f':
		return "a boolean"
	case t[0] == 'n':
		return "null"
	default:
		return "a number"
	}
}

// lenientString reads a scalar as text: a string as itself, a number or
// boolean as written, null as "". An array or object is kept as compact
// JSON text and reported, so the entry stays visible.
func lenientString(raw json.RawMessage, field string, warn warnFunc) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	switch jsonType(raw) {
	case "null":
		return ""
	case "a number", "a boolean":
		return string(bytes.TrimSpace(raw))
	}
	warn("%s is %s; read as JSON text", field, jsonType(raw))
	var compact bytes.Buffer
	if json.Compact(&compact, raw) != nil {
		return string(raw)
	}
	return compact.String()
}

// lenientStrings reads a list of arguments: each element as lenientString
// does. A single string is read as one argument and reported.
func lenientStrings(raw json.RawMessage, field string, warn warnFunc) []string {
	if len(raw) == 0 || jsonType(raw) == "null" {
		return nil
	}
	var items []json.RawMessage
	if json.Unmarshal(raw, &items) != nil {
		warn("%s is %s; read as one argument", field, jsonType(raw))
		return []string{lenientString(raw, field, func(string, ...any) {})}
	}
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = lenientString(it, fmt.Sprintf("%s[%d]", field, i), warn)
	}
	return out
}

// lenientStringMap reads an object of names to values (env, headers), each
// value as lenientString does. Anything other than an object is reported
// and ignored.
func lenientStringMap(raw json.RawMessage, field string, warn warnFunc) map[string]string {
	if len(raw) == 0 || jsonType(raw) == "null" {
		return nil
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		warn("%s is %s; ignored", field, jsonType(raw))
		return nil
	}
	if len(obj) == 0 {
		return nil
	}
	out := make(map[string]string, len(obj))
	for _, k := range sortedKeys(obj) {
		out[k] = lenientString(obj[k], fmt.Sprintf("%s %q", field, k), warn)
	}
	return out
}

// decodeServer reads one server entry leniently, so a value of an
// unexpected type cannot hide the server, or the other servers of the
// file, from discover and scan --auto. It reports false for an entry that
// is not an object.
func decodeServer(name string, raw json.RawMessage, warn warnFunc) (MCPServer, bool) {
	serverWarn := func(format string, args ...any) {
		warn("server %q: "+format, append([]any{name}, args...)...)
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		warn("server %q is not an object; skipped", name)
		return MCPServer{}, false
	}
	s := MCPServer{
		Name:    name,
		Args:    lenientStrings(fields["args"], "args", serverWarn),
		Env:     lenientStringMap(fields["env"], "env", serverWarn),
		Headers: lenientStringMap(fields["headers"], "headers", serverWarn),
	}
	if !decodeCommandObject(fields["command"], &s, serverWarn) {
		s.Command = lenientString(fields["command"], "command", serverWarn)
	}
	s.Transport = firstString(fields["type"], fields["transport"])
	s.URL = firstString(fields["url"], fields["serverUrl"], fields["httpUrl"])
	switch {
	case s.Transport == "stdio":
		s.Transport = ""
	case s.Transport == "" && s.URL != "":
		s.Transport = "remote"
		if jsonString(fields["httpUrl"]) != "" {
			s.Transport = "http"
		}
	}
	return s, true
}

// decodeCommandObject reads a command given as an object with a "path",
// the form an editor documents ({"path", "args", "env"}), into s: the path
// becomes the command, its args come before any top-level args, and its
// env is merged with the top-level env (top-level entries win). It
// reports false when raw is not such an object.
func decodeCommandObject(raw json.RawMessage, s *MCPServer, warn warnFunc) bool {
	if jsonType(raw) != "an object" {
		return false
	}
	var c map[string]json.RawMessage
	if json.Unmarshal(raw, &c) != nil {
		return false
	}
	path, ok := c["path"]
	if !ok {
		return false
	}
	s.Command = lenientString(path, "command.path", warn)
	if args := lenientStrings(c["args"], "command.args", warn); len(args) > 0 {
		s.Args = append(args, s.Args...)
	}
	if env := lenientStringMap(c["env"], "command.env", warn); len(env) > 0 {
		for k, v := range s.Env {
			env[k] = v
		}
		s.Env = env
	}
	return true
}

// decodeServerMap reads a map of server names to entries. A value that is
// not an object is reported and yields no servers.
func decodeServerMap(raw json.RawMessage, warn warnFunc) map[string]MCPServer {
	var entries map[string]json.RawMessage
	if json.Unmarshal(raw, &entries) != nil {
		warn("the server list is %s, not an object; no servers read", jsonType(raw))
		return nil
	}
	servers := make(map[string]MCPServer, len(entries))
	for _, name := range sortedKeys(entries) {
		if s, ok := decodeServer(name, entries[name], warn); ok {
			servers[name] = s
		}
	}
	return servers
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

// collector gathers the warnings of one configuration file, prefixed with
// its path.
type collector struct {
	path     string
	warnings []string
}

func (c *collector) warn(format string, args ...any) {
	c.warnings = append(c.warnings, c.path+": "+fmt.Sprintf(format, args...))
}

// parseError reports a client file that was read but that the JSON
// reader rejects: a syntax error (including JSONC comments and trailing
// commas, which some clients accept), nesting too deep, or a top level
// that is not an object. Its message keeps the form "parsing <path>: ...".
type parseError struct {
	path string
	data []byte
	err  error
}

func (e *parseError) Error() string { return fmt.Sprintf("parsing %s: %v", e.path, e.err) }
func (e *parseError) Unwrap() error { return e.err }

// warning describes the failure after the path, like the other warnings,
// without quoting the file, which can hold secrets.
func (e *parseError) warning() string {
	var typeErr *json.UnmarshalTypeError
	if errors.As(e.err, &typeErr) {
		return fmt.Sprintf("%s: the file is %s, not a JSON object; no servers read", e.path, jsonType(bytes.TrimSpace(e.data)))
	}
	where := ""
	var syntaxErr *json.SyntaxError
	if errors.As(e.err, &syntaxErr) && syntaxErr.Offset > 0 && syntaxErr.Offset <= int64(len(e.data)) {
		where = fmt.Sprintf(" (near line %d)", bytes.Count(e.data[:syntaxErr.Offset], []byte("\n"))+1)
	}
	return e.path + ": the file could not be parsed as JSON" + where + "; no servers read. Some clients accept JSONC (comments, trailing commas), which discovery does not read"
}

// parseConfigWithKey parses a config file using the specified JSON key for the server map.
// If key is empty, defaults to "mcpServers".
// For VS Code ("servers" key), also tries "mcpServers" as fallback.
func parseConfigWithKey(path, key string) ([]MCPServer, error) {
	servers, _, err := parseConfigWithKeyWarnings(path, key)
	return servers, err
}

// parseConfigWithKeyWarnings is parseConfigWithKey that also returns the
// entries it could not read as expected.
func parseConfigWithKeyWarnings(path, key string) ([]MCPServer, []string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}

	if key == "" {
		key = "mcpServers"
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, nil, &parseError{path: path, data: data, err: err}
	}

	c := &collector{path: path}
	servers := extractServersFromKeyWarn(raw, key, c.warn)

	// Fallback: if primary key is "servers", also try "mcpServers" (VS Code compat)
	if len(servers) == 0 && key == "servers" {
		servers = extractServersFromKeyWarn(raw, "mcpServers", c.warn)
	}

	return servers, c.warnings, nil
}

func extractServersFromKey(raw map[string]json.RawMessage, key string) []MCPServer {
	return extractServersFromKeyWarn(raw, key, func(string, ...any) {})
}

func extractServersFromKeyWarn(raw map[string]json.RawMessage, key string, warn warnFunc) []MCPServer {
	serversRaw, ok := raw[key]
	if !ok {
		return nil
	}
	serverMap := decodeServerMap(serversRaw, warn)
	var servers []MCPServer
	for _, name := range sortedKeys(serverMap) {
		servers = append(servers, serverMap[name])
	}
	return servers
}

// parseOpenCodeConfig parses OpenCode's config format where servers are under "mcp"
// and commands are arrays: {"mcp": {"name": {"command": ["cmd", "arg1"], "environment": {...}}}}
func parseOpenCodeConfig(path string) ([]MCPServer, error) {
	servers, _, err := parseOpenCodeConfigWarnings(path)
	return servers, err
}

func parseOpenCodeConfigWarnings(path string) ([]MCPServer, []string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, nil, &parseError{path: path, data: data, err: err}
	}

	mcpRaw, ok := raw["mcp"]
	if !ok {
		return nil, nil, nil
	}

	c := &collector{path: path}
	var entries map[string]json.RawMessage
	if json.Unmarshal(mcpRaw, &entries) != nil {
		c.warn("the mcp key is %s, not an object; no servers read", jsonType(mcpRaw))
		return nil, c.warnings, nil
	}

	var servers []MCPServer
	for _, name := range sortedKeys(entries) {
		warn := func(format string, args ...any) {
			c.warn("server %q: "+format, append([]any{name}, args...)...)
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(entries[name], &fields) != nil {
			c.warn("server %q is not an object; skipped", name)
			continue
		}
		s := MCPServer{
			Name:    name,
			Env:     lenientStringMap(fields["environment"], "environment", warn),
			Headers: lenientStringMap(fields["headers"], "headers", warn),
		}
		command := lenientStrings(fields["command"], "command", warn)
		if len(command) > 0 {
			s.Command = command[0]
			if len(command) > 1 {
				s.Args = command[1:]
			}
		}
		// OpenCode spells a remote server "type": "remote" with a url.
		if s.URL = jsonString(fields["url"]); s.URL != "" {
			s.Transport = jsonString(fields["type"])
			if s.Transport == "" || s.Transport == "local" {
				s.Transport = "remote"
			}
		}
		servers = append(servers, s)
	}
	return servers, c.warnings, nil
}

// parseClaudeCodeConfig parses Claude Code's ~/.claude.json where mcpServers
// may be nested under scope keys: {"projects": {"/path": {"mcpServers": {...}}}, "mcpServers": {...}}
func parseClaudeCodeConfig(path string) ([]MCPServer, error) {
	servers, _, err := parseClaudeCodeConfigWarnings(path)
	return servers, err
}

func parseClaudeCodeConfigWarnings(path string) ([]MCPServer, []string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, nil, &parseError{path: path, data: data, err: err}
	}

	c := &collector{path: path}
	seen := map[string]bool{}
	var servers []MCPServer

	// Top-level mcpServers
	if topRaw, ok := raw["mcpServers"]; ok {
		servers = append(servers, extractUniqueServers(topRaw, seen, c.warn)...)
	}

	// Nested under "projects": each project scope may have mcpServers
	if projectsRaw, ok := raw["projects"]; ok {
		var projects map[string]json.RawMessage
		if json.Unmarshal(projectsRaw, &projects) == nil {
			for _, key := range sortedKeys(projects) {
				var proj map[string]json.RawMessage
				if json.Unmarshal(projects[key], &proj) == nil {
					if mcpRaw, ok := proj["mcpServers"]; ok {
						servers = append(servers, extractUniqueServers(mcpRaw, seen, c.warn)...)
					}
				}
			}
		}
	}

	return servers, c.warnings, nil
}

func extractUniqueServers(raw json.RawMessage, seen map[string]bool, warn warnFunc) []MCPServer {
	serverMap := decodeServerMap(raw, warn)
	var servers []MCPServer
	for _, name := range sortedKeys(serverMap) {
		if seen[name] {
			continue
		}
		seen[name] = true
		servers = append(servers, serverMap[name])
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
		return nil, &parseError{path: path, data: clean, err: err}
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
