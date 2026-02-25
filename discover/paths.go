// Package discover auto-detects MCP client configurations across 17
// known AI coding assistants and agent frameworks.
package discover

import (
	"os"
	"path/filepath"
	"runtime"
)

// Client represents a known MCP client application.
type Client struct {
	Name      string
	Paths     []string // Config file paths to check
	ConfigKey string   // JSON key for server map ("" = "mcpServers")
}

// KnownClients returns all supported MCP client applications with their config paths.
func KnownClients() []Client {
	home, _ := os.UserHomeDir()
	clients := []Client{
		{
			Name:  "claude-desktop",
			Paths: claudeDesktopPaths(home),
		},
		{
			Name:  "cursor",
			Paths: []string{filepath.Join(home, ".cursor", "mcp.json")},
		},
		{
			Name:      "vscode",
			Paths:     []string{filepath.Join(home, ".vscode", "mcp.json")},
			ConfigKey: "servers", // VS Code native MCP uses "servers"; parser also tries "mcpServers" fallback
		},
		{
			Name:  "cline",
			Paths: []string{filepath.Join(home, ".cline", "mcp_settings.json")},
		},
		{
			Name: "windsurf",
			Paths: []string{
				filepath.Join(home, ".windsurf", "mcp.json"),
				filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"),
			},
		},
		{
			Name:  "openclaw",
			Paths: []string{filepath.Join(home, ".openclaw", "openclaw.json")},
		},
		{
			Name:      "opencode",
			Paths:     []string{filepath.Join(home, ".config", "opencode", "opencode.json")},
			ConfigKey: "opencode", // custom parser signal
		},
		{
			Name:      "zed",
			Paths:     []string{filepath.Join(home, ".config", "zed", "settings.json")},
			ConfigKey: "context_servers",
		},
		{
			Name:      "amp",
			Paths:     []string{filepath.Join(home, ".config", "amp", "settings.json")},
			ConfigKey: "mcpServers",
		},
		{
			Name:  "gemini-cli",
			Paths: []string{filepath.Join(home, ".gemini", "settings.json")},
		},
		{
			Name:  "copilot-cli",
			Paths: []string{filepath.Join(home, ".copilot", "mcp-config.json")},
		},
		{
			Name:  "amazon-q",
			Paths: []string{filepath.Join(home, ".aws", "amazonq", "mcp.json")},
		},
		{
			Name:      "claude-code",
			Paths:     []string{filepath.Join(home, ".claude.json")},
			ConfigKey: "claude-code", // custom parser signal
		},
		{
			Name:  "roo-code",
			Paths: rooCodePaths(home),
		},
		{
			Name:  "kilo-code",
			Paths: kiloCodePaths(home),
		},
		{
			Name:  "boltai",
			Paths: boltAIPaths(home),
		},
		{
			Name:  "jetbrains",
			Paths: []string{filepath.Join(home, ".junie", "mcp", "mcp.json")},
		},
	}
	return clients
}

func claudeDesktopPaths(home string) []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{
			filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
		}
	case "linux":
		return []string{
			filepath.Join(home, ".config", "claude", "claude_desktop_config.json"),
		}
	case "windows":
		appdata := os.Getenv("APPDATA")
		if appdata == "" {
			appdata = filepath.Join(home, "AppData", "Roaming")
		}
		return []string{
			filepath.Join(appdata, "Claude", "claude_desktop_config.json"),
		}
	default:
		return nil
	}
}

func rooCodePaths(home string) []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{
			filepath.Join(home, "Library", "Application Support", "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings", "mcp_settings.json"),
		}
	case "linux":
		return []string{
			filepath.Join(home, ".config", "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings", "mcp_settings.json"),
		}
	case "windows":
		appdata := os.Getenv("APPDATA")
		if appdata == "" {
			appdata = filepath.Join(home, "AppData", "Roaming")
		}
		return []string{
			filepath.Join(appdata, "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings", "mcp_settings.json"),
		}
	default:
		return nil
	}
}

func kiloCodePaths(home string) []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{
			filepath.Join(home, "Library", "Application Support", "Code", "User", "globalStorage", "kilocode.kilo-code", "settings", "mcp_settings.json"),
		}
	case "linux":
		return []string{
			filepath.Join(home, ".config", "Code", "User", "globalStorage", "kilocode.kilo-code", "settings", "mcp_settings.json"),
		}
	case "windows":
		appdata := os.Getenv("APPDATA")
		if appdata == "" {
			appdata = filepath.Join(home, "AppData", "Roaming")
		}
		return []string{
			filepath.Join(appdata, "Code", "User", "globalStorage", "kilocode.kilo-code", "settings", "mcp_settings.json"),
		}
	default:
		return nil
	}
}

func boltAIPaths(home string) []string {
	if runtime.GOOS == "darwin" {
		return []string{filepath.Join(home, ".boltai", "mcp.json")}
	}
	return nil
}
