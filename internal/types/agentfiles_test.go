package types

import "testing"

func TestIsAgentInstructionFile(t *testing.T) {
	yes := []string{
		// Base names, at the root and nested.
		".cursorrules", ".windsurfrules", ".clinerules", ".rules", ".roorules",
		".roorules-code", ".goosehints",
		"AGENTS.md", "agents.md", "AGENTS.override.md", "AGENT.md",
		"CLAUDE.md", ".claude/CLAUDE.md", "CLAUDE.local.md", "GEMINI.md",
		"copilot-instructions.md", ".github/copilot-instructions.md",
		"repo/sub/.cursorrules", "packages/web/AGENTS.md", ".junie/AGENTS.md",
		// Cursor rules: .mdc anywhere (single-file scans carry only the
		// base name), and .md under .cursor/rules.
		".cursor/rules/style.mdc", "project/.cursor/rules/security.mdc",
		".cursor/rules/frontend/react.mdc", "style.mdc", ".cursor/rules/notes.md",
		".cursor/agents/reviewer.md",
		// Windsurf / Devin Desktop.
		".windsurf/rules/general.md", ".devin/rules/general.md",
		".windsurf/global_rules.md", ".devin/global_rules.md",
		// Cline.
		".clinerules/html.md", ".clinerules/nested/a.md", ".clinerules/01-general",
		".cline/rules/a.txt",
		// Roo Code.
		".roo/rules/html.md", ".roo/rules/sub/x.txt", ".roo/rules-code/a.md",
		".roo/rules-architect/deep/b.md",
		// Kiro.
		".kiro/steering/html.md", ".kiro/agents/helper.md",
		// GitHub Copilot.
		".github/instructions/html.instructions.md",
		".github/instructions/web/react.instructions.md",
		".github/prompts/setup.prompt.md", ".github/agents/planner.agent.md",
		// Claude Code.
		".claude/rules/testing.md", ".claude/rules/frontend/react.md",
		".claude/agents/helper.md", ".claude/commands/setup.md",
		".claude/commands/frontend/component.md",
		// Gemini CLI, Continue, JetBrains.
		".gemini/agents/helper.md", ".gemini/system.md",
		".continue/rules/style.md", ".aiassistant/rules/style.md",
		".junie/guidelines.md", ".junie/playbook.md", ".junie/guidelines/a.md",
		".junie/rules/a.md",
		// Case-insensitive and Windows separators.
		".Cursor/Rules/Style.MDC", `.github\instructions\a.instructions.md`,
	}
	for _, p := range yes {
		if !IsAgentInstructionFile(p) {
			t.Errorf("IsAgentInstructionFile(%q) = false, want true", p)
		}
	}
	no := []string{
		"README.md", "docs/guide.md", "src/main.go", "package.json",
		"notes.txt", "SKILL.md", ".claude/skills/x/SKILL.md",
		"cursorrules",               // missing leading dot
		"my.cursorrules.backup.txt", // not the rules file itself
		"CONVENTIONS.md",            // Aider loads it only when configured
		".continuerules",            // not in Continue's documentation
		".github/instructions/notes.md",
		".github/prompts/readme.md",
		".github/workflows/ci.yml",
		".windsurf/rules/sub/deep.md", // Windsurf rules are not recursive
		".roo/rules/.DS_Store",
		".roo/rulesets/a.md",
		".claude/settings.json", ".claude/agents/config.json",
		".gemini/settings.json", ".kiro/steering/notes.txt",
		"rules/a.md", "x/rules/.cursor/a.md",
		".cursor/mcp.json",
	}
	for _, p := range no {
		if IsAgentInstructionFile(p) {
			t.Errorf("IsAgentInstructionFile(%q) = true, want false", p)
		}
	}
}
