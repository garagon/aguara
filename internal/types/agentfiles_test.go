package types

import "testing"

func TestIsAgentInstructionFile(t *testing.T) {
	yes := []string{
		".cursorrules", ".windsurfrules", ".clinerules",
		"AGENTS.md", "agents.md", "copilot-instructions.md",
		".github/copilot-instructions.md",
		"repo/sub/.cursorrules",
	}
	for _, p := range yes {
		if !IsAgentInstructionFile(p) {
			t.Errorf("IsAgentInstructionFile(%q) = false, want true", p)
		}
	}
	no := []string{
		"README.md", "docs/guide.md", "src/main.go", "package.json",
		"notes.txt", "CLAUDE.md", // CLAUDE.md intentionally excluded in v1
		"cursorrules",               // missing leading dot
		"my.cursorrules.backup.txt", // not the rules file itself
		// Directory-scoped formats are deferred (see doc comment).
		".cursor/rules/style.mdc", "project/.cursor/rules/security.mdc",
		".windsurf/rules/general.md", "x/.windsurf/rules/anything",
	}
	for _, p := range no {
		if IsAgentInstructionFile(p) {
			t.Errorf("IsAgentInstructionFile(%q) = true, want false", p)
		}
	}
}
