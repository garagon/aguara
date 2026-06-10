package types

import (
	"path/filepath"
	"strings"
)

// IsAgentInstructionFile reports whether path is an AI-agent instruction
// file -- a file an agent or AI editor auto-loads and follows as
// directives. A prompt injection committed in one of these is what the
// agent will actually obey, so it is a higher-trust surface than
// ordinary documentation: it is scanned for injection even without a
// markdown extension, and findings in it are weighted up rather than
// down.
//
// Recognised by base name, so it works the same for a directory walk and
// for a direct single-file scan:
//
//	.cursorrules / .windsurfrules / .clinerules  (single-file rules)
//	AGENTS.md                                    (cross-tool convention)
//	copilot-instructions.md                      (GitHub Copilot; also under .github/)
//
// The directory-scoped formats (.cursor/rules/*.mdc, .windsurf/rules/*)
// are intentionally left out for now: identifying them needs the full
// path, which a single-file scan does not carry, and the pattern matcher
// dispatches rules by extension or base name rather than by path. They
// are a follow-up once both can key on the containing directory.
//
// CLAUDE.md is also excluded: it is heavily used for legitimate project
// instructions, so weighting it as an attack surface is deferred to
// avoid false positives.
func IsAgentInstructionFile(path string) bool {
	switch strings.ToLower(filepath.Base(filepath.ToSlash(path))) {
	case ".cursorrules", ".windsurfrules", ".clinerules",
		"agents.md", "copilot-instructions.md":
		return true
	}
	return false
}
