package types

import (
	"path/filepath"
	"strings"
)

// IsAgentInstructionFile reports whether path is an AI-agent instruction
// file: a file that a coding agent or AI editor loads from the repository
// and follows as directives (project rules, steering files, custom agent
// and command prompts). A prompt injection committed in one of these is
// what the agent will actually obey, so it is a higher-trust surface than
// ordinary documentation. The pattern matcher treats these files as
// Markdown for rule targeting whatever their extension, the NLP analyzer
// runs its Markdown pipeline on them, and confidence scoring weights their
// findings up rather than down.
//
// path may use slash or backslash separators. A file qualifies when:
//
//   - its base name is a documented instruction file name in the
//     documented spelling (AGENTS.md, CLAUDE.md, .cursorrules, ...),
//     anywhere in the tree; tools also read nested copies of these;
//   - its base name is one of those names in another letter case and the
//     file sits at the scan root or directly inside a config directory
//     the tools read it from (.claude/, .junie/). On case-insensitive file
//     systems the tool loads it there, while elsewhere lowercase names
//     such as docs/agent.md or docs/providers/gemini.md are ordinary
//     documentation pages;
//   - it has the .mdc extension, Cursor's rule file format; or
//   - it sits in a documented tool directory (.cursor/rules/,
//     .github/instructions/, .claude/commands/, ...). These dot-directories
//     cannot be mistaken for documentation pages, so they match in any
//     letter case and anywhere in the path (monorepo packages, vendored
//     projects).
//
// A single-file scan only carries the base name, which counts as the scan
// root. The list is limited to locations each tool's own documentation
// describes; the source for every entry is noted next to it.
func IsAgentInstructionFile(path string) bool {
	slashed := strings.ReplaceAll(path, "\\", "/")
	dir, base := "", slashed
	if i := strings.LastIndexByte(slashed, '/'); i >= 0 {
		dir, base = slashed[:i], slashed[i+1:]
	}
	if instructionBaseNames[base] || strings.HasPrefix(base, ".roorules-") {
		return true
	}
	p := strings.ToLower(slashed)
	lowerBase := strings.ToLower(base)
	if dir == "" && (foldedBaseNames[lowerBase] || strings.HasPrefix(lowerBase, ".roorules-")) {
		return true
	}
	if parent := strings.ToLower(dir[strings.LastIndexByte(dir, '/')+1:]); configDirNames[parent][lowerBase] {
		return true
	}
	// Cursor project rules "must use the .mdc extension"; the extension is
	// Cursor's rule format, which also covers a single-file scan of
	// .cursor/rules/x.mdc.
	// https://cursor.com/docs/rules
	if filepath.Ext(lowerBase) == ".mdc" {
		return true
	}
	dirs := strings.Split(p, "/")
	dirs = dirs[:len(dirs)-1]
	for _, c := range instructionDirs {
		if c.matches(dirs, lowerBase) {
			return true
		}
	}
	return false
}

// IsAgentDirectiveFile reports whether everything in path, fenced code
// blocks included, is something an agent is told to act on: a skill
// definition (SKILL.md) or an agent instruction file. In ordinary
// documentation a fenced block is an example for a human reader, so
// scanners treat matches there as less severe; in these files a fenced
// install command under "Setup" is what the agent will run, so code
// blocks must not lower severity or confidence. SKILL.md is matched in
// any case, as the skill-policy and skill-chain analyzers do.
func IsAgentDirectiveFile(path string) bool {
	base := path
	if i := strings.LastIndexAny(path, `/\`); i >= 0 {
		base = path[i+1:]
	}
	return strings.EqualFold(base, "SKILL.md") || IsAgentInstructionFile(path)
}

// instructionBaseNames are instruction file names in their documented
// spelling. They are recognised anywhere in the tree.
var instructionBaseNames = map[string]bool{
	// Cross-tool convention read by Codex, Cursor, GitHub Copilot, Devin
	// (Windsurf), Cline, Roo Code, Kiro, Goose, Zed, JetBrains AI Assistant
	// and Junie, and by Claude Code (also as .claude/AGENTS.md) when no
	// CLAUDE.md exists.
	// https://developers.openai.com/codex/guides/agents-md
	// https://cursor.com/docs/rules
	// https://docs.github.com/en/copilot/how-tos/configure-custom-instructions/add-repository-instructions
	// https://code.claude.com/docs/en/memory
	"AGENTS.md": true,
	// Codex reads AGENTS.override.md in place of AGENTS.md.
	// https://developers.openai.com/codex/guides/agents-md
	"AGENTS.override.md": true,
	// Devin loads AGENTS.local.md (personal rules) like AGENTS.md.
	// https://docs.devin.ai/cli/extensibility/rules
	"AGENTS.local.md": true,
	// Zed, Roo Code and Devin fall back to AGENT.md.
	// https://zed.dev/docs/ai/instructions
	// https://roocodeinc.github.io/Roo-Code/features/custom-instructions
	// https://docs.devin.ai/cli/extensibility/rules
	"AGENT.md": true,
	// Claude Code project memory (also ./.claude/CLAUDE.md) and personal
	// project memory; GitHub Copilot, Cursor, Devin and Zed read CLAUDE.md
	// too.
	// https://code.claude.com/docs/en/memory
	"CLAUDE.md":       true,
	"CLAUDE.local.md": true,
	// Gemini CLI context file; GitHub Copilot and Zed read it too.
	// https://geminicli.com/docs/cli/gemini-md/
	"GEMINI.md": true,
	// Zed project rules, and the single-file rule formats Zed reads as
	// fallbacks (Cursor's legacy .cursorrules, Windsurf's legacy
	// .windsurfrules, Cline's .clinerules).
	// https://zed.dev/docs/ai/instructions
	// https://docs.devin.ai/cli/extensibility/rules
	// https://docs.cline.bot/customization/cline-rules
	".rules":         true,
	".cursorrules":   true,
	".windsurfrules": true,
	".clinerules":    true,
	// Roo Code single-file workspace rules; .roorules-{modeSlug} is
	// matched by prefix.
	// https://roocodeinc.github.io/Roo-Code/features/custom-instructions
	".roorules": true,
	// Goose project hints.
	// https://goose-docs.ai/docs/guides/context-engineering/using-goosehints
	".goosehints": true,
}

// foldedBaseNames holds instructionBaseNames lowercased, for the
// case-insensitive match at the scan root.
var foldedBaseNames = func() map[string]bool {
	m := make(map[string]bool, len(instructionBaseNames))
	for name := range instructionBaseNames {
		m[strings.ToLower(name)] = true
	}
	return m
}()

// configDirNames are the instruction files a tool reads from inside its
// own config directory, lowercased: matched in any case directly in that
// directory.
var configDirNames = map[string]map[string]bool{
	// ./.claude/CLAUDE.md and .claude/AGENTS.md.
	// https://code.claude.com/docs/en/memory
	".claude": {"claude.md": true, "agents.md": true},
	// .junie/AGENTS.md.
	// https://junie.jetbrains.com/docs/guidelines-and-memory.html
	".junie": {"agents.md": true},
}

// instructionDir is a directory convention: files inside dir (a sequence of
// consecutive directory names) whose name ends with one of suffixes. When
// prefix is set, the last element of dir only has to start with it (Roo
// Code's rules-{modeSlug}). recursive admits files in subdirectories.
type instructionDir struct {
	dir       []string
	prefix    bool
	recursive bool
	suffixes  []string
	names     []string // exact file names, instead of suffixes
}

var (
	mdOnly   = []string{".md"}
	textLike = []string{".md", ".markdown", ".txt", ""}
)

// instructionDirs are instruction files recognised by their directory.
var instructionDirs = []instructionDir{
	// Cursor ignores plain .md files in .cursor/rules (its rules are .mdc,
	// matched by extension above), but Devin "reads from
	// .cursor/rules/*.md and .cursor/rules/*.mdc". Cursor subagents.
	// https://cursor.com/docs/rules
	// https://docs.devin.ai/cli/extensibility/rules
	// https://cursor.com/docs/subagents
	{dir: []string{".cursor", "rules"}, suffixes: mdOnly},
	{dir: []string{".cursor", "agents"}, suffixes: mdOnly},
	// Windsurf / Devin Desktop workspace rules and global rules.
	// https://docs.devin.ai/desktop/devin-local/customizations
	// https://docs.devin.ai/cli/extensibility/rules
	{dir: []string{".windsurf", "rules"}, suffixes: mdOnly},
	{dir: []string{".devin", "rules"}, suffixes: mdOnly},
	{dir: []string{".windsurf"}, names: []string{"global_rules.md"}},
	{dir: []string{".devin"}, names: []string{"global_rules.md"}},
	// Cline rules directories.
	// https://docs.cline.bot/customization/cline-rules
	{dir: []string{".clinerules"}, recursive: true, suffixes: textLike},
	{dir: []string{".cline", "rules"}, recursive: true, suffixes: textLike},
	// Roo Code workspace and mode-specific rules, read recursively; any
	// text file counts.
	// https://roocodeinc.github.io/Roo-Code/features/custom-instructions
	{dir: []string{".roo", "rules"}, recursive: true, suffixes: textLike},
	{dir: []string{".roo", "rules-"}, prefix: true, recursive: true, suffixes: textLike},
	// Kiro steering files and custom agents.
	// https://kiro.dev/docs/steering/
	// https://kiro.dev/docs/custom-agents/creating/
	{dir: []string{".kiro", "steering"}, suffixes: mdOnly},
	{dir: []string{".kiro", "agents"}, suffixes: mdOnly},
	// GitHub Copilot repository-wide and path-specific instructions, prompt
	// files and custom agents. Zed also reads
	// .github/copilot-instructions.md.
	// https://docs.github.com/en/copilot/how-tos/configure-custom-instructions/add-repository-instructions
	// https://zed.dev/docs/ai/instructions
	// https://code.visualstudio.com/docs/agent-customization/prompt-files
	// https://code.visualstudio.com/docs/agents/reference/custom-agent-file-reference
	{dir: []string{".github"}, names: []string{"copilot-instructions.md"}},
	{dir: []string{".github", "instructions"}, recursive: true, suffixes: []string{".instructions.md"}},
	{dir: []string{".github", "prompts"}, suffixes: []string{".prompt.md"}},
	{dir: []string{".github", "agents"}, suffixes: mdOnly},
	// Claude Code rules, subagents and slash commands.
	// https://code.claude.com/docs/en/memory
	// https://code.claude.com/docs/en/sub-agents
	// https://code.claude.com/docs/en/skills
	{dir: []string{".claude", "rules"}, recursive: true, suffixes: mdOnly},
	{dir: []string{".claude", "agents"}, recursive: true, suffixes: mdOnly},
	{dir: []string{".claude", "commands"}, recursive: true, suffixes: mdOnly},
	// Gemini CLI subagents and the project system prompt override.
	// https://geminicli.com/docs/core/subagents/
	// https://geminicli.com/docs/cli/system-prompt/
	{dir: []string{".gemini", "agents"}, suffixes: mdOnly},
	{dir: []string{".gemini"}, names: []string{"system.md"}},
	// Continue rules.
	// https://docs.continue.dev/customize/deep-dives/rules
	{dir: []string{".continue", "rules"}, suffixes: mdOnly},
	// JetBrains AI Assistant project rules.
	// https://www.jetbrains.com/help/ai-assistant/configure-project-rules.html
	{dir: []string{".aiassistant", "rules"}, suffixes: mdOnly},
	// JetBrains Junie guidelines, rules and playbook.
	// https://junie.jetbrains.com/docs/guidelines-and-memory.html
	{dir: []string{".junie"}, names: []string{"guidelines.md", "playbook.md"}},
	{dir: []string{".junie", "guidelines"}, recursive: true, suffixes: mdOnly},
	{dir: []string{".junie", "rules"}, suffixes: mdOnly},
}

// matches reports whether a file named base inside the directory chain dirs
// (lowercased, outermost first) falls under the convention.
func (c instructionDir) matches(dirs []string, base string) bool {
	if !c.fileMatches(base) {
		return false
	}
	n := len(c.dir)
	for end := len(dirs); end >= n; end-- {
		if end != len(dirs) && !c.recursive {
			return false
		}
		if c.dirMatchesAt(dirs, end-n) {
			return true
		}
	}
	return false
}

func (c instructionDir) dirMatchesAt(dirs []string, start int) bool {
	for i, want := range c.dir {
		got := dirs[start+i]
		if c.prefix && i == len(c.dir)-1 {
			if !strings.HasPrefix(got, want) {
				return false
			}
			continue
		}
		if got != want {
			return false
		}
	}
	return true
}

func (c instructionDir) fileMatches(base string) bool {
	if base == "" {
		return false
	}
	if len(c.names) > 0 {
		for _, n := range c.names {
			if base == n {
				return true
			}
		}
		return false
	}
	for _, s := range c.suffixes {
		switch {
		case s == "":
			// Extensionless text file such as "01-general"; dotfiles
			// (.DS_Store and the like) are not rules.
			if !strings.Contains(base, ".") {
				return true
			}
		case strings.HasSuffix(base, s) && len(base) > len(s):
			return true
		}
	}
	return false
}
