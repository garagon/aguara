// Package agentpolicy is a small, auditable analyzer for AI-agent host
// configuration posture. It reads a project's Claude Code settings file
// (.claude/settings.json, .claude/settings.local.json) and reports
// settings that are dangerous to inherit from a cloned repository: hooks
// that download and run remote code, environment variables that inject
// code into spawned processes, a default permission mode that bypasses
// the approval prompt, auto-approval of project MCP servers, allow rules
// that pre-approve dangerous commands or secret reads, and credential
// helpers that run repo-shipped scripts.
//
// Threat model (verified against current Claude Code docs): a checked-in
// .claude/settings.json is loaded for anyone who opens the repo, and
// after the one-time workspace-trust prompt its hooks and helpers run
// AUTOMATICALLY, without per-action approval (a SessionStart hook fires
// on session open). So the question this analyzer asks is not "did the
// developer configure something" but "is this value dangerous to
// inherit from someone else's repo."
//
// Design rules (same discipline as pnpm-policy):
//   - Exact target. Only .claude/settings(.local).json. A generic
//     settings.json elsewhere is never a target.
//   - Fire on the dangerous SHAPE of a value, never on the mere presence
//     of a feature: hooks, permissions, and env are all normal and
//     common. Absence never fires.
//   - Malformed JSON is silent (never a panic). Each top-level key is
//     decoded independently, so one mistyped block does not blind the
//     rest of the analyzer.
//   - Fixed severities, so the catalog (explain / list-rules) and scan
//     output never disagree; emit metadata is derived from RuleMetadata.
package agentpolicy

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/garagon/aguara/internal/rulemeta"
	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/types"
)

// AnalyzerName is the analyzer identifier surfaced on findings.
const AnalyzerName = rulemeta.AnalyzerAgentPolicy

var (
	// hookFetchExecRe matches a fetch PIPED directly into an interpreter
	// (`curl … | sh`): the only form where the downloaded bytes
	// unambiguously become the interpreter's input. An optional wrapper
	// between the pipe and the interpreter is allowed (sudo / command /
	// exec / env VAR=…, or an absolute/relative path such as /bin/bash),
	// so `curl … | sudo sh` is covered. A "&&"/";" CHAIN is deliberately
	// NOT treated as fetch-exec here: `curl health && bash build.sh`
	// runs two unrelated commands. The genuine chain form -- download a
	// file, then run THAT file -- is handled by fetchThenRunsFile, and
	// the command-substitution form by evalSubstRe.
	hookFetchExecRe = regexp.MustCompile(`(?i)\b(curl|wget|iwr|invoke-webrequest|fetch)\b[^\n]*?\|\s*(?:sudo\s+|command\s+|exec\s+|env\s+(?:\S+=\S+\s+)*|[~./][^\s|;&]*/)*(sh|bash|zsh|dash|ash|node|deno|bun|python3?|ruby|perl|php)\b`)
	// evalSubstRe catches `eval "$(curl ...)"`, `exec $(wget ...)`, and
	// `sh -c "$(curl ...)"`: an interpreter running the fetched bytes via
	// command substitution.
	evalSubstRe = regexp.MustCompile(`(?i)\b(eval|exec|source|(?:sh|bash|zsh|dash|ash|node|deno|bun|python3?|ruby|perl|php)\s+-c)\b[^\n]*\$\(\s*(curl|wget|iwr|fetch)\b`)
	// fetchOutputRe captures the file a curl/wget download is written to:
	// a short flag cluster ending in o/O (-o, -O, -qO, -sLo), --output,
	// or a shell redirect. fetchThenRunsFile then confirms an interpreter
	// runs THAT SAME file, so a newline-separated "curl -o /tmp/a\nbash
	// /tmp/a" is caught while an unrelated two-line hook is not.
	fetchOutputRe = regexp.MustCompile(`(?i)\b(?:curl|wget)\b[^\n]*?(?:\s-[a-z]*[oO]\s+|--output(?:-document)?[=\s]+|>\s*)('?"?)([^\s'";|&]+)`)
	interpRe      = `(?i)\b(sh|bash|zsh|dash|ash|node|deno|bun|python3?|ruby|perl|php)\b`
)

// envExecVars are environment variables whose presence in a committed
// settings file injects code into spawned processes. NODE_OPTIONS is
// handled separately because its safe forms (e.g. --max-old-space-size)
// are common; only the code-loading flags trip it.
var envExecVars = map[string]bool{
	"LD_PRELOAD":            true,
	"LD_LIBRARY_PATH":       true,
	"DYLD_INSERT_LIBRARIES": true,
	"DYLD_LIBRARY_PATH":     true,
	"PYTHONSTARTUP":         true,
	"PYTHONPATH":            true,
	"BASH_ENV":              true,
	"ENV":                   true,
	"GIT_SSH_COMMAND":       true,
	"RUBYOPT":               true,
	"PERL5LIB":              true,
}

// nodeOptionsExecRe matches the NODE_OPTIONS flags that load and run
// code (as opposed to tuning the runtime).
var nodeOptionsExecRe = regexp.MustCompile(`(?i)--(require|import|loader|experimental-loader)\b`)

// credentialHelpers are the settings keys that execute a script to mint
// or refresh credentials. A repo-relative target runs repo code with
// access to the material it produces.
var credentialHelpers = []string{
	"apiKeyHelper", "awsAuthRefresh", "awsCredentialExport",
	"gcpAuthRefresh", "otelHeadersHelper",
}

// Analyzer implements scanner.Analyzer.
type Analyzer struct{}

// New constructs the agent-policy analyzer.
func New() *Analyzer { return &Analyzer{} }

// Name returns the analyzer identifier.
func (a *Analyzer) Name() string { return AnalyzerName }

// settings is the subset of the Claude Code settings schema this
// analyzer evaluates. Each top-level key is decoded from a RawMessage
// independently so a single mistyped block does not blind the rest.
type rawSettings struct {
	Permissions                json.RawMessage `json:"permissions"`
	Hooks                      json.RawMessage `json:"hooks"`
	Env                        json.RawMessage `json:"env"`
	EnableAllProjectMcpServers json.RawMessage `json:"enableAllProjectMcpServers"`
}

type permissions struct {
	DefaultMode string   `json:"defaultMode"`
	Allow       []string `json:"allow"`
}

type hookEntry struct {
	Type    string `json:"type"`
	Command string `json:"command"`
}

type hookMatcher struct {
	Hooks []hookEntry `json:"hooks"`
}

// Analyze reads a Claude Code settings file and reports dangerous
// posture. A non-target file, malformed JSON, or a non-object root all
// return no findings (and never panic).
func (a *Analyzer) Analyze(_ context.Context, target *scanner.Target) ([]types.Finding, error) {
	if !isTarget(target) {
		return nil, nil
	}

	var top rawSettings
	if err := json.Unmarshal(target.Content, &top); err != nil {
		// Malformed or non-object root: stay silent rather than guess.
		return nil, nil
	}

	lines := strings.Split(string(target.Content), "\n")
	rel := target.RelPath
	if rel == "" {
		rel = target.Path
	}

	var findings []types.Finding
	emit := func(id, desc string, anchor string, rem string) {
		line, text := locate(lines, anchor)
		findings = append(findings, types.Finding{
			RuleID:      id,
			RuleName:    ruleInfo[id].Name,
			Severity:    ruleInfo[id].SeverityLevel(),
			Category:    ruleInfo[id].Category,
			Description: desc,
			FilePath:    rel,
			Line:        line,
			MatchedText: text,
			Remediation: rem,
			Analyzer:    AnalyzerName,
		})
	}

	a.checkHooks(top.Hooks, emit)
	a.checkEnv(top.Env, emit)
	a.checkPermissions(top.Permissions, emit)
	a.checkMCPAutoApprove(top.EnableAllProjectMcpServers, emit)
	a.checkCredentialHelpers(target.Content, emit)

	return findings, nil
}

type emitFunc func(id, desc, anchor, rem string)

// checkHooks flags any hook command that downloads and executes remote
// code, on any event.
func (a *Analyzer) checkHooks(raw json.RawMessage, emit emitFunc) {
	if len(raw) == 0 {
		return
	}
	var events map[string][]hookMatcher
	if err := json.Unmarshal(raw, &events); err != nil {
		return
	}
	for event, matchers := range events {
		for _, m := range matchers {
			for _, h := range m.Hooks {
				cmd := h.Command
				if cmd == "" {
					continue
				}
				if hookFetchExecRe.MatchString(cmd) || evalSubstRe.MatchString(cmd) || fetchThenRunsFile(cmd) {
					emit(RuleHookFetchExec,
						fmt.Sprintf("A %s hook command downloads a remote resource and runs it through an interpreter, which Claude Code executes automatically when a session opens in this repo.", event),
						cmd,
						"Remove the fetch-and-execute hook from .claude/settings.json. Vendor and review any needed setup script instead of piping a network fetch into a shell.")
				}
			}
		}
	}
}

// fetchThenRunsFile reports whether a command downloads a resource to a
// file and then runs that same file through an interpreter, even when
// the two statements are separated by a newline (which the inline
// pipe/chain regex does not cross). The file identity must match, so an
// unrelated fetch and a later unrelated interpreter call do not trip it.
func fetchThenRunsFile(cmd string) bool {
	for _, m := range fetchOutputRe.FindAllStringSubmatch(cmd, -1) {
		file := strings.TrimSpace(m[2])
		if file == "" {
			continue
		}
		runRe, err := regexp.Compile(interpRe + `[^\n]*` + regexp.QuoteMeta(file))
		if err != nil {
			continue
		}
		if runRe.MatchString(cmd) {
			return true
		}
	}
	return false
}

// checkEnv flags an env block that sets a code-execution variable.
func (a *Analyzer) checkEnv(raw json.RawMessage, emit emitFunc) {
	if len(raw) == 0 {
		return
	}
	var env map[string]string
	if err := json.Unmarshal(raw, &env); err != nil {
		return
	}
	for k, v := range env {
		dangerous := envExecVars[k]
		if k == "NODE_OPTIONS" && nodeOptionsExecRe.MatchString(v) {
			dangerous = true
		}
		if dangerous {
			emit(RuleEnvExec,
				fmt.Sprintf("The env block sets %s, which injects code into processes Claude Code spawns in this repo's sessions.", k),
				fmt.Sprintf("%q", k),
				"Remove the code-execution environment variable from the committed settings env block; set runtime flags per developer instead.")
		}
	}
}

// checkPermissions flags bypass mode, weak auto-approve modes, broad
// command allow rules, and secret-read allow rules.
func (a *Analyzer) checkPermissions(raw json.RawMessage, emit emitFunc) {
	if len(raw) == 0 {
		return
	}
	var p permissions
	if err := json.Unmarshal(raw, &p); err != nil {
		return
	}

	switch strings.TrimSpace(p.DefaultMode) {
	case "bypassPermissions":
		emit(RuleBypassPerms,
			"permissions.defaultMode is bypassPermissions, pre-disabling the tool-approval prompt for anyone who clones the repo.",
			"bypassPermissions",
			"Remove defaultMode: bypassPermissions from the committed settings; it is a per-developer local choice.")
	case "acceptEdits", "auto":
		emit(RulePermsWeakMode,
			fmt.Sprintf("permissions.defaultMode is %q, an auto-approving mode shipped as a project default.", p.DefaultMode),
			"defaultMode",
			"Leave defaultMode unset in committed settings so each developer opts into a faster mode locally.")
	}

	for _, rule := range p.Allow {
		if isBroadCommandRule(rule) {
			emit(RuleBroadAllow,
				fmt.Sprintf("permissions.allow pre-approves %q, a blanket or dangerous command the agent can run without asking anyone who clones the repo.", rule),
				rule,
				"Replace the broad allow rule with the narrowest specific commands; never commit a wildcard Bash allow or pre-approve fetch/delete/eval commands.")
		}
		if isSecretReadRule(rule) {
			emit(RuleSecretReadAllow,
				fmt.Sprintf("permissions.allow pre-approves %q, granting the agent silent access to a sensitive path.", rule),
				rule,
				"Remove the secret-path allow rule; credential files should require an explicit prompt or sit in the deny list.")
		}
	}
}

// checkMCPAutoApprove flags enableAllProjectMcpServers: true.
func (a *Analyzer) checkMCPAutoApprove(raw json.RawMessage, emit emitFunc) {
	if len(raw) == 0 {
		return
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err != nil {
		return
	}
	if b {
		emit(RuleMCPAutoApprove,
			"enableAllProjectMcpServers is true, so every MCP server in the repo's .mcp.json loads without a per-server approval prompt.",
			"enableAllProjectMcpServers",
			"Remove enableAllProjectMcpServers: true and approve project MCP servers individually after reviewing each one.")
	}
}

// checkCredentialHelpers flags a helper that runs a repo-relative script
// or a network fetch. The helpers are decoded from the raw content so a
// malformed sibling key does not block them.
func (a *Analyzer) checkCredentialHelpers(content []byte, emit emitFunc) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(content, &top); err != nil {
		return
	}
	for _, key := range credentialHelpers {
		raw, ok := top[key]
		if !ok {
			continue
		}
		var val string
		if err := json.Unmarshal(raw, &val); err != nil {
			continue
		}
		if isRepoRelativeCommand(val) {
			emit(RuleHelperRepoScript,
				fmt.Sprintf("%s runs a repo-shipped script (%q), which executes at session start / credential refresh with access to the material it mints.", key, val),
				fmt.Sprintf("%q", key),
				"Point credential helpers at a trusted developer-installed absolute path, never a repo-relative script or a network fetch.")
		}
	}
}

// isBroadCommandRule reports whether a permission allow rule pre-approves
// a blanket or dangerous command class. Narrow rules (Bash(npm run
// test)) return false.
func isBroadCommandRule(rule string) bool {
	r := strings.TrimSpace(rule)
	// Blanket bash: "Bash", "Bash()", "Bash(*)", "Bash( * )".
	if r == "Bash" || r == "Bash()" {
		return true
	}
	tool, arg, ok := splitRule(r)
	if !ok || tool != "Bash" {
		return false
	}
	arg = strings.TrimSpace(arg)
	if arg == "*" || arg == "" || arg == ":*" {
		return true
	}
	// A dangerous command at the head of the rule, with a wildcard tail.
	// Claude Bash rules wildcard either with a space (Bash(curl *)) or a
	// colon prefix form (Bash(curl:*)); the binary is the first token up
	// to the first space or colon.
	head := strings.ToLower(strings.Fields(arg)[0])
	head = strings.SplitN(head, ":", 2)[0]
	if dangerousBinaries[head] && strings.Contains(arg, "*") {
		return true
	}
	return false
}

var dangerousBinaries = map[string]bool{
	"curl": true, "wget": true, "rm": true, "eval": true, "exec": true,
	"sh": true, "bash": true, "nc": true, "ncat": true, "netcat": true,
	"chmod": true, "sudo": true, "dd": true, "mkfifo": true, "node": true,
}

// isSecretReadRule reports whether an allow rule grants Read/Edit access
// to a sensitive path.
func isSecretReadRule(rule string) bool {
	tool, arg, ok := splitRule(strings.TrimSpace(rule))
	if !ok || (tool != "Read" && tool != "Edit") {
		return false
	}
	a := strings.ToLower(arg)
	for _, marker := range []string{
		".env", "secret", "credential", "/.ssh", "/.aws", ".npmrc",
		"id_rsa", "id_ed25519", ".pem", ".git-credentials", ".netrc",
	} {
		if strings.Contains(a, marker) {
			return true
		}
	}
	return false
}

// scriptInterpreters take a script-path argument, so a bare filename
// after one is a repo-relative script (`bash mint.sh` runs ./mint.sh).
var scriptInterpreters = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ash": true,
	"node": true, "deno": true, "bun": true, "python": true,
	"python3": true, "ruby": true, "perl": true, "php": true,
}

// helperPrefixes are privilege/exec wrappers to skip (not interpreters).
var helperPrefixes = map[string]bool{
	"sudo": true, "command": true, "exec": true, "env": true,
}

// fetchCommands are the binaries whose invocation IS a network fetch.
// Matched on the resolved command's base name so a benign absolute
// helper whose name merely contains "fetch" (e.g.
// /usr/local/bin/fetch-token) is not misread as a fetch.
var fetchCommands = map[string]bool{
	"curl": true, "wget": true, "iwr": true,
	"invoke-webrequest": true, "fetch": true,
}

// isRepoRelativeCommand reports whether a helper command runs code from
// the repository (relative path or bare filename) or performs a network
// fetch, rather than running an absolute / home-anchored system path the
// developer controls. Leading interpreter / wrapper / flag / env-
// assignment tokens are skipped so the test applies to the script the
// command actually runs (e.g. `bash ./.claude/mint.sh`,
// `sudo python scripts/token.py`).
func isRepoRelativeCommand(cmd string) bool {
	c := strings.TrimSpace(cmd)
	if c == "" {
		return false
	}
	fields := strings.Fields(c)
	i := 0
	viaInterp := false
	for i < len(fields) {
		tok := fields[i]
		base := strings.ToLower(filepath.Base(tok))
		if scriptInterpreters[base] {
			viaInterp = true
			i++
			continue
		}
		if helperPrefixes[base] || strings.HasPrefix(tok, "-") || strings.Contains(tok, "=") {
			i++
			continue
		}
		break
	}
	if i >= len(fields) {
		return false
	}
	target := fields[i]
	// A network fetch is the dangerous command itself, not a substring
	// of an absolute binary name.
	if fetchCommands[strings.ToLower(filepath.Base(target))] {
		return true
	}
	// Absolute or home-anchored paths are the developer's own tooling.
	if strings.HasPrefix(target, "/") || strings.HasPrefix(target, "~") ||
		strings.HasPrefix(target, "$HOME") || strings.HasPrefix(target, "${HOME}") {
		return false
	}
	// Explicit repo-relative path, the .claude/ directory anywhere, or a
	// bare relative path with a separator (e.g. "scripts/mint.sh").
	if strings.HasPrefix(target, "./") || strings.HasPrefix(target, "../") ||
		strings.Contains(target, ".claude/") || strings.Contains(target, "/") {
		return true
	}
	// A bare filename run through an interpreter (`bash mint.sh`) is a
	// repo-relative script; a bare token with no interpreter is treated
	// as a system binary on PATH and not flagged.
	return viaInterp
}

// splitRule parses a "Tool(arg)" permission rule into (tool, arg). A
// rule without parentheses (e.g. a bare "Read") returns ok=false.
func splitRule(rule string) (tool, arg string, ok bool) {
	open := strings.IndexByte(rule, '(')
	if open < 0 || !strings.HasSuffix(rule, ")") {
		return "", "", false
	}
	return rule[:open], rule[open+1 : len(rule)-1], true
}

// locate returns the 1-based line number and trimmed text of the first
// line containing anchor, or (0, anchor) when not found.
func locate(lines []string, anchor string) (int, string) {
	for i, ln := range lines {
		if strings.Contains(ln, anchor) {
			return i + 1, strings.TrimSpace(ln)
		}
	}
	return 0, anchor
}

// isTarget matches only a Claude Code settings file under a .claude/
// directory (settings.json or settings.local.json).
func isTarget(t *scanner.Target) bool {
	if t == nil {
		return false
	}
	for _, p := range []string{t.RelPath, t.Path} {
		if p == "" {
			continue
		}
		s := filepath.ToSlash(p)
		for _, name := range []string{"settings.json", "settings.local.json"} {
			// Require a real ".claude" path segment (repo root
			// ".claude/<name>" or "/.claude/<name>" anywhere), not a
			// directory that merely ends in ".claude" such as
			// "fixtures/not.claude/<name>".
			if s == ".claude/"+name || strings.HasSuffix(s, "/.claude/"+name) {
				return true
			}
		}
	}
	return false
}
