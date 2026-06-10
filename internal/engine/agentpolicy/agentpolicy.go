// Package agentpolicy is a small, auditable analyzer for AI-agent host
// configuration posture. Its first supported surface is Claude Code
// project settings: it reads .claude/settings.json (and the local
// .claude/settings.local.json) and reports values that are risky to
// inherit from a repository -- hooks that download and run remote code,
// environment variables that inject code into spawned processes, a
// bypass-oriented permission default, auto-approval of project MCP
// servers, allow rules that pre-approve dangerous commands or secret
// reads, and credential helpers that run repo-shipped scripts.
//
// Threat model (verified against current Claude Code docs): the
// project-level .claude/settings.json can be committed with a repo and
// is applied for anyone who opens it, and after the one-time
// workspace-trust prompt its hooks and helpers run automatically (a
// SessionStart hook fires on session open). Project settings cannot
// silently grant the strongest modes -- Claude Code keeps workspace
// trust, network approval, and suspicious-command checks, and ignores a
// project-supplied "auto" mode -- but they can weaken or preconfigure
// approval behavior and run code. So the question this analyzer asks is
// not "did the developer configure something" but "is this value risky
// to inherit from a repository." (.claude/settings.local.json is local,
// usually gitignored posture, not repo-supplied; it is scanned too, but
// the repo-shipped threat framing applies to settings.json.)
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
//
// Scope boundary: hook command and credential-helper detection works on
// common shell shapes with bounded regexes; it is deliberately NOT a
// shell parser. It catches the unambiguous, high-frequency forms (a
// fetch piped or command-substituted into an interpreter at a command
// position; an interpreter running a repo-relative or fetched script)
// and stays silent on cross-statement dataflow, deeply obfuscated
// indirection, and other constructed strings -- under-report before
// false-positive. Such lines are still covered by the pattern engine's
// download-and-execute rules; agent-policy adds the agent-config framing.
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
	// (`curl … | sh`): a form where the downloaded bytes unambiguously
	// become the interpreter's input. An optional wrapper between the
	// pipe and the interpreter is allowed (sudo / command / exec /
	// env VAR=…, or an absolute/relative path such as /bin/bash), so
	// `curl … | sudo sh` is covered.
	// The fetch must be at a COMMAND position (start of command or after
	// a shell separator), so a `curl` that is an argument to another
	// command (`printf 'curl ...' | bash`, `echo curl | bash`) is not
	// read as the pipeline producer. The span up to the pipe excludes
	// shell separators (; & |) and newlines, so the fetch and the
	// pipe-to-interpreter are the SAME segment -- `curl health; echo x |
	// sh` does not match.
	hookFetchExecRe = regexp.MustCompile(`(?i)(?:^|[;&|(\n])\s*(?:sudo\s+|command\s+|exec\s+|env\s+(?:\S+=\S+\s+)*|[~./][^\s|;&]*/)*(curl|wget|iwr|invoke-webrequest|fetch)\b[^\n;&|]*?\|\s*(?:sudo\s+|command\s+|exec\s+|env\s+(?:\S+=\S+\s+)*|[~./][^\s|;&]*/)*(sh|bash|zsh|dash|ash|node|deno|bun|python3?|ruby|perl|php|iex|invoke-expression)\b`)
	// evalSubstRe catches `eval "$(curl ...)"`, `exec $(wget ...)`, and
	// `sh -c "$(curl ...)"`: an interpreter running the fetched bytes via
	// command substitution.
	//
	// Scope boundary (deliberate, under-report before false-positive):
	// only the pipe and command-substitution forms are detected, because
	// in both the fetched bytes provably reach the interpreter. The
	// "download to a temp file, then run that file in a separate
	// statement" form (`curl -o /tmp/a …; bash /tmp/a`) is NOT matched
	// here -- telling it apart from a benign hook that fetches a health
	// check and then runs an unrelated local script requires modeling
	// shell command segments, redirection, curl's stdout-vs-file
	// semantics, and execution order, which a regex cannot do without
	// false positives. Such a line is still flagged by the pattern
	// engine's download-and-execute rules; agent-policy adds the
	// agent-config framing for the unambiguous forms.
	// The span between the eval keyword and the $(fetch) excludes shell
	// separators so `eval $X; echo $(curl health)` does not match (the
	// fetched bytes are echoed, not evaluated).
	evalSubstRe = regexp.MustCompile(`(?i)\b(eval|exec|source|(?:sh|bash|zsh|dash|ash|node|deno|bun|python3?|ruby|perl|php)\s+-c)\b[^\n;&]*\$\(\s*(curl|wget|iwr|fetch)\b`)
)

// envExecVars are environment variables whose presence in a committed
// settings file injects code into spawned processes. NODE_OPTIONS is
// handled separately because its safe forms (e.g. --max-old-space-size)
// are common; only the code-loading flags trip it.
// envExecVars hold values that inject code on their own. "ENV" (sh's
// interactive-startup file) is deliberately excluded: it is overwhelmingly
// used as a generic application flag (ENV=production), so flagging it HIGH
// would false-positive and fail --ci on benign configs; BASH_ENV covers
// the unambiguous startup-file vector.
var envExecVars = map[string]bool{
	"LD_PRELOAD":            true,
	"LD_LIBRARY_PATH":       true,
	"DYLD_INSERT_LIBRARIES": true,
	"DYLD_LIBRARY_PATH":     true,
	"PYTHONSTARTUP":         true,
	"PYTHONPATH":            true,
	"BASH_ENV":              true,
	"GIT_SSH_COMMAND":       true,
	"RUBYOPT":               true,
	"PERL5LIB":              true,
}

// nodeOptionsExecRe matches the NODE_OPTIONS flags that load and run
// code (as opposed to tuning the runtime), including Node's short
// aliases (-r for --require, -i is interactive so excluded).
var nodeOptionsExecRe = regexp.MustCompile(`(?i)(--(require|import|loader|experimental-loader)\b|(?:^|\s)-r(?:\s|=))`)

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
			// High, fixed confidence: these are deterministic structural
			// matches on a known config schema, not heuristics. It also
			// lets the finding hold its own in cross-rule dedup -- a hook
			// like `curl | sh` also trips the pattern matcher's
			// download-and-execute rule on the same line, and without a
			// confidence the agent-config framing would always be dropped.
			Confidence: 0.9,
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
				if hookFetchExecRe.MatchString(cmd) || evalSubstRe.MatchString(cmd) {
					emit(RuleHookFetchExec,
						fmt.Sprintf("A %s hook command downloads a remote resource and runs it through an interpreter, which Claude Code executes automatically when a session opens in this repo.", event),
						cmd,
						"Remove the fetch-and-execute hook from .claude/settings.json. Vendor and review any needed setup script instead of piping a network fetch into a shell.")
				}
			}
		}
	}
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
		// An empty value clears the variable -- a hardening action, not an
		// injection. Flagging it would false-positive (and fail --ci) on a
		// config that explicitly clears an inherited dangerous variable.
		if strings.TrimSpace(v) == "" {
			continue
		}
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
			"permissions.defaultMode is bypassPermissions, a bypass-oriented default that weakens the tool-approval prompt for the project after workspace trust.",
			"bypassPermissions",
			"Remove defaultMode: bypassPermissions from the project settings; auto-approval is a per-developer local choice, not a project default.")
	case "acceptEdits":
		// Only acceptEdits: Claude Code IGNORES defaultMode "auto" when it
		// comes from project/local settings, so a repo cannot grant itself
		// auto mode and flagging it would be a false positive.
		emit(RulePermsWeakMode,
			"permissions.defaultMode is \"acceptEdits\", an edit-auto-approving mode set as a project default.",
			"defaultMode",
			"Leave defaultMode unset in project settings so each developer opts into a faster mode locally.")
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
	// to the first space or colon. An absolute path (Bash(/bin/rm *)) is
	// reduced to its base name so it still matches the dangerous list.
	head := strings.ToLower(strings.Fields(arg)[0])
	head = strings.SplitN(head, ":", 2)[0]
	head = filepath.Base(strings.Trim(head, `'"`))
	if dangerousBinaries[head] && strings.Contains(arg, "*") {
		return true
	}
	return false
}

var dangerousBinaries = map[string]bool{
	"curl": true, "wget": true, "rm": true, "eval": true, "exec": true,
	"nc": true, "ncat": true, "netcat": true,
	"chmod": true, "sudo": true, "dd": true, "mkfifo": true,
	// Interpreters: a wildcard allow (Bash(python *)) lets the agent run
	// arbitrary code in that language without approval.
	"sh": true, "bash": true, "zsh": true, "dash": true, "ash": true,
	"node": true, "deno": true, "bun": true, "python": true, "python3": true,
	"ruby": true, "perl": true, "php": true, "pwsh": true, "powershell": true,
}

// isSecretReadRule reports whether an allow rule grants Read/Edit access
// to a sensitive path.
func isSecretReadRule(rule string) bool {
	tool, arg, ok := splitRule(strings.TrimSpace(rule))
	if !ok || (tool != "Read" && tool != "Edit") {
		return false
	}
	a := strings.ToLower(arg)
	// A committed .env template/placeholder is not a secret; exempt the
	// well-known sample suffixes so a normal Read(./.env.example) rule is
	// not flagged.
	for _, tmpl := range []string{".env.example", ".env.sample", ".env.template", ".env.dist", ".env.defaults"} {
		if strings.Contains(a, tmpl) {
			return false
		}
	}
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
	"pwsh": true, "powershell": true,
}

// helperPrefixes are privilege/exec wrappers to skip (not interpreters).
var helperPrefixes = map[string]bool{
	"sudo": true, "command": true, "exec": true, "env": true,
}

// envAssignRe matches a leading KEY=value environment assignment.
var envAssignRe = regexp.MustCompile(`^[A-Za-z_]\w*=`)

// cFlagRe matches an interpreter command-string flag (bash -c, sh -lc,
// pwsh -Command), whose argument is a command, not a script path.
var cFlagRe = regexp.MustCompile(`(?i)(^|\s)-(l?i?c|ic)\b|(?i)(^|\s)(-command|--command)\b`)

// fetchWordRe matches a network-fetch command as a word.
var fetchWordRe = regexp.MustCompile(`(?i)\b(curl|wget|iwr|invoke-webrequest|fetch)\b`)

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
		// A KEY=value env assignment is only skippable BEFORE the
		// command/interpreter. After an interpreter, the next token is
		// the script argument, even if it contains "=" (e.g.
		// ./.claude/mint=prod.sh).
		if helperPrefixes[base] || strings.HasPrefix(tok, "-") ||
			(!viaInterp && envAssignRe.MatchString(tok)) {
			i++
			continue
		}
		break
	}
	// `interp -c "<command string>"` runs a command STRING, not a script
	// path: the argument is `op read ...` or `$(curl ...)`, not a file.
	// Only when the command is actually an interpreter -- so a non-shell
	// binary using -c for its own option (`/usr/local/bin/mint -c
	// ./mint.yml`) is NOT misread. Classify the string by content (a
	// fetch or an explicit repo-relative path), not by its first word,
	// which is often a PATH tool like `op` or `vault`.
	if viaInterp && cFlagRe.MatchString(c) {
		return fetchWordRe.MatchString(c) ||
			strings.Contains(c, "./") || strings.Contains(c, "../") ||
			strings.Contains(c, ".claude/")
	}
	if i >= len(fields) {
		return false
	}
	// Strip shell quotes so a quoted absolute path (`bash
	// "/usr/local/bin/mint.sh"`) is classified by its real prefix.
	target := strings.Trim(fields[i], `'"`)
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

// locate returns the 1-based line number for anchor and the anchor
// itself as MatchedText. MatchedText is the specific dangerous token,
// NOT the whole source line, so a minified settings.json whose line also
// holds an unrelated secret does not echo that secret into output. The
// JSON-escaped form of the anchor is also searched, so a hook command
// containing escaped quotes (eval "$(curl ...)") matches the raw
// `\"`-escaped line. When the anchor cannot be located (deeper JSON
// escaping), the line falls back to 1 -- never 0 -- to keep the
// 1-indexed finding contract that inline-ignore relies on.
func locate(lines []string, anchor string) (int, string) {
	escaped := strings.ReplaceAll(anchor, `"`, `\"`)
	for i, ln := range lines {
		if strings.Contains(ln, anchor) || (escaped != anchor && strings.Contains(ln, escaped)) {
			return i + 1, anchor
		}
	}
	return 1, anchor
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
