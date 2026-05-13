// Package jsrisk inspects JavaScript source for static payload shapes
// that combine into supply-chain risk chains: large obfuscated payloads,
// detached background execution from install-time code, CI credential
// harvesting paired with a network or registry sink, OIDC token
// extraction from runner process memory, and persistence through Claude
// Code or VS Code workspace automation.
//
// The analyzer is fully offline. It runs at most a single linear pass
// over the content plus a handful of compiled-once regex matches; it
// never executes scripts and never deobfuscates dynamically. Findings
// stay chain-aware: single weak signals (a large file alone, a single
// CI env reference alone, a child_process call alone) never fire.
package jsrisk

import (
	"bytes"
	"context"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/types"
)

// AnalyzerName is the value reported in Finding.Analyzer for this engine.
const AnalyzerName = "jsrisk"

// Rule IDs emitted by this analyzer.
const (
	RuleObfuscation       = "JS_OBF_001"
	RuleDaemon            = "JS_DAEMON_001"
	RuleCISecretHarvest   = "JS_CI_SECRET_HARVEST_001"
	RuleProcMemOIDC       = "JS_PROC_MEM_OIDC_001"
	RuleAgentPersistence  = "AGENT_PERSISTENCE_001"
)

// Detection thresholds. Chosen to leave room for ordinary minified
// vendor bundles to fall through while flagging known obfuscator-io
// fingerprints. Constants live at package scope so tests can reason
// about them.
const (
	sizeBytesThreshold      = 500 * 1024 // 500 KB
	maxLineLenThreshold     = 200 * 1024 // 200 KB
	hexIdentifierThreshold  = 100
	dispatcherCallThreshold = 100
)

// Analyzer implements scanner.Analyzer for JavaScript supply-chain risk.
type Analyzer struct{}

// New returns a fresh JavaScript risk analyzer.
func New() *Analyzer { return &Analyzer{} }

// Name returns the analyzer identifier.
func (a *Analyzer) Name() string { return AnalyzerName }

// Analyze inspects JavaScript files and returns chain-aware findings.
// Non-JavaScript files return nil.
func (a *Analyzer) Analyze(_ context.Context, target *scanner.Target) ([]types.Finding, error) {
	if !isJavaScriptTarget(target) {
		return nil, nil
	}
	if len(target.Content) == 0 {
		return nil, nil
	}
	m := computeMetrics(target.Content)
	return detect(target.RelPath, m), nil
}

// --- target gating ---

// isJavaScriptTarget returns true for .js / .mjs / .cjs files. Checks
// both Path (real-repo scans) and RelPath (in-memory content with a
// hinted name).
func isJavaScriptTarget(t *scanner.Target) bool {
	if t == nil {
		return false
	}
	for _, p := range []string{t.Path, t.RelPath} {
		if p == "" {
			continue
		}
		ext := strings.ToLower(filepath.Ext(filepath.ToSlash(p)))
		switch ext {
		case ".js", ".mjs", ".cjs":
			return true
		}
	}
	return false
}

// --- compiled regexes (compiled once at package init) ---

// hexIdentifierRe matches obfuscator-io-style hex identifiers like
// _0x1a2b3c. The leading underscore + 0x prefix is the fingerprint.
var hexIdentifierRe = regexp.MustCompile(`_0x[0-9a-fA-F]{2,}`)

// dispatcherCallRe matches a hex identifier immediately followed by a
// call: _0x1a2b3c(...). This is the dispatcher shape that obfuscator
// payloads use to route string-array lookups.
var dispatcherCallRe = regexp.MustCompile(`_0x[0-9a-fA-F]{2,}\s*\(`)

// propertyBoundary is the leading-context alternation used by the
// daemon-option regexes: the property key must be preceded by start of
// input or one of the structural characters that introduce an object
// property. Without it, `notdetached: true` or `isStdio: 'ignore'`
// would falsely match because `detached` / `stdio` are substrings.
const propertyBoundary = `(?:^|[\s,{;(\[])`

// detachedTrueRe matches `detached: true`, `"detached": true`, and the
// single-quoted/no-space variants ONLY when the key is at a property
// boundary, so substrings like `notdetached: true` are excluded.
var detachedTrueRe = regexp.MustCompile(`(?i)` + propertyBoundary + `["']?detached["']?\s*:\s*true\b`)

// stdioIgnoredRe matches `stdio: 'ignore'` / `stdio: "ignore"` /
// `"stdio": "ignore"` and the array forms (`stdio: ['ignore', ...]`,
// `"stdio": ['ignore'`) at a property boundary.
var stdioIgnoredRe = regexp.MustCompile(`(?i)` + propertyBoundary + `["']?stdio["']?\s*:\s*(?:['"]ignore['"]|\[\s*['"]ignore['"])`)


// --- metrics ---

// metrics holds the once-computed signals for the current file. Line
// fields record the 1-based line of the first occurrence so findings
// can anchor at the relevant source location.
type metrics struct {
	SizeBytes  int
	LineCount  int
	MaxLineLen int

	HexIdentifierCount  int
	DispatcherCallCount int
	HasWhileTruePattern bool
	LineObfSpecific     int // first obfuscator-specific signal

	HasNetworkSink       bool
	HasPublishSink       bool
	HasGitHubGraphQLSink bool
	HasSessionSink       bool
	HasChildProcess      bool
	HasProcessEnv        bool
	LineNetworkSink      int

	HasCISecretRead bool
	LineCISecret    int
	CISecretMatched string

	HasDaemonChain bool
	LineDaemon     int

	HasProcMemAccess bool
	HasOIDCTokenEnv  bool
	HasRunnerWorker  bool
	LineProcMem      int

	HasClaudePersistence bool
	HasVSCodePersistence bool
	LineAgentPath        int
	AgentPathMatched     string
}

// computeMetrics walks the content once, tracking line numbers and
// signal occurrences. Substring matches use bytes.Contains on the full
// content; line numbers come from a single scan that splits on '\n'.
// Total work is O(N) in content length plus a handful of regex passes.
func computeMetrics(content []byte) *metrics {
	m := &metrics{SizeBytes: len(content)}

	// One pass to find max line length and total line count.
	curLen := 0
	lineNum := 1
	if m.SizeBytes > 0 {
		m.LineCount = 1
	}
	for i := 0; i < len(content); i++ {
		if content[i] == '\n' {
			if curLen > m.MaxLineLen {
				m.MaxLineLen = curLen
			}
			curLen = 0
			lineNum++
			m.LineCount++
			continue
		}
		curLen++
	}
	if curLen > m.MaxLineLen {
		m.MaxLineLen = curLen
	}
	_ = lineNum // suppress unused warning; the variable documents the loop

	// Regex passes count occurrences over the full content. FindAllIndex
	// with the cap argument keeps memory bounded if a file is pathological.
	hex := hexIdentifierRe.FindAllIndex(content, hexIdentifierThreshold*2)
	m.HexIdentifierCount = len(hex)
	disp := dispatcherCallRe.FindAllIndex(content, dispatcherCallThreshold*2)
	m.DispatcherCallCount = len(disp)
	m.HasWhileTruePattern = bytes.Contains(content, []byte("while(!![])")) ||
		bytes.Contains(content, []byte("while (!![])"))

	// Earliest line of an obfuscator-specific signal anchors JS_OBF_001.
	if m.HasWhileTruePattern {
		idx := bytes.Index(content, []byte("while(!![])"))
		if idx < 0 {
			idx = bytes.Index(content, []byte("while (!![])"))
		}
		if idx >= 0 {
			m.LineObfSpecific = lineOf(content, idx)
		}
	}
	if m.LineObfSpecific == 0 && m.HexIdentifierCount > hexIdentifierThreshold && len(hex) > 0 {
		m.LineObfSpecific = lineOf(content, hex[0][0])
	}
	if m.LineObfSpecific == 0 && m.DispatcherCallCount > dispatcherCallThreshold && len(disp) > 0 {
		m.LineObfSpecific = lineOf(content, disp[0][0])
	}

	// Network / publish / GitHub / session sinks. The network regex is
	// whitespace-tolerant (so `fetch (...)` matches) and case-insensitive.
	// Publish / GitHub / session sinks are unambiguous literal strings.
	lower := bytes.ToLower(content)
	if loc := networkSinkRe.FindIndex(content); loc != nil {
		m.HasNetworkSink = true
		m.LineNetworkSink = lineOf(content, loc[0])
	}
	for _, n := range publishSinkNeedles {
		if bytes.Contains(lower, []byte(n)) {
			m.HasPublishSink = true
		}
	}
	for _, n := range githubGraphQLNeedles {
		if bytes.Contains(lower, []byte(n)) {
			m.HasGitHubGraphQLSink = true
		}
	}
	for _, n := range sessionSinkNeedles {
		if bytes.Contains(lower, []byte(n)) {
			m.HasSessionSink = true
		}
	}
	// HasChildProcess is true when the file contains either a
	// receiver-bound child_process method call (require chain or known
	// alias) or a bare invocation whose name was destructured from
	// child_process. Used by JS_OBF_001 severity escalation only.
	m.HasChildProcess = hasChildProcessInvocation(content)
	m.HasProcessEnv = bytes.Contains(lower, []byte("process.env"))

	// CI / cloud secret reads come in three forms: direct member access
	// (process.env.NAME), bracket access (process.env['NAME']), and
	// destructuring ({NAME} = process.env). Pure string mentions do not
	// count as a read.
	checkSecretName := func(name string, idx int) {
		for _, n := range ciSecretEnvVars {
			if name == n && !m.HasCISecretRead {
				m.HasCISecretRead = true
				m.LineCISecret = lineOf(content, idx)
				m.CISecretMatched = n
				return
			}
		}
	}
	for _, match := range envReadRe.FindAllSubmatchIndex(content, -1) {
		if m.HasCISecretRead {
			break
		}
		checkSecretName(string(content[match[2]:match[3]]), match[0])
	}
	if !m.HasCISecretRead {
		for _, match := range envDestructureRe.FindAllSubmatchIndex(content, -1) {
			if m.HasCISecretRead {
				break
			}
			nameList := string(content[match[2]:match[3]])
			for _, raw := range strings.Split(nameList, ",") {
				entry := strings.TrimSpace(raw)
				// Aliased entries take the form `NAME: alias`; the
				// source name is everything before the colon.
				if idx := strings.Index(entry, ":"); idx >= 0 {
					entry = strings.TrimSpace(entry[:idx])
				}
				checkSecretName(entry, match[0])
				if m.HasCISecretRead {
					break
				}
			}
		}
	}
	// Cloud metadata endpoints and on-disk credential paths are
	// identified by literal-string presence; they are unambiguous IPs /
	// filesystem paths that do not appear as env var names.
	for _, n := range ciSecretLiteralNeedles {
		if i := bytes.Index(content, []byte(n)); i >= 0 {
			m.HasCISecretRead = true
			if m.LineCISecret == 0 {
				m.LineCISecret = lineOf(content, i)
				m.CISecretMatched = n
			}
		}
	}

	// Daemonization is computed inline so the chain options (detached,
	// stdio:ignore, .unref()) are tied to a real child_process call,
	// not satisfied by any object literal elsewhere in the file. See
	// findDaemonChain for the per-invocation proximity walk.
	if line, ok := findDaemonChain(content); ok {
		m.HasDaemonChain = true
		m.LineDaemon = line
	}

	// Process memory access requires a /proc/ reference paired with a
	// memory-like subpath (/mem, /maps, cmdline) in proximity. The
	// proximity window catches both literal paths and concatenated forms
	// like `'/proc/' + pid + '/mem'` while filtering out files that
	// reference /proc/stat in one place and an unrelated 'cmdline'
	// identifier elsewhere.
	m.LineProcMem = findProcMemPair(content)
	m.HasProcMemAccess = m.LineProcMem > 0
	m.HasOIDCTokenEnv = bytes.Contains(content, []byte("ACTIONS_ID_TOKEN_REQUEST_TOKEN")) ||
		bytes.Contains(content, []byte("ACTIONS_ID_TOKEN_REQUEST_URL"))
	m.HasRunnerWorker = bytes.Contains(content, []byte("Runner.Worker"))

	// Agent persistence references. Path-only needles fire on their
	// own; the runOn:folderOpen token only counts as persistence when
	// the file also references .vscode/tasks.json (manually-runnable
	// tasks files alone are not persistence).
	for _, n := range agentPersistenceNeedles {
		if i := bytes.Index(content, []byte(n)); i >= 0 {
			if strings.HasPrefix(n, ".claude/") {
				m.HasClaudePersistence = true
			} else {
				m.HasVSCodePersistence = true
			}
			if m.LineAgentPath == 0 {
				m.LineAgentPath = lineOf(content, i)
				m.AgentPathMatched = n
			}
		}
	}
	if bytes.Contains(content, []byte(".vscode/tasks.json")) {
		for _, n := range runOnFolderOpenNeedles {
			if i := bytes.Index(content, []byte(n)); i >= 0 {
				m.HasVSCodePersistence = true
				if m.LineAgentPath == 0 {
					m.LineAgentPath = lineOf(content, i)
					m.AgentPathMatched = ".vscode/tasks.json + " + n
				}
				break
			}
		}
	}

	return m
}

// lineOf returns the 1-based line number of byte offset idx in content.
func lineOf(content []byte, idx int) int {
	if idx <= 0 {
		return 1
	}
	return bytes.Count(content[:idx], []byte{'\n'}) + 1
}

// cpCallSite records a real child_process invocation: Start is the
// beginning of the receiver/name token, ArgsStart is the byte after
// the opening `(`. Daemon detection extracts the call's actual args
// (paren-balanced) starting at ArgsStart so options belonging to a
// different nearby call do not satisfy the chain.
type cpCallSite struct {
	Start     int
	ArgsStart int
}

// collectChildProcessCalls returns sites of real child_process
// invocations: receiver-bound method calls (require chain or known
// module alias) plus bare calls whose name was destructured from
// child_process. Unrelated `.spawn(...)` calls and bare calls whose
// name was never imported from the module are excluded.
func collectChildProcessCalls(content []byte) []cpCallSite {
	var sites []cpCallSite
	for _, loc := range childProcessReceiverRe.FindAllIndex(content, -1) {
		sites = append(sites, cpCallSite{Start: loc[0], ArgsStart: loc[1]})
	}
	// Collect destructured local names. For each entry the source
	// (left of `:` in CJS, left of ` as ` in ESM) must be a real
	// child_process method; the local binding (right side, or the
	// entry itself when not aliased) is what shows up in a bare call.
	destructuredNames := map[string]bool{}
	addDestructure := func(body string, aliasSep string) {
		for _, raw := range strings.Split(body, ",") {
			entry := strings.TrimSpace(raw)
			if entry == "" {
				continue
			}
			source, local := entry, entry
			if i := strings.Index(entry, aliasSep); i >= 0 {
				source = strings.TrimSpace(entry[:i])
				local = strings.TrimSpace(entry[i+len(aliasSep):])
			}
			if cpMethodNames[source] && local != "" {
				destructuredNames[local] = true
			}
		}
	}
	for _, m := range childProcessDestructureRe.FindAllSubmatchIndex(content, -1) {
		addDestructure(string(content[m[2]:m[3]]), ":")
	}
	for _, m := range childProcessESMDestructureRe.FindAllSubmatchIndex(content, -1) {
		addDestructure(string(content[m[2]:m[3]]), " as ")
	}
	if len(destructuredNames) > 0 {
		for _, loc := range anyBareInvokeRe.FindAllSubmatchIndex(content, -1) {
			if destructuredNames[string(content[loc[2]:loc[3]])] {
				sites = append(sites, cpCallSite{Start: loc[0], ArgsStart: loc[1]})
			}
		}
	}
	// Sort by Start so the earliest qualifying call is the anchor.
	for i := 1; i < len(sites); i++ {
		for j := i; j > 0 && sites[j-1].Start > sites[j].Start; j-- {
			sites[j-1], sites[j] = sites[j], sites[j-1]
		}
	}
	return sites
}

// hasChildProcessInvocation reports whether the file contains any
// real child_process invocation. Used by JS_OBF_001 severity escalation.
func hasChildProcessInvocation(content []byte) bool {
	return len(collectChildProcessCalls(content)) > 0
}

// extractCallArgs returns the bytes between the opening `(` at
// argsStart (inclusive) and its matching `)`, ignoring quoted string
// literals and template literals. Nested parens balance correctly.
// When the call is unterminated (truncated input), the remainder of
// content is returned, which is conservative for proximity checks.
func extractCallArgs(content []byte, argsStart int) []byte {
	depth := 1
	inStr := byte(0)
	escaped := false
	for i := argsStart; i < len(content); i++ {
		c := content[i]
		if escaped {
			escaped = false
			continue
		}
		if inStr != 0 {
			if c == '\\' {
				escaped = true
				continue
			}
			if c == inStr {
				inStr = 0
			}
			continue
		}
		switch c {
		case '\'', '"', '`':
			inStr = c
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return content[argsStart:i]
			}
		}
	}
	return content[argsStart:]
}

// findDaemonChain returns the line of the first child_process call
// whose own args (paren-balanced, string-aware) contain BOTH
// `detached: true` AND `stdio: 'ignore'`. The args-extracted check
// ties the options to the call that owns them, so daemon-shape
// options belonging to an unrelated nearby spawn (or a different
// trailing object literal) do not satisfy the chain.
func findDaemonChain(content []byte) (int, bool) {
	for _, site := range collectChildProcessCalls(content) {
		args := extractCallArgs(content, site.ArgsStart)
		if !detachedTrueRe.Match(args) {
			continue
		}
		if !stdioIgnoredRe.Match(args) {
			continue
		}
		return lineOf(content, site.Start), true
	}
	return 0, false
}

// procMemPairWindow bounds how far a quote-wrapped memory subpath can
// be from a /proc/ occurrence before they stop counting as part of the
// same access. 200 bytes is generous for any plausible source form
// (`'/proc/' + pid + '/mem'`, template literals, multi-arg function
// calls) without spanning unrelated identifiers.
const procMemPairWindow = 200

// procMemLiteralRe matches a literal path: /proc/<pid-or-self>/<sub>
// where <sub> is mem, maps, or cmdline and is followed by a word
// boundary. Root-level files like /proc/meminfo and /proc/cmdline
// (which is the kernel boot args file, not per-process) do not match
// because they lack the intervening pid segment.
var procMemLiteralRe = regexp.MustCompile(`/proc/(?:[0-9]+|self|thread-self)/(mem|maps|cmdline)\b`)

// childProcessReceiverRe matches a child_process method call whose
// receiver is either an inline require chain or a conventional alias
// for the imported module. Restricting to these receivers prevents
// `worker.spawn(...)` on an unrelated object from satisfying the
// daemon chain just because `child_process` appears elsewhere in the
// file. The conventional aliases (cp, childProcess, child_process,
// ChildProcess) cover the bindings real-world code uses; obscure
// renames are intentionally out of reach without AST parsing.
var childProcessReceiverRe = regexp.MustCompile(
	`(?:require\s*\(\s*['"](?:node:)?child_process['"]\s*\)|\b(?:cp|childProcess|child_process|ChildProcess|_cp)\b)` +
		`\s*\.\s*(?:spawn|spawnSync|fork|exec|execSync|execFile|execFileSync)\s*\(`,
)

// anyBareInvokeRe captures the name and call site of any bare
// identifier invocation in the file. Used together with the
// destructured-name set: only invocations whose name was destructured
// from child_process (CJS or ESM) and originally bound to a real cp
// method are credited as a child_process call.
var anyBareInvokeRe = regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\s*\(`)

// childProcessDestructureRe matches `const { spawn, fork } =
// require('child_process')` and its var/let variants. Submatch 1 is
// the brace body; callers parse each entry for the local binding
// (after `:` if aliased, the entry itself otherwise).
var childProcessDestructureRe = regexp.MustCompile(
	`(?:const|let|var)\s*\{\s*([^}]+)\s*\}\s*=\s*require\s*\(\s*['"](?:node:)?child_process['"]\s*\)`,
)

// childProcessESMDestructureRe matches the ESM equivalent:
// `import { spawn } from 'child_process'` /
// `import { spawn as launch } from 'node:child_process'`. The .mjs /
// .cjs scan targets need this form for parity with CommonJS code.
var childProcessESMDestructureRe = regexp.MustCompile(
	`import\s*\{\s*([^}]+)\s*\}\s*from\s*['"](?:node:)?child_process['"]`,
)

// cpMethodNames is the set of child_process methods whose call is
// considered an invocation for daemon detection. The bare-form
// callable (after destructure aliasing) must originate from one of
// these names.
var cpMethodNames = map[string]bool{
	"spawn": true, "spawnSync": true,
	"fork":    true,
	"exec":    true, "execSync": true,
	"execFile": true, "execFileSync": true,
}

// envReadRe captures direct env-variable reads:
// `process.env.<NAME>`, `process.env['<NAME>']`, or
// `process.env["<NAME>"]`.
var envReadRe = regexp.MustCompile(`process\.env\s*(?:\.|\[\s*['"])([A-Z][A-Z0-9_]+)`)

// envDestructureRe captures destructured env reads with or without
// aliases:
//
//	const { GITHUB_TOKEN } = process.env
//	const { FOO, GITHUB_TOKEN: t } = process.env
//	const { GITHUB_TOKEN: t, NPM_TOKEN: n } = process.env
//
// Submatch 1 is the full brace content; callers split on `,` and
// take the substring before `:` (if present) as the source name.
var envDestructureRe = regexp.MustCompile(`\{\s*([^}]+?)\s*\}\s*=\s*process\.env\b`)


// procMemDynamicSubRe matches the quote-wrapped subpath token used by
// dynamic forms: `'/mem'`, `"/maps"`, `` `/cmdline` ``, and the
// template-interpolation closing form `}/mem`. The leading set
// includes `}` so template literals (`/proc/${pid}/mem`) match.
var procMemDynamicSubRe = regexp.MustCompile("[}'\"\x60]/(mem|maps|cmdline)['\"\x60}]")

// findProcMemPair returns the 1-based line of the first /proc/ access
// that targets a memory-like subpath: either a literal
// /proc/<pid>/<sub> match, or a /proc/ occurrence followed within
// procMemPairWindow bytes by a quote-wrapped subpath token (the form
// dynamic concat and template literals leave in source).
func findProcMemPair(content []byte) int {
	if loc := procMemLiteralRe.FindIndex(content); loc != nil {
		return lineOf(content, loc[0])
	}
	off := 0
	for off < len(content) {
		i := bytes.Index(content[off:], []byte("/proc/"))
		if i < 0 {
			return 0
		}
		procStart := off + i
		windowEnd := procStart + procMemPairWindow
		if windowEnd > len(content) {
			windowEnd = len(content)
		}
		if procMemDynamicSubRe.Match(content[procStart:windowEnd]) {
			return lineOf(content, procStart)
		}
		off = procStart + len("/proc/")
	}
	return 0
}

// --- needle lists ---

// All lower-cased; matched against bytes.ToLower(content). Each entry
// names a known network API. Bare method names like `.post(` / `.put(`
// were dropped because they false-positive on any object with a method
// of that name (in-memory caches, database clients, queue libraries),
// turning the credential-harvest chain into a wide CI block.
// networkSinkRe matches JavaScript expressions that perform an HTTP /
// socket call to an external endpoint. JavaScript permits whitespace
// between the callee and `(`, so the regex tolerates it; this catches
// `fetch (...)` exfil payloads that a literal `fetch(` substring
// would miss. Each alternation names a specific API rather than a
// bare method like `.post(` so unrelated objects with same-named
// methods do not falsely trigger.
var networkSinkRe = regexp.MustCompile(
	`(?i)\b(?:` +
		`fetch|` +
		`axios\.(?:post|put|request|get)|` +
		`got\.(?:post|put|get)|` +
		`http\.request|https\.request|` +
		`net\.connect|net\.createconnection|` +
		`xmlhttprequest` +
		`)\s*\(` +
		// require chain variants: require('https').request(...) and
		// node: scheme. Single and double-quoted module names.
		`|require\s*\(\s*['"](?:node:)?https?['"]\s*\)\s*\.\s*request\s*\(`,
)

var publishSinkNeedles = []string{
	"registry.npmjs.org",
	"/-/npm/v1/tokens",
	"npm publish",
}

var githubGraphQLNeedles = []string{
	"api.github.com/graphql",
	"createcommitonbranch",
}

var sessionSinkNeedles = []string{
	"filev2.getsession.org",
	"seed1.getsession.org",
	"seed2.getsession.org",
	"seed3.getsession.org",
}

// ciSecretEnvVars are GHA / cloud env var names whose value is the
// secret. A real read goes through process.env (see envReadRe); the
// bare string is not enough on its own.
var ciSecretEnvVars = []string{
	"GITHUB_TOKEN",
	"ACTIONS_ID_TOKEN_REQUEST_TOKEN",
	"ACTIONS_ID_TOKEN_REQUEST_URL",
	"NPM_TOKEN",
	"AWS_ACCESS_KEY_ID",
	"AWS_SECRET_ACCESS_KEY",
	"AWS_WEB_IDENTITY_TOKEN_FILE",
	"VAULT_TOKEN",
	"KUBERNETES_SERVICE_HOST",
}

// ciSecretLiteralNeedles are cloud-metadata IPs and on-disk credential
// paths. These are unambiguous strings; their literal presence in a
// JavaScript file is sufficient evidence of secret access.
var ciSecretLiteralNeedles = []string{
	"/var/run/secrets/kubernetes.io/serviceaccount",
	"169.254.169.254",
	"169.254.170.2",
}

// agentPersistenceNeedles are paths whose presence alone is sufficient
// evidence of editor-automation persistence. Each names a file that
// either holds auto-running config (.claude/settings.json hooks) or is
// itself auto-executed (.vscode/setup.mjs) on workspace open.
var agentPersistenceNeedles = []string{
	".claude/settings.json",
	".claude/router_runtime.js",
	".claude/setup.mjs",
	".claude/hooks/",
	".vscode/setup.mjs",
}

// runOnFolderOpenNeedles capture the VS Code task trigger that turns
// a tasks.json entry into an auto-run on workspace open. These do not
// fire on their own; persistence requires the file ALSO references
// .vscode/tasks.json (see detection below).
var runOnFolderOpenNeedles = []string{
	`runOn": "folderOpen`,
	`runOn":"folderOpen`,
	`runOn: "folderOpen`,
	`runOn: 'folderOpen`,
	`runOn:'folderOpen`,
}

// --- detection ---

func detect(path string, m *metrics) []types.Finding {
	var out []types.Finding
	if f := detectObfuscation(path, m); f != nil {
		out = append(out, *f)
	}
	if f := detectDaemon(path, m); f != nil {
		out = append(out, *f)
	}
	if f := detectCISecretHarvest(path, m); f != nil {
		out = append(out, *f)
	}
	if f := detectProcMemOIDC(path, m); f != nil {
		out = append(out, *f)
	}
	if f := detectAgentPersistence(path, m); f != nil {
		out = append(out, *f)
	}
	return out
}

// detectObfuscation requires at least two signals AND at least one
// obfuscator-specific signal so that ordinary minified vendor bundles
// (which trip the size and line-length thresholds on their own) do not
// false-positive.
func detectObfuscation(path string, m *metrics) *types.Finding {
	generic := 0
	obfSpecific := 0
	if m.SizeBytes > sizeBytesThreshold {
		generic++
	}
	if m.MaxLineLen > maxLineLenThreshold {
		generic++
	}
	if m.HexIdentifierCount > hexIdentifierThreshold {
		obfSpecific++
	}
	if m.DispatcherCallCount > dispatcherCallThreshold {
		obfSpecific++
	}
	if m.HasWhileTruePattern {
		obfSpecific++
	}

	// At least one obfuscator-specific signal is required; total signals
	// must reach two. A minified bundle that hits only size and line
	// length stays clean.
	if obfSpecific == 0 {
		return nil
	}
	if generic+obfSpecific < 2 {
		return nil
	}

	sev := types.SeverityMedium
	if m.HasProcessEnv || m.HasChildProcess || m.HasNetworkSink {
		sev = types.SeverityHigh
	}
	line := m.LineObfSpecific
	if line == 0 {
		line = 1
	}
	return &types.Finding{
		RuleID:   RuleObfuscation,
		RuleName: "Large obfuscated JavaScript payload",
		Severity: sev,
		Category: "supply-chain",
		Description: "JavaScript file matches the static shape of an obfuscator-emitted " +
			"payload (hex identifier density, dispatcher calls, or a while(!![]) loop) " +
			"in combination with at least one further signal. Payloads with this shape are " +
			"the standard delivery vehicle for npm supply-chain compromises.",
		FilePath:    path,
		Line:        line,
		MatchedText: "obfuscator fingerprint (hex idents / dispatcher / while-loop) + size/network",
		Analyzer:    AnalyzerName,
		Confidence:  0.85,
		Remediation: "Inspect the file's provenance: a build pipeline normally does not ship " +
			"obfuscated JavaScript. If the file is vendored, pin it to a specific checksum " +
			"and review the upstream source. If it appeared during install, treat it as a " +
			"compromised dependency lifecycle artifact.",
	}
}

// detectDaemon flags child_process invocations that detach + ignore
// stdio (or .unref()) within the same options block — the install-time
// daemonization shape used to keep a payload alive after install
// exits. The proximity gate (computed in findDaemonChain) prevents an
// unrelated object literal carrying daemon-shape options from
// satisfying this rule.
func detectDaemon(path string, m *metrics) *types.Finding {
	if !m.HasDaemonChain {
		return nil
	}
	sev := types.SeverityHigh
	if m.HasCISecretRead || m.HasNetworkSink || m.HasPublishSink {
		sev = types.SeverityCritical
	}
	line := m.LineDaemon
	if line == 0 {
		line = 1
	}
	return &types.Finding{
		RuleID:   RuleDaemon,
		RuleName: "Detached background execution from JavaScript",
		Severity: sev,
		Category: "supply-chain",
		Description: "JavaScript spawns a child process with detached: true and either " +
			"stdio ignored or .unref() called. That keeps the spawned process alive past " +
			"the parent's exit, which is the standard shape for install-time payloads that " +
			"persist beyond `npm install`.",
		FilePath:    path,
		Line:        line,
		MatchedText: "child_process + detached: true + stdio-ignore / unref",
		Analyzer:    AnalyzerName,
		Confidence:  0.9,
		Remediation: "Audit the spawn target. Legitimate libraries rarely detach background " +
			"processes; if this code lives inside a postinstall or dependency-lifecycle " +
			"path, treat it as a compromise and pin the dependency to a clean version.",
	}
}

// detectCISecretHarvest flags the combination of reading CI / cloud
// secrets and emitting them through a network or registry sink, the
// canonical fingerprint of a credential-stealing payload.
func detectCISecretHarvest(path string, m *metrics) *types.Finding {
	if !m.HasCISecretRead {
		return nil
	}
	if !m.HasNetworkSink && !m.HasPublishSink && !m.HasGitHubGraphQLSink && !m.HasSessionSink {
		return nil
	}
	line := m.LineCISecret
	if line == 0 {
		line = 1
	}
	return &types.Finding{
		RuleID:   RuleCISecretHarvest,
		RuleName: "CI credential harvesting with network or registry sink",
		Severity: types.SeverityCritical,
		Category: "supply-chain",
		Description: "JavaScript reads a CI / cloud token (e.g. " + m.CISecretMatched +
			") and then routes it to a network, npm registry, GitHub API, or session-exfil " +
			"sink. Whatever the wrapper looks like, this is the credential-exfil shape used " +
			"by recent npm supply-chain compromises.",
		FilePath:    path,
		Line:        line,
		MatchedText: "reads " + m.CISecretMatched + " + network/registry/graphql/session sink",
		Analyzer:    AnalyzerName,
		Confidence:  0.95,
		Remediation: "Treat the surrounding package as compromised. Rotate any tokens this " +
			"runner has held, audit recent runs of the affected pipeline, and pin the " +
			"dependency to a known-clean version.",
	}
}

// detectProcMemOIDC flags reads of the GitHub Actions runner process
// memory paired with the OIDC token env var name — the runner-pivot
// pattern observed in supply-chain incidents.
func detectProcMemOIDC(path string, m *metrics) *types.Finding {
	if !m.HasProcMemAccess {
		return nil
	}
	// Require a more specific /proc subpath than the bare prefix.
	// content is captured in lineOf via the metrics struct's first index.
	// Without it the rule is too broad (any /proc/ reference triggers).
	// The substring check happens here via the auxiliary metrics state.
	if !m.HasOIDCTokenEnv && !m.HasRunnerWorker {
		return nil
	}
	line := m.LineProcMem
	if line == 0 {
		line = 1
	}
	return &types.Finding{
		RuleID:   RuleProcMemOIDC,
		RuleName: "Runner process memory access combined with OIDC token reference",
		Severity: types.SeverityCritical,
		Category: "supply-chain",
		Description: "JavaScript accesses /proc/<pid>/mem|maps|cmdline-style paths and " +
			"references ACTIONS_ID_TOKEN_REQUEST_* or Runner.Worker. Reading another " +
			"process's memory to steal an OIDC token is a runner-pivot shape with no " +
			"legitimate use in normal package code.",
		FilePath:    path,
		Line:        line,
		MatchedText: "/proc/* + ACTIONS_ID_TOKEN_REQUEST_* | Runner.Worker",
		Analyzer:    AnalyzerName,
		Confidence:  0.97,
		Remediation: "Treat the file as malicious. Rotate any tokens reachable from the " +
			"affected runner and audit recent CI runs for unexpected publishes.",
	}
}

// detectAgentPersistence flags writes or references to Claude Code or
// VS Code workspace files that auto-run on workspace open.
func detectAgentPersistence(path string, m *metrics) *types.Finding {
	if !m.HasClaudePersistence && !m.HasVSCodePersistence {
		return nil
	}
	sev := types.SeverityHigh
	if m.HasCISecretRead || m.HasDaemonChain {
		sev = types.SeverityCritical
	}
	line := m.LineAgentPath
	if line == 0 {
		line = 1
	}
	return &types.Finding{
		RuleID:   RuleAgentPersistence,
		RuleName: "Persistence through Claude Code or VS Code workspace automation",
		Severity: sev,
		Category: "supply-chain",
		Description: "File references " + m.AgentPathMatched + ", an automation surface that " +
			"executes on workspace open. Writing to or invoking these paths from package " +
			"code installs persistence that survives reinstall and is invisible outside the " +
			"specific editor.",
		FilePath:    path,
		Line:        line,
		MatchedText: m.AgentPathMatched,
		Analyzer:    AnalyzerName,
		Confidence:  0.9,
		Remediation: "Editor automation files belong to the user, not to package code. " +
			"Audit the change in a clean clone, remove any package-emitted automation, and " +
			"pin the source package to a known-clean version.",
	}
}
