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

// detachedTrueRe matches `detached: true`, `"detached": true`, and the
// single-quoted/no-space variants. Without the quote-tolerant form,
// JSON-style spawn options ({"detached": true, ...}) miss the daemon
// chain entirely.
var detachedTrueRe = regexp.MustCompile(`(?i)["']?detached["']?\s*:\s*true\b`)


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

	HasSpawnDetached bool
	HasStdioIgnored  bool
	HasUnref         bool
	LineDaemon       int

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

	// Network / publish / GitHub / session sinks. Each list is a small
	// set of unambiguous strings that should not appear in unrelated
	// dependency or library names.
	lower := bytes.ToLower(content)
	for _, n := range networkSinkNeedles {
		if i := bytes.Index(lower, []byte(n)); i >= 0 {
			m.HasNetworkSink = true
			if m.LineNetworkSink == 0 {
				m.LineNetworkSink = lineOf(content, i)
			}
		}
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
	m.HasChildProcess = bytes.Contains(lower, []byte("child_process")) ||
		bytes.Contains(lower, []byte("require('child_process')")) ||
		bytes.Contains(lower, []byte(`require("child_process")`))
	m.HasProcessEnv = bytes.Contains(lower, []byte("process.env"))

	// CI / cloud secret reads. The list is short and unambiguous; each
	// entry is either an env var name (uppercase / underscored, so it
	// will not appear as a registry package name) or a well-known cloud
	// metadata IP / path.
	for _, n := range ciSecretReadNeedles {
		if i := bytes.Index(content, []byte(n)); i >= 0 {
			m.HasCISecretRead = true
			if m.LineCISecret == 0 {
				m.LineCISecret = lineOf(content, i)
				m.CISecretMatched = n
			}
		}
	}

	// Daemonization signals. Quote-tolerant regex catches the JSON-style
	// `"detached": true` form that a naive substring match for
	// `detached:` would skip.
	if loc := detachedTrueRe.FindIndex(content); loc != nil {
		m.HasSpawnDetached = true
		m.LineDaemon = lineOf(content, loc[0])
	}
	if bytes.Contains(content, []byte(`stdio: 'ignore'`)) ||
		bytes.Contains(content, []byte(`stdio: "ignore"`)) ||
		bytes.Contains(content, []byte(`stdio:'ignore'`)) ||
		bytes.Contains(content, []byte(`stdio:"ignore"`)) ||
		bytes.Contains(content, []byte(`stdio: ['ignore'`)) ||
		bytes.Contains(content, []byte(`stdio:['ignore'`)) {
		m.HasStdioIgnored = true
	}
	m.HasUnref = bytes.Contains(content, []byte(".unref()"))

	// Process memory access requires both a /proc/ reference AND one of
	// the memory-like subpaths (mem / maps / cmdline). Static /proc/stat
	// reads do not satisfy that pair. The substring form covers both
	// literal paths (`/proc/self/maps`) and dynamic concatenation
	// (`'/proc/' + pid + '/mem'`) without a brittle regex.
	if bytes.Contains(content, []byte("/proc/")) &&
		(bytes.Contains(content, []byte("/mem")) ||
			bytes.Contains(content, []byte("/maps")) ||
			bytes.Contains(content, []byte("cmdline"))) {
		m.HasProcMemAccess = true
		m.LineProcMem = lineOf(content, bytes.Index(content, []byte("/proc/")))
	}
	m.HasOIDCTokenEnv = bytes.Contains(content, []byte("ACTIONS_ID_TOKEN_REQUEST_TOKEN")) ||
		bytes.Contains(content, []byte("ACTIONS_ID_TOKEN_REQUEST_URL"))
	m.HasRunnerWorker = bytes.Contains(content, []byte("Runner.Worker"))

	// Agent persistence references. Each path is a known incident
	// fingerprint root; the analyzer keeps the first match as the
	// anchor line.
	for _, n := range agentPersistenceNeedles {
		if i := bytes.Index(content, []byte(n)); i >= 0 {
			switch {
			case strings.HasPrefix(n, ".claude/"):
				m.HasClaudePersistence = true
			case strings.HasPrefix(n, ".vscode/"):
				m.HasVSCodePersistence = true
			default:
				m.HasClaudePersistence = true
			}
			if m.LineAgentPath == 0 {
				m.LineAgentPath = lineOf(content, i)
				m.AgentPathMatched = n
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

// --- needle lists ---

// All lower-cased; matched against bytes.ToLower(content). Each entry
// names a known network API. Bare method names like `.post(` / `.put(`
// were dropped because they false-positive on any object with a method
// of that name (in-memory caches, database clients, queue libraries),
// turning the credential-harvest chain into a wide CI block.
var networkSinkNeedles = []string{
	"fetch(",
	"axios.post",
	"axios.put",
	"axios.request",
	"axios.get",
	"got.post",
	"got.put",
	"got.get",
	"http.request",
	"https.request",
	"net.connect",
	"net.createconnection",
	"xmlhttprequest",
}

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

// ciSecretReadNeedles are case-sensitive on purpose: GHA / cloud envs
// are uppercase and would not appear as part of a dependency name.
var ciSecretReadNeedles = []string{
	"GITHUB_TOKEN",
	"ACTIONS_ID_TOKEN_REQUEST_TOKEN",
	"ACTIONS_ID_TOKEN_REQUEST_URL",
	"NPM_TOKEN",
	"AWS_ACCESS_KEY_ID",
	"AWS_SECRET_ACCESS_KEY",
	"AWS_WEB_IDENTITY_TOKEN_FILE",
	"VAULT_TOKEN",
	"KUBERNETES_SERVICE_HOST",
	"/var/run/secrets/kubernetes.io/serviceaccount",
	"169.254.169.254",
	"169.254.170.2",
}

var agentPersistenceNeedles = []string{
	".claude/settings.json",
	".claude/router_runtime.js",
	".claude/setup.mjs",
	".claude/hooks/",
	".vscode/tasks.json",
	".vscode/setup.mjs",
	`runOn": "folderOpen`,
	`runOn":"folderOpen`,
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
// stdio (or .unref()) — the install-time daemonization shape used to
// keep a payload alive after the install step exits.
func detectDaemon(path string, m *metrics) *types.Finding {
	if !m.HasChildProcess {
		return nil
	}
	if !m.HasSpawnDetached {
		return nil
	}
	if !m.HasStdioIgnored && !m.HasUnref {
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
	if m.HasCISecretRead || (m.HasSpawnDetached && (m.HasStdioIgnored || m.HasUnref)) {
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
