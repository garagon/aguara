// Package jsrisk inspects JavaScript source for static payload shapes
// that combine into supply-chain risk chains: large obfuscated payloads,
// detached background execution from install-time code, CI credential
// harvesting paired with a network or registry sink, OIDC token
// extraction from runner process memory, persistence through Claude
// Code or VS Code workspace automation, and DNS TXT credential exfil
// (JS_DNS_TXT_EXFIL_001, added for the May 2026 node-ipc compromise).
//
// The analyzer is fully offline. It runs at most a single linear pass
// over the content plus a handful of compiled-once regex matches; it
// never executes scripts and never deobfuscates dynamically. Findings
// stay chain-aware: single weak signals (a large file alone, a single
// CI env reference alone, a child_process call alone) never fire.
//
// Limits of the regex-based JS scanner. The DNS TXT detector tracks
// string-literal interiors, comments, regex literals, template-literal
// interpolations, fs/os/dns module aliases (require + ESM + combined
// imports + destructure-with-rename), inline-require chains, and
// statement boundaries (`;`, ASI newlines, comma-as-separator at top
// level). It is NOT a full JavaScript parser. Sophisticated obfuscation
// (dynamic property access through computed names, eval / Function
// constructor, ASTs reassembled at runtime) can evade the rule. The
// rule is one signal in a defense-in-depth stack — complement it with
// the npm metadata check (`aguara check --ecosystem npm`), pinned
// release scanning, and runtime egress monitoring. Detector accuracy
// was iterated against the published node-ipc 2026 payload shape and
// representative malicious-package examples; known limitations are
// acceptable trade-offs for the deterministic-and-offline guarantee.
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
	RuleObfuscation      = "JS_OBF_001"
	RuleDaemon           = "JS_DAEMON_001"
	RuleCISecretHarvest  = "JS_CI_SECRET_HARVEST_001"
	RuleProcMemOIDC      = "JS_PROC_MEM_OIDC_001"
	RuleAgentPersistence = "AGENT_PERSISTENCE_001"
	RuleDNSTXTExfil      = "JS_DNS_TXT_EXFIL_001"
	RuleBunSecondStage   = "JS_BUN_SECOND_STAGE_001"
	RuleGitHubC2         = "JS_GITHUB_C2_001"
	RuleSudoersTamper    = "JS_SUDOERS_TAMPER_001"
	RuleHostTrustTamper  = "JS_HOST_TRUST_TAMPER_001"
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
	return detect(target.RelPath, m, target.Content), nil
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

	// DNS TXT exfil chain. HasDNSTXTSink is true when the file makes a
	// real `resolveTxt(...)` call against the Node `dns` module (direct,
	// alias-from-Resolver, inline require, or imported function). String
	// mentions of `resolveTxt` outside a call do not count.
	HasDNSTXTSink bool
	LineDNSTXT    int

	// HasNodeIPCIOC is true when the file contains literal IOC strings
	// from the May 2026 node-ipc compromise: the bt.node.js DNS zone,
	// the sh.azurestaticprovider.net HTTPS endpoint, or the __ntw /
	// __ntRun runtime markers. Presence escalates the DNS-TXT chain
	// straight to CRITICAL.
	HasNodeIPCIOC bool
	NodeIPCMatch  string

	// Bun second-stage chain (JS_BUN_SECOND_STAGE_001). HasBunExecution
	// is true when the file runs the Bun runtime through a bound
	// child_process / execa / shelljs call. Execution alone never fires; a
	// strong partner (obfuscator shape, CI/cloud secret read, or a
	// network-call sink) is required, so the partner cannot be faked by a
	// documentation string.
	HasBunExecution bool
	LineBun         int

	// GitHub-as-C2 write/control channel (JS_GITHUB_C2_001).
	// HasGitHubWriteChannel is true when the file writes/controls GitHub
	// content: a GraphQL write mutation, an Octokit write method call, or a
	// REST contents/git-data endpoint paired with a PUT/PATCH/POST. The
	// channel alone never fires; it requires a strong partner. Kind is one
	// of "graphql-write" | "octokit-write" | "rest-write".
	HasGitHubWriteChannel bool
	LineGitHubChannel     int
	GitHubChannelKind     string

	// HasStrongSecretRead is a CI/cloud secret read that is NOT a bare
	// GITHUB_TOKEN (NPM_TOKEN, AWS, OIDC request token, Vault, kube, cloud
	// metadata). It is the discriminating partner for JS_GITHUB_C2_001: a
	// legitimate release bot reads GITHUB_TOKEN, so only a non-GitHub
	// secret separates credential exfil from ordinary GitHub writes.
	HasStrongSecretRead bool
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

	// Shared lexical view: comments + regex-literal bodies masked, string
	// interiors known. Every signal below scans view.Code so a commented
	// or regex-literal occurrence never counts; code-token signals also
	// skip matches inside string literals (a call keyword or env read in a
	// string is data, not code). Computed once.
	view := newJSLexicalView(content)
	code := view.Code

	// Obfuscator signals. Counted over masked code; identifiers/calls that
	// land inside a string literal are example data, not the payload, so
	// they are filtered out. The cap is applied to CODE-TOKEN matches (via
	// countCodeTokenMatches), not raw matches, so a real payload preceded
	// by many stringified _0x examples is still counted.
	hexCount, hexFirst := countCodeTokenMatches(view, hexIdentifierRe, hexIdentifierThreshold)
	m.HexIdentifierCount = hexCount
	dispCount, dispFirst := countCodeTokenMatches(view, dispatcherCallRe, dispatcherCallThreshold)
	m.DispatcherCallCount = dispCount
	if idx := whileTrueIndex(view); idx >= 0 {
		m.HasWhileTruePattern = true
		m.LineObfSpecific = lineOf(code, idx)
	}
	if m.LineObfSpecific == 0 && m.HexIdentifierCount > hexIdentifierThreshold && hexFirst >= 0 {
		m.LineObfSpecific = lineOf(code, hexFirst)
	}
	if m.LineObfSpecific == 0 && m.DispatcherCallCount > dispatcherCallThreshold && dispFirst >= 0 {
		m.LineObfSpecific = lineOf(code, dispFirst)
	}

	// Network / publish / GitHub / session sinks. The network regex is
	// whitespace-tolerant (so `fetch (...)` matches) and case-insensitive.
	// Publish / GitHub / session sinks are unambiguous literal strings.
	// Aliased http/https/net imports are discovered separately so a
	// payload like `const h = require('https'); h.request(...)` still
	// counts as a network sink.
	// Length-preserving ASCII fold so offsets in lowerCode line up with
	// view.Code (and the call-argument ranges). bytes.ToLower is
	// Unicode-aware and could shift offsets on non-ASCII input.
	lowerCode := asciiLowerBytes(code)
	// Child_process call sites and execa matches are computed once and
	// reused by the child_process flag, Bun execution, and (only when
	// needed) host-needle binding.
	cpCalls := collectChildProcessCalls(code)
	execaMatches := execaCallRe.FindAllIndex(code, -1)
	shelljsCalls := collectShelljsExecCalls(code)

	// Network sink: the fetch()/http.request() CALL keyword must be real
	// code, not inside a string ("fetch('x')") or a regex (/fetch\(/).
	// Streamed so a file full of stringified `fetch(` examples does not
	// force materializing every match.
	if loc := firstCodeTokenIndex(view, networkSinkRe); loc >= 0 {
		m.HasNetworkSink = true
		m.LineNetworkSink = lineOf(code, loc)
	}
	if !m.HasNetworkSink {
		if line := findNetworkAliasSink(code); line > 0 {
			m.HasNetworkSink = true
			m.LineNetworkSink = line
		}
	}
	// Host data indicators (registry / GitHub GraphQL / session) are broad
	// PARTNER signals matched by presence on comment-masked code: a
	// commented mention no longer counts, but a host in any string still
	// does. They are deliberately NOT bound to a modeled HTTP-client call:
	// binding by client whitelist loses real exfil through unmodeled
	// clients (request, superagent, ky, internal wrappers), and these
	// needles only matter as a partner to a real secret read anyway.
	// (Call-bound host matching with a sound abstraction is a possible
	// future refinement, not a per-client list.)
	for _, n := range publishSinkNeedles {
		if bytes.Contains(lowerCode, []byte(n)) {
			m.HasPublishSink = true
			break
		}
	}
	for _, n := range githubGraphQLNeedles {
		if bytes.Contains(lowerCode, []byte(n)) {
			m.HasGitHubGraphQLSink = true
			break
		}
	}
	for _, n := range sessionSinkNeedles {
		if bytes.Contains(lowerCode, []byte(n)) {
			m.HasSessionSink = true
			break
		}
	}
	// HasChildProcess: a real receiver-bound or destructured child_process
	// call, with the call keyword in code (not a stringified example).
	for _, site := range cpCalls {
		if view.CodeTokenAt(site.Start) {
			m.HasChildProcess = true
			break
		}
	}
	m.HasProcessEnv = hasCodeToken(view, lowerCode, "process.env")

	// Bun execution: a bound child_process / execa / shelljs call running
	// bun on masked code. The gate (detectBunSecondStage) pairs this with a
	// strong partner; execution alone never fires.
	if line := bunExecutionSite(view, cpCalls, execaMatches, shelljsCalls); line > 0 {
		m.HasBunExecution = true
		m.LineBun = line
	}

	// GitHub-as-C2 write/control channel: a GraphQL write mutation, an
	// Octokit write-method call, or a REST contents/git-data endpoint
	// paired with a PUT/PATCH/POST. Channel alone never fires (see
	// detectGitHubC2); it needs a strong partner.
	if kind, line := findGitHubWriteChannel(view, lowerCode); kind != "" {
		m.HasGitHubWriteChannel = true
		m.GitHubChannelKind = kind
		m.LineGitHubChannel = line
	}

	// CI / cloud secret reads come in three forms: direct member access
	// (process.env.NAME), bracket access (process.env['NAME']), and
	// destructuring ({NAME} = process.env). Pure string mentions do not
	// count as a read.
	checkSecretName := func(name string, idx int) {
		for _, n := range ciSecretEnvVars {
			if name == n && !m.HasCISecretRead {
				m.HasCISecretRead = true
				m.LineCISecret = lineOf(code, idx)
				m.CISecretMatched = n
				return
			}
		}
	}
	// process.env.SECRET reads must be real code: a `process.env.GITHUB_TOKEN`
	// inside a string or comment is documentation, not a read.
	for _, match := range envReadRe.FindAllSubmatchIndex(code, -1) {
		if m.HasCISecretRead {
			break
		}
		if !matchInCode(view, match) {
			continue
		}
		checkSecretName(string(code[match[2]:match[3]]), match[0])
	}
	if !m.HasCISecretRead {
		for _, match := range envDestructureRe.FindAllSubmatchIndex(code, -1) {
			if m.HasCISecretRead {
				break
			}
			if !matchInCode(view, match) {
				continue
			}
			nameList := string(code[match[2]:match[3]])
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
	// unambiguous IPs / filesystem paths. They live inside string
	// arguments, so they are matched on comment-masked code (a commented
	// mention does not count) but not string-guarded.
	for _, n := range ciSecretLiteralNeedles {
		if i := bytes.Index(code, []byte(n)); i >= 0 {
			m.HasCISecretRead = true
			if m.LineCISecret == 0 {
				m.LineCISecret = lineOf(code, i)
				m.CISecretMatched = n
			}
		}
	}

	// Strong (non-bare-GITHUB_TOKEN) secret read: the discriminating
	// partner for the GitHub-C2 write channel. A legitimate release bot
	// reads GITHUB_TOKEN, so only a non-GitHub secret (NPM_TOKEN, AWS,
	// OIDC request token, Vault, kube, cloud metadata) separates credential
	// exfil from an ordinary GitHub write. Env reads must be real code, and
	// an assignment LHS (`process.env.NPM_TOKEN = x`) is a write, not a
	// read, so it is excluded (same handling as the DNS detector).
	envLHSStarts := map[int]bool{}
	for _, loc := range processEnvDotLHSAssignRe.FindAllIndex(code, -1) {
		envLHSStarts[loc[0]] = true
	}
	for _, loc := range processEnvBracketLHSAssignRe.FindAllIndex(code, -1) {
		envLHSStarts[loc[0]] = true
	}
	for _, match := range envReadRe.FindAllSubmatchIndex(code, -1) {
		if m.HasStrongSecretRead {
			break
		}
		if !matchInCode(view, match) || envLHSStarts[match[0]] {
			continue
		}
		name := string(code[match[2]:match[3]])
		if name == "GITHUB_TOKEN" {
			continue
		}
		for _, n := range ciSecretEnvVars {
			if name == n {
				m.HasStrongSecretRead = true
				break
			}
		}
	}
	// Destructured form: const { AWS_SECRET_ACCESS_KEY = "" } = process.env.
	if !m.HasStrongSecretRead {
		for _, match := range envDestructureRe.FindAllSubmatchIndex(code, -1) {
			if m.HasStrongSecretRead {
				break
			}
			if !matchInCode(view, match) {
				continue
			}
			for _, raw := range strings.Split(string(code[match[2]:match[3]]), ",") {
				entry := strings.TrimSpace(raw)
				// Strip a default initializer (`NAME = def`) then a rename
				// (`NAME: alias`) before comparing the source member name.
				if idx := strings.Index(entry, "="); idx >= 0 {
					entry = strings.TrimSpace(entry[:idx])
				}
				if idx := strings.Index(entry, ":"); idx >= 0 {
					entry = strings.TrimSpace(entry[:idx])
				}
				if entry == "GITHUB_TOKEN" {
					continue
				}
				for _, n := range ciSecretEnvVars {
					if entry == n {
						m.HasStrongSecretRead = true
						break
					}
				}
				if m.HasStrongSecretRead {
					break
				}
			}
		}
	}
	if !m.HasStrongSecretRead {
		for _, n := range ciSecretLiteralNeedles {
			if bytes.Contains(code, []byte(n)) {
				m.HasStrongSecretRead = true
				break
			}
		}
	}
	// Whole-environment exfil (JSON.stringify(process.env),
	// Object.values(process.env), ...) dumps every secret, including the
	// non-GitHub ones, so it is a strong partner. Uses the DUMP-only regex:
	// the single-key process.env[k] lookup is one variable (possibly
	// GITHUB_TOKEN), which is the release-bot shape, not a credential dump.
	if !m.HasStrongSecretRead {
		for _, loc := range wholeProcessEnvDumpRe.FindAllIndex(code, -1) {
			if matchInCode(view, loc) {
				m.HasStrongSecretRead = true
				break
			}
		}
	}

	// Daemonization is computed inline so the chain options (detached,
	// stdio:ignore, .unref()) are tied to a real child_process call,
	// not satisfied by any object literal elsewhere in the file. Runs on
	// masked code so a commented example does not satisfy it.
	if line, ok := findDaemonChain(code); ok {
		m.HasDaemonChain = true
		m.LineDaemon = line
	}

	// Process memory access requires a /proc/ reference paired with a
	// memory-like subpath (/mem, /maps, cmdline) in proximity. The
	// proximity window catches both literal paths and concatenated forms
	// like `'/proc/' + pid + '/mem'` while filtering out files that
	// reference /proc/stat in one place and an unrelated 'cmdline'
	// identifier elsewhere.
	m.LineProcMem = findProcMemPair(code)
	m.HasProcMemAccess = m.LineProcMem > 0
	m.HasOIDCTokenEnv = bytes.Contains(code, []byte("ACTIONS_ID_TOKEN_REQUEST_TOKEN")) ||
		bytes.Contains(code, []byte("ACTIONS_ID_TOKEN_REQUEST_URL"))
	m.HasRunnerWorker = bytes.Contains(code, []byte("Runner.Worker"))

	// Agent persistence references. Matched on comment-masked code so a
	// commented .claude/ mention does not count; the path lives inside a
	// string argument of a write/read, so it is not string-guarded.
	// (Tighter write/read-call binding for these paths is a documented
	// follow-up; see PR notes.) VS Code persistence is gated on the pair
	// tasks.json + runOn:folderOpen.
	for _, n := range agentPersistenceNeedles {
		if i := bytes.Index(code, []byte(n)); i >= 0 {
			m.HasClaudePersistence = true
			if m.LineAgentPath == 0 {
				m.LineAgentPath = lineOf(code, i)
				m.AgentPathMatched = n
			}
		}
	}
	if bytes.Contains(code, []byte(".vscode/tasks.json")) {
		if loc := runOnFolderOpenRe.FindIndex(code); loc != nil {
			m.HasVSCodePersistence = true
			if m.LineAgentPath == 0 {
				m.LineAgentPath = lineOf(code, loc[0])
				m.AgentPathMatched = ".vscode/tasks.json + runOn: folderOpen"
			}
		}
	}

	// DNS TXT exfil signals. The detector requires a real resolveTxt
	// invocation; it already strips comments and gates on string interiors
	// internally, so masked code passes through unchanged.
	if line := findDNSTXTSink(code); line > 0 {
		m.HasDNSTXTSink = true
		m.LineDNSTXT = line
	}
	// Compute string interiors once and reuse for both archive and
	// envs.txt partner gating. A partner requires its executable
	// anchor (an fs-write call or an os.tmpdir call) to live in
	// code, not inside a quoted string in a help message.
	// contentStringRanges is computed lazily by detectDNSTXTExfil
	// when it needs to gate partner anchors on executable code.
	// computeMetrics does not need it because the DNS TXT chain
	// partners are not surfaced as struct fields.

	// Archive partner: executable os.tmpdir / tmpdir anchor in code,
	// Archive and envs.txt partner scans are NOT performed here.
	// Both partners are recomputed inside detectDNSTXTExfil from
	// comment-stripped content, with the same alias-binding gates,
	// so computing them in computeMetrics would be wasted work on
	// every JavaScript file (large minified bundles especially).
	// detectDNSTXTExfil only runs when HasDNSTXTSink is true; the
	// recomputation cost is amortized over actual chain candidates.
	for _, n := range nodeIPCIOCNeedles {
		if bytes.Contains(code, []byte(n)) {
			m.HasNodeIPCIOC = true
			if m.NodeIPCMatch == "" {
				m.NodeIPCMatch = n
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
	// Method is the lowercased child_process SOURCE method (exec, execsync,
	// spawn, ...), resolved through any destructuring rename. It lets callers
	// distinguish shell-interpreting forms (exec/execSync) from program APIs
	// without re-reading the local call name.
	Method string
}

// collectChildProcessCalls returns sites of real child_process
// invocations: receiver-bound method calls (require chain or known
// module alias) plus bare calls whose name was destructured from
// child_process. Unrelated `.spawn(...)` calls and bare calls whose
// name was never imported from the module are excluded.
func collectChildProcessCalls(content []byte) []cpCallSite {
	var sites []cpCallSite
	// A binding or call written inside a STRING literal (a doc/snippet that
	// quotes `require('child_process')`) is text, not a real import; skip
	// those so an unrelated object's `.exec(...)` is not misclassified.
	sr := jsStringInteriors(content)

	// Inline require chain: require('child_process').spawn(...)
	for _, loc := range inlineRequireReceiverRe.FindAllIndex(content, -1) {
		if insideStringInterior(sr, loc[0]) {
			continue
		}
		sites = append(sites, cpCallSite{Start: loc[0], ArgsStart: loc[1], Method: lastCallMethod(content, loc[1])})
	}

	// Aliases bound via CJS require or ESM default/namespace import.
	// Only names that are ACTUALLY bound from child_process count as
	// receivers; an unrelated local variable called `cp` does not.
	aliases := map[string]bool{}
	for _, m := range childProcessAliasAssignRe.FindAllSubmatchIndex(content, -1) {
		if insideStringInterior(sr, m[2]) {
			continue
		}
		aliases[string(content[m[2]:m[3]])] = true
	}
	for _, m := range childProcessAliasESMRe.FindAllSubmatchIndex(content, -1) {
		if insideStringInterior(sr, m[2]) {
			continue
		}
		aliases[string(content[m[2]:m[3]])] = true
	}
	if len(aliases) > 0 {
		// Generic identifier-method matcher; filter to imported names.
		// jsIdentBoundary handles `$`-prefixed aliases that a literal
		// `\b` would skip.
		for _, m := range identifierCPMethodCallRe.FindAllSubmatchIndex(content, -1) {
			if aliases[string(content[m[2]:m[3]])] {
				// Submatch 0 spans the boundary char + alias + .method(.
				// The actual identifier starts at m[2]; that is the
				// anchor we want for the finding's Line. ArgsStart is
				// m[1] (one past the opening paren).
				sites = append(sites, cpCallSite{Start: m[2], ArgsStart: m[1], Method: lastCallMethod(content, m[1])})
			}
		}
	}

	// Collect destructured local names. For each entry the source
	// (left of `:` in CJS, left of ` as ` in ESM) must be a real
	// child_process method; the local binding (right side, or the
	// entry itself when not aliased) is what shows up in a bare call.
	// local binding name -> lowercased source child_process method, so a
	// renamed destructure (`{ execSync: run }`) still reports its real method.
	destructuredNames := map[string]string{}
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
				destructuredNames[local] = strings.ToLower(source)
			}
		}
	}
	for _, m := range childProcessDestructureRe.FindAllSubmatchIndex(content, -1) {
		if insideStringInterior(sr, m[2]) {
			continue
		}
		addDestructure(string(content[m[2]:m[3]]), ":")
	}
	for _, m := range childProcessESMDestructureRe.FindAllSubmatchIndex(content, -1) {
		if insideStringInterior(sr, m[2]) {
			continue
		}
		addDestructure(string(content[m[2]:m[3]]), " as ")
	}
	if len(destructuredNames) > 0 {
		for _, loc := range anyBareInvokeRe.FindAllSubmatchIndex(content, -1) {
			if src, ok := destructuredNames[string(content[loc[2]:loc[3]])]; ok {
				sites = append(sites, cpCallSite{Start: loc[0], ArgsStart: loc[1], Method: src})
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

// bunExecutionSite returns the 1-based line of the first REAL Bun runtime
// launch in already-comment-stripped code, or 0. Execution is recognized
// only at bound call sites: a child_process call (spawn/exec/execFile/fork
// via collectChildProcessCalls) whose args run bun, an execa(...) call
// running bun, or a shelljs `.exec(...)` running a bun command in a file
// that imports shelljs. An unrelated `db.exec('bun run x')`, a
// user-defined helper named exec/spawn, and documented commands therefore
// do not register. Call-site starts inside a string literal are skipped
// (a stringified example is not a call).
// bunExecutionSite takes the shared lexical view plus the already-computed
// child_process call sites and execa call matches (so it does not re-scan
// the file), and returns the line of the first real Bun payload launch.
func bunExecutionSite(view jsLexicalView, cpCalls []cpCallSite, execaMatches [][]int, shelljsCalls []cpCallSite) int {
	code := view.Code
	best := -1
	consider := func(start int) {
		if start < 0 || view.InString(start) {
			return
		}
		if best < 0 || start < best {
			best = start
		}
	}

	// Real child_process calls whose arguments launch bun on a payload:
	// the program-literal form spawn("bun", ["./x.mjs"]) and the
	// command-string form exec("bun run ./x"). Bound via
	// collectChildProcessCalls (receiver alias or destructured), so a
	// user-defined function named spawn/exec does not count.
	for _, site := range cpCalls {
		if callRunsBun(code[site.Start:site.ArgsStart], extractCallArgs(code, site.ArgsStart)) {
			consider(site.Start)
		}
	}
	// execa('bun', ['./x.mjs']) / execaCommand('bun run ./x').
	for _, loc := range execaMatches {
		if callRunsBun(code[loc[0]:loc[1]], extractCallArgs(code, loc[1])) {
			consider(loc[0])
		}
	}
	// shelljs .exec("bun run ..."), bound to a real shelljs receiver.
	for _, site := range shelljsCalls {
		if bunCommandStrRe.Match(extractCallArgs(code, site.ArgsStart)) {
			consider(site.Start)
		}
	}
	if best < 0 {
		return 0
	}
	return lineOf(code, best)
}

// findGitHubWriteChannel detects that the file WRITES or controls GitHub
// content: a GraphQL write mutation, an Octokit write-method call, or a
// REST contents/git-data endpoint paired with a PUT/PATCH/POST method.
// Returns the channel kind and the anchor line, or ("", 0) for none. Reads
// from GitHub (raw/gist/contents GET) are NOT a write channel -- those are
// a separate follow-up rule.
func findGitHubWriteChannel(view jsLexicalView, lowerCode []byte) (string, int) {
	code := view.Code
	// GraphQL write mutations: GitHub-specific names inside a query STRING,
	// AND with the GraphQL `mutation` keyword nearby (the actual mutation
	// body), AND a real send to GitHub's GraphQL API: the api.github.com
	// /graphql endpoint as the URL of an HTTP client call, or a `.graphql(`
	// client call. The send requirement keeps a fixture / example / unused
	// mutation constant (even one that also names the endpoint) from counting
	// as a channel.
	//
	// KNOWN LIMIT (lexical engine, no dataflow): the send and the mutation
	// string are correlated at FILE level, not bound to the same request
	// payload. A file that performs a real read-only GraphQL query AND also
	// carries a SEPARATE unused write-mutation fixture string would be treated
	// as a write channel. Binding the mutation literal to the request body
	// (which is routinely an indirected variable, `body: q`) needs variable
	// dataflow the analyzer does not do; the GitHub codex bot triages the
	// residual by real-world risk.
	graphqlSend := githubGraphQLEndpointSent(view, lowerCode) ||
		firstCodeTokenIndex(view, githubGraphQLCallRe) >= 0
	if graphqlSend {
		for _, n := range githubGraphQLMutationNeedles {
			if i := graphqlMutationIndex(view, lowerCode, n); i >= 0 {
				return "graphql-write", lineOf(code, i)
			}
		}
	}
	// Octokit write-method calls (code tokens): a GitHub write method on an
	// octokit / github / gh receiver chain.
	if idx := firstCodeTokenIndex(view, octokitWriteRe); idx >= 0 {
		return "octokit-write", lineOf(code, idx)
	}
	// Octokit request("POST /repos/.../git/blobs", ...) route form: method
	// + endpoint together in a route string passed to request(...). The
	// request( call must be real code, not a stringified example.
	if idx := firstCodeTokenIndex(view, githubRequestRouteRe); idx >= 0 {
		return "rest-write", lineOf(code, idx)
	}
	// REST contents / git-data endpoint reached by an HTTP client with a
	// write verb. Iterate ALL endpoint candidates so a read of /contents (for
	// a SHA) followed by a later write endpoint is still detected; a
	// read-only endpoint, or an endpoint that is merely data, is skipped.
	for _, re := range []*regexp.Regexp{githubContentsEndpointRe, githubGitDataEndpointRe} {
		for _, loc := range re.FindAllIndex(lowerCode, -1) {
			if restEndpointIsWrite(view, lowerCode, loc[0]) {
				return "rest-write", lineOf(code, loc[0])
			}
		}
	}
	return "", 0
}

// urlOptionKeys are the option keys whose value is a request URL, so a GitHub
// endpoint assigned to one of them is the request target (not body/data).
var urlOptionKeys = map[string]bool{
	"url": true, "uri": true, "baseurl": true, "endpoint": true, "href": true,
}

// httpClientRoots is the set of receiver roots recognised as HTTP clients on
// the raw-REST write path. This is intentionally FP-safe rather than
// exhaustive: an exotic or instance-named client (api.post, this.http.put) is
// NOT recognised here, so it produces a miss rather than a false write. The
// common malware shapes (octokit, GraphQL mutations) are caught by the
// dedicated detectors above; this path only supplements raw fetch/axios/got
// style calls to a GitHub contents / git-data endpoint.
var httpClientRoots = map[string]bool{
	"fetch": true, "axios": true, "got": true, "ky": true, "request": true,
	"superagent": true, "needle": true, "undici": true, "http": true, "https": true,
}

// stringRangeContaining binary-searches the (sorted) string interiors for the
// range containing idx, returning [start, end) and ok. Binary search keeps the
// per-endpoint lookup logarithmic, so a bundle with tens of thousands of
// string literals does not make the REST scan quadratic.
func stringRangeContaining(view jsLexicalView, idx int) (int, int, bool) {
	ranges := view.StringRanges
	lo, hi := 0, len(ranges)
	for lo < hi {
		mid := (lo + hi) / 2
		r := ranges[mid]
		if idx < r[0] {
			hi = mid
		} else if idx >= r[1] {
			lo = mid + 1
		} else {
			return r[0], r[1], true
		}
	}
	return 0, 0, false
}

// stringStartContaining returns the interior start of the string literal that
// contains idx, or -1 if idx is not inside a string.
func stringStartContaining(view jsLexicalView, idx int) int {
	if s, _, ok := stringRangeContaining(view, idx); ok {
		return s
	}
	return -1
}

// restEndpointIsWrite reports whether the GitHub REST endpoint string at idx
// is the target of an HTTP write request: the first argument of a recognised
// HTTP-client call (with a verb-specific helper like `.post`/`.put`, or a
// top-level `method: PUT/PATCH/POST` option), or the `url:`-keyed value of an
// options object that carries such a method. A GitHub path that is merely a
// body/data value, or the argument of a non-HTTP callee (console.log), is not
// a write.
func restEndpointIsWrite(view jsLexicalView, lowerCode []byte, idx int) bool {
	isVerbWrite, ok := urlBoundToHTTPClient(view, lowerCode, idx)
	if !ok {
		return false
	}
	// A verb-specific helper (.post/.put/.patch) is itself the write verb; a
	// generic client needs a top-level `method: PUT/PATCH/POST` option in the
	// same request.
	return isVerbWrite || writeMethodNear(view, idx)
}

// urlBoundToHTTPClient reports whether the URL string at idx is the request
// URL of a recognised HTTP client call -- the positional first argument
// (`client(URL, ...)`) or a url-ish option value in the client's FIRST
// (options) argument (`client({ url: URL })`) -- and, when so, whether the
// callee is a verb-specific write helper (.post/.put/.patch). A GitHub path
// that is merely a body/data value, or the argument of a non-HTTP callee
// (console.log), is not bound.
func urlBoundToHTTPClient(view jsLexicalView, lowerCode []byte, idx int) (isVerbWrite, ok bool) {
	strStart := stringStartContaining(view, idx)
	if strStart <= 0 {
		return false, false
	}
	// Step over the opening delimiter, then any whitespace, to the preceding
	// significant byte in the code.
	j := strStart - 2
	for j >= 0 && isJSSpace(lowerCode[j]) {
		j--
	}
	if j < 0 {
		return false, false
	}
	urlKeyed := false
	switch lowerCode[j] {
	case '(':
		// positional URL argument: allowed.
	case ':':
		if !precedingKeyIsURL(lowerCode, j) {
			return false, false
		}
		urlKeyed = true
	default:
		return false, false
	}
	code := view.Code
	gStart, _, found := enclosingGroupSpan(view, idx)
	if !found {
		return false, false
	}
	var callParen int
	if code[gStart] == '(' {
		callParen = gStart
	} else {
		// URL sits inside an object / array literal; the call paren encloses
		// it. A url-keyed value only counts when that object is the client's
		// FIRST argument (the options/config object), not a body/data
		// argument: axios.post('collector', { url: '<github>' }) writes to
		// the collector, and the github path is just data.
		pStart, _, ok2 := enclosingGroupSpan(view, gStart)
		if !ok2 || code[pStart] != '(' {
			return false, false
		}
		if urlKeyed && firstSignificantByteAfter(view, pStart) != gStart {
			return false, false
		}
		callParen = pStart
	}
	isClient, verb := classifyHTTPCallee(calleeBefore(lowerCode, callParen))
	if !isClient {
		return false, false
	}
	return verb, true
}

// githubGraphQLEndpointSent reports whether the api.github.com/graphql
// endpoint string is the request URL of a real HTTP client call (a genuine
// send), as opposed to an unused constant / fixture / documentation string.
func githubGraphQLEndpointSent(view jsLexicalView, lowerCode []byte) bool {
	needle := []byte("api.github.com/graphql")
	for from := 0; from < len(lowerCode); {
		i := bytes.Index(lowerCode[from:], needle)
		if i < 0 {
			return false
		}
		abs := from + i
		if _, ok := urlBoundToHTTPClient(view, lowerCode, abs); ok {
			return true
		}
		from = abs + 1
	}
	return false
}

// firstSignificantByteAfter returns the offset of the first non-whitespace
// byte after parenIdx, or the start of a string argument that begins there. A
// return value equal to an object's `{` offset means that object is the call's
// first argument.
func firstSignificantByteAfter(view jsLexicalView, parenIdx int) int {
	code := view.Code
	for i := parenIdx + 1; i < len(code); i++ {
		if view.InString(i) {
			return i
		}
		if isJSSpace(code[i]) {
			continue
		}
		return i
	}
	return -1
}

// lastCallMethod returns the lowercased method/identifier immediately before
// the `(` whose arguments begin at argsStart (e.g. "execsync" for
// `cp.execSync(`, "exec" for `require('child_process').exec(`). Used to apply
// shell-redirect parsing only to shell-interpreting calls.
func lastCallMethod(code []byte, argsStart int) string {
	j := argsStart - 2 // step over '(' then scan back
	for j >= 0 && isJSSpace(code[j]) {
		j--
	}
	end := j + 1
	for j >= 0 {
		c := code[j]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '$' {
			j--
			continue
		}
		break
	}
	if j+1 >= end {
		return ""
	}
	return strings.ToLower(string(code[j+1 : end]))
}

// calleeBefore returns the dotted callee token immediately before the `(` at
// parenIdx (e.g. "axios.post", "http.request", "console.log"), lowercased.
func calleeBefore(lowerCode []byte, parenIdx int) string {
	j := parenIdx - 1
	for j >= 0 && isJSSpace(lowerCode[j]) {
		j--
	}
	end := j + 1
	for j >= 0 && (isJSIdentByte(lowerCode[j]) || lowerCode[j] == '.') {
		j--
	}
	start := j + 1
	if start >= end {
		return ""
	}
	return strings.Trim(string(lowerCode[start:end]), ".")
}

// classifyHTTPCallee reports whether callee is a recognised HTTP client
// (isClient) and, if so, whether the callee is a verb-specific write helper
// such as `.post` / `.put` / `.patch` (isVerbWrite).
func classifyHTTPCallee(callee string) (isClient, isVerbWrite bool) {
	if callee == "" {
		return false, false
	}
	parts := strings.Split(callee, ".")
	if !httpClientRoots[parts[0]] {
		return false, false
	}
	last := parts[len(parts)-1]
	return true, last == "post" || last == "put" || last == "patch"
}

// precedingKeyIsURL reports whether the object key immediately before colonIdx
// is a url-ish option key (url / uri / baseURL / endpoint / href).
func precedingKeyIsURL(lowerCode []byte, colonIdx int) bool {
	j := colonIdx - 1
	for j >= 0 && isJSSpace(lowerCode[j]) {
		j--
	}
	if j >= 0 && (lowerCode[j] == '"' || lowerCode[j] == '\'' || lowerCode[j] == '`') {
		j--
	}
	end := j + 1
	for j >= 0 && isJSIdentByte(lowerCode[j]) {
		j--
	}
	start := j + 1
	if start >= end {
		return false
	}
	return urlOptionKeys[string(lowerCode[start:end])]
}

func isJSSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

func isJSIdentByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '_' || b == '$'
}

// graphqlMutationKeywordRe matches the GraphQL `mutation` operation keyword
// with word boundaries, so `mutationName` / `commentMutation` do not match.
var graphqlMutationKeywordRe = regexp.MustCompile(`(?i)\bmutation\b`)

// graphqlMutationInSameString reports whether the word-bounded GraphQL
// `mutation` keyword lives in the SAME string literal as the GitHub
// mutation-name occurrence at idx, binding the name to an actual GraphQL
// mutation body. This rejects free-text neighbours such as
// `const mutationName = 'createGist'`, where the name sits in one string and
// the substring `mutation` is an unrelated identifier outside it.
func graphqlMutationInSameString(view jsLexicalView, lowerCode []byte, idx int) bool {
	s, e, ok := stringRangeContaining(view, idx)
	if !ok {
		return false
	}
	return graphqlMutationKeywordRe.Match(lowerCode[s:e])
}

// graphqlMutationIndex returns the offset of the first occurrence of the
// lowercase GitHub mutation needle that lies inside a string interior AND
// has the GraphQL `mutation` keyword nearby (a real mutation body), or -1.
// It scans ALL occurrences, so an earlier harmless mention of the name
// (e.g. in a doc string) does not suppress a later real mutation.
func graphqlMutationIndex(view jsLexicalView, lowerCode []byte, needle string) int {
	n := []byte(needle)
	for from := 0; from < len(lowerCode); {
		i := bytes.Index(lowerCode[from:], n)
		if i < 0 {
			return -1
		}
		abs := from + i
		if view.InString(abs) && graphqlMutationInSameString(view, lowerCode, abs) {
			return abs
		}
		from = abs + 1
	}
	return -1
}

// enclosingGroupSpan returns the byte span [start, end) of the innermost
// bracket group ( (...) / {...} / [...] ) that encloses idx, skipping
// brackets that fall inside string interiors. It binds a fetch/axios URL to
// the SAME call argument list or options object as its `method:` option, so
// a write method belonging to a different request is not associated with this
// endpoint. Returns ok=false when idx is at top level (no enclosing group).
//
// The enclosing open is found by scanning BACKWARD from idx and stops at the
// nearest unmatched open bracket, so a flat sequence of calls (a generated
// bundle with thousands of endpoint literals) stays bounded per candidate
// instead of rescanning from the start of the file. The forward scan that
// finds the matching close is likewise bounded by the group span.
func enclosingGroupSpan(view jsLexicalView, idx int) (int, int, bool) {
	code := view.Code
	if idx > len(code) {
		idx = len(code)
	}
	open := -1
	depth := 0
	for i := idx - 1; i >= 0; i-- {
		if view.InString(i) {
			continue
		}
		switch code[i] {
		case ')', '}', ']':
			depth++
		case '(', '{', '[':
			if depth == 0 {
				open = i
			} else {
				depth--
			}
		}
		if open >= 0 {
			break
		}
	}
	if open < 0 {
		return 0, 0, false
	}
	// Everything between open and idx is balanced (the backward scan found
	// open at depth 0), so at idx we are exactly one level inside open.
	depth = 1
	for i := idx; i < len(code); i++ {
		if view.InString(i) {
			continue
		}
		switch code[i] {
		case '(', '{', '[':
			depth++
		case ')', '}', ']':
			depth--
			if depth == 0 {
				return open, i + 1, true
			}
		}
	}
	return open, len(code), true
}

// writeMethodNear reports whether a real PUT/PATCH/POST write-method option
// lives in the request options object of the GitHub endpoint at endpointIdx.
// The match must sit at the TOP LEVEL of that options object (brace depth 1
// within the enclosing call / object group), so a `method` field buried in a
// nested object -- e.g. `{ body: { method: 'POST' } }` on a read-only URL --
// is not mistaken for the HTTP verb.
func writeMethodNear(view jsLexicalView, endpointIdx int) bool {
	code := view.Code
	start, end, ok := enclosingGroupSpan(view, endpointIdx)
	if !ok {
		return false
	}
	for _, loc := range httpWriteMethodRe.FindAllIndex(code[start:end], -1) {
		p := start + loc[0]
		if !matchInCode(view, []int{p, start + loc[1]}) {
			continue
		}
		if braceDepthAt(view, start, p) == 1 {
			return true
		}
	}
	return false
}

// braceDepthAt returns the `{}` nesting depth at pos relative to start,
// counting only braces in code (string interiors skipped). A request options
// object opens exactly one brace, so its top-level fields sit at depth 1.
func braceDepthAt(view jsLexicalView, start, pos int) int {
	code := view.Code
	depth := 0
	for i := start; i < pos && i < len(code); i++ {
		if view.InString(i) {
			continue
		}
		switch code[i] {
		case '{':
			depth++
		case '}':
			depth--
		}
	}
	return depth
}

// detectGitHubC2 emits JS_GITHUB_C2_001 when the file uses GitHub as a
// write/control channel AND carries a strong partner that a legitimate
// GitHub-write tool (release / changeset bot) does NOT have. A bare
// GITHUB_TOKEN read, a payload body (content/sha/tree), or the GitHub
// channel itself are NOT partners -- that is the ordinary release-bot
// shape, and JS_CI_SECRET_HARVEST_001 already owns "secret to a sink".
//
// Execution is the SUSPICIOUS kind only -- install-time daemonization or a
// Bun second stage -- not any child_process call: release bots routinely
// shell out for git metadata (`execSync('git rev-parse HEAD')`), so bare
// child_process is not a partner release bots lack.
func detectGitHubC2(path string, m *metrics) *types.Finding {
	if !m.HasGitHubWriteChannel {
		return nil
	}
	exec := m.HasDaemonChain || m.HasBunExecution
	persistence := m.HasClaudePersistence || m.HasVSCodePersistence
	strongPartner := m.hasObfuscatorShape() || exec || persistence ||
		m.HasStrongSecretRead || m.HasSessionSink
	if !strongPartner {
		return nil
	}
	// CRITICAL: a non-GitHub secret read written through the GitHub channel
	// is the credential-exfil-via-GitHub shape (a release bot reads only
	// GITHUB_TOKEN, which is not a strong secret). Other strong partners
	// (obfuscation / execution / persistence / session exfil) stay HIGH.
	//
	// KNOWN LIMIT (lexical engine, no dataflow): the secret read and the
	// GitHub channel are correlated at FILE level, not bound to the same
	// payload. A release script that reads NPM_TOKEN to run `npm publish` AND
	// also writes a changelog to GitHub would escalate to CRITICAL even
	// though the token never reaches the GitHub write. Binding the secret to
	// the write payload needs variable dataflow the analyzer does not do; the
	// GitHub codex bot triages the residual by real-world risk.
	sev := types.SeverityHigh
	if m.HasStrongSecretRead {
		sev = types.SeverityCritical
	}
	line := m.LineGitHubChannel
	if line == 0 {
		line = 1
	}
	return &types.Finding{
		RuleID:   RuleGitHubC2,
		RuleName: "GitHub used as payload or command channel",
		Severity: sev,
		Category: "supply-chain",
		Description: "JavaScript writes or controls GitHub-hosted content (" + m.GitHubChannelKind +
			") and pairs it with a supply-chain signal: obfuscation, local execution, " +
			"persistence, a non-GitHub credential read, or an exfil sink. This is GitHub used " +
			"as a payload/command channel, not an ordinary repository operation; the Red Hat/" +
			"Miasma worm used the GitHub API to stage and control payloads. A normal release " +
			"bot (createCommitOnBranch + GITHUB_TOKEN + a content body) does not match.",
		FilePath:    path,
		Line:        line,
		MatchedText: "github write/control channel (" + m.GitHubChannelKind + ") + supply-chain partner",
		Analyzer:    AnalyzerName,
		Confidence:  0.85,
		Remediation: "Confirm why package code writes to GitHub during install or runtime. " +
			"Inspect the channel in a clean clone, rotate any non-GitHub credentials the " +
			"process could reach, and pin the dependency to a reviewed version.",
	}
}

// fsWriteCall records the first-argument (path) byte range of a verified fs
// write/append call. A path token inside [pathStart, pathEnd) is written to
// disk; the full call args (for content inspection) start at pathStart.
type fsWriteCall struct{ pathStart, pathEnd int }

// fsDataArg returns the second (data) argument bytes of an fs write call,
// given firstArgEndIdx (the comma or close paren ending the first/path arg).
// The data argument is what is written to disk; options and callbacks that
// follow are excluded. Returns nil when there is no data argument.
func fsDataArg(code []byte, firstArgEndIdx int, stringRanges [][2]int) []byte {
	if firstArgEndIdx < 0 || firstArgEndIdx >= len(code) || code[firstArgEndIdx] != ',' {
		return nil
	}
	start := firstArgEndIdx + 1
	depth := 1
	for i := start; i < len(code); i++ {
		if insideStringInterior(stringRanges, i) {
			continue
		}
		switch code[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if depth == 0 {
				return code[start:i]
			}
		case ',':
			if depth == 1 {
				return code[start:i]
			}
		}
	}
	return code[start:]
}

// collectFSWriteCalls returns every verified fs write/append call in stripped
// (comment-masked) code. Each call's receiver/alias/destructure is bound to a
// real fs / fs-extra / fs/promises import, so a local `writer.writeFileSync`
// or a stringified example is not counted. Shared by the DNS-TXT envs.txt
// staging check and the host-trust tamper detector.
func collectFSWriteCalls(stripped []byte, stringRanges [][2]int) []fsWriteCall {
	fsBindings := collectModuleBindings(stripped, stringRanges,
		fsModuleAliasRe, fsModuleAliasESMRe, fsDestructureRe, fsDestructureESMRe, fsModuleAliasESMCombinedRe)
	var calls []fsWriteCall
	add := func(matchEnd int) {
		openParen := matchEnd - 1
		argEnd := firstArgEnd(stripped, openParen, stringRanges)
		if argEnd <= openParen {
			return
		}
		calls = append(calls, fsWriteCall{openParen + 1, argEnd})
	}
	for _, mt := range fsWriteReceiverRe.FindAllSubmatchIndex(stripped, -1) {
		if insideStringInterior(stringRanges, mt[2]) {
			continue
		}
		recv := string(stripped[mt[2]:mt[3]])
		if !fsBindings.aliases[recv] && fsBindings.sourceByLocal[recv] != "promises" {
			continue
		}
		if !fsWriteMethodNames[string(stripped[mt[4]:mt[5]])] {
			continue
		}
		add(mt[1])
	}
	for _, mt := range fsWriteBareCallRe.FindAllSubmatchIndex(stripped, -1) {
		if insideStringInterior(stringRanges, mt[2]) {
			continue
		}
		if !fsWriteMethodNames[fsBindings.sourceByLocal[string(stripped[mt[2]:mt[3]])]] {
			continue
		}
		add(mt[1])
	}
	for _, mt := range fsPromisesWriteReceiverRe.FindAllSubmatchIndex(stripped, -1) {
		if insideStringInterior(stringRanges, mt[2]) {
			continue
		}
		recv := string(stripped[mt[2]:mt[3]])
		if !fsBindings.aliases[recv] && fsBindings.sourceByLocal[recv] != "promises" {
			continue
		}
		if !fsWriteMethodNames[string(stripped[mt[4]:mt[5]])] {
			continue
		}
		add(mt[1])
	}
	for _, mt := range inlineRequireFsWriteRe.FindAllSubmatchIndex(stripped, -1) {
		if insideStringInterior(stringRanges, mt[2]) {
			continue
		}
		add(mt[1])
	}
	return calls
}

// Sensitive host-trust surfaces, grouped by how they are gated.
//
// A path is `exact` when it names a single file: it must be followed by a
// path boundary so /etc/sudoers does NOT match /etc/sudoers.bak and /etc/hosts
// does NOT match /etc/hosts.allow. A non-exact token ends in `/` and is a
// directory prefix (its trailing slash is the boundary), so any file written
// under it counts.
type hostPath struct {
	token string
	exact bool
}

// sudoers: /etc/sudoers (the file) and /etc/sudoers.d/* (the drop-in dir).
var sudoersPaths = []hostPath{
	{"/etc/sudoers.d/", false},
	{"/etc/sudoers", true},
}

// loaderTrustPaths: writes that change library preload, certificate trust,
// the SSH daemon, or the global shell profile. HIGH on the write alone;
// CRITICAL only with a strong partner.
var loaderTrustPaths = []hostPath{
	{"/etc/ld.so.preload", true},
	{"/etc/profile.d/", false},
	{"/etc/profile", true},
	{"/usr/local/share/ca-certificates/", false},
	{"/etc/ssl/certs/", false},
	{"/etc/ssh/sshd_config", true},
}

// netResolutionPaths: name-resolution surfaces. A write fires ONLY when the
// content names a sensitive domain (redirecting registry/forge traffic) or a
// strong partner is present -- these files are edited by legitimate
// container/dev tooling too.
var netResolutionPaths = []hostPath{
	{"/etc/hosts", true},
	{"/etc/resolv.conf", true},
}

func allHostPaths() []hostPath {
	var all []hostPath
	all = append(all, sudoersPaths...)
	all = append(all, loaderTrustPaths...)
	all = append(all, netResolutionPaths...)
	return all
}

// isPathByte reports whether c can be part of a filesystem path component, so
// it would extend a path token in either direction.
func isPathByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '.' || c == '_' || c == '-' || c == '/'
}

// hostPathBoundaryOK reports whether the byte after an exact path token at
// [loc, loc+len(token)) is a path boundary (not a filename-continuation
// character), so /etc/sudoers matches but /etc/sudoers.bak does not.
func hostPathBoundaryOK(code []byte, end int) bool {
	return end >= len(code) || !isPathByte(code[end])
}

// pathExtendedByConcat reports whether an exact path token is extended into a
// different file by a JS expression: a string concatenation
// (`'/etc/sudoers' + '.bak'`) or a template interpolation
// (`/etc/sudoers${'.bak'}`), both evaluating to /etc/sudoers.bak. end is the
// byte right after the token.
func pathExtendedByConcat(buf []byte, end int) bool {
	if end >= len(buf) {
		return false
	}
	c := buf[end]
	// `${...}` template interpolation immediately after the token.
	if c == '$' && end+1 < len(buf) && buf[end+1] == '{' {
		return true
	}
	// A closing quote followed by `+` string concatenation.
	if c != '\'' && c != '"' && c != '`' {
		return false
	}
	j := end + 1
	for j < len(buf) && (buf[j] == ' ' || buf[j] == '\t' || buf[j] == '\n' || buf[j] == '\r') {
		j++
	}
	return j < len(buf) && buf[j] == '+'
}

// sudoersGrantRe matches the distinctive sudoers privilege-grant directives
// that escalate a sudoers write to CRITICAL on their own: NOPASSWD,
// ALL=(ALL) / ALL=(ALL:ALL), %sudo, %wheel. Broad tokens (root, /bin/bash,
// node, curl ...) are deliberately excluded -- they appear in legitimate
// sudoers data and provisioning scripts, so they stay HIGH unless a strong
// partner is present.
var sudoersGrantRe = regexp.MustCompile(`(?i)nopasswd|all\s*=\s*\(\s*all(?:\s*:\s*all)?\s*\)|%sudo\b|%wheel\b`)

// hostTamperSensitiveDomains gate a /etc/hosts or /etc/resolv.conf write:
// pinning one of these to an attacker-controlled address redirects package,
// registry, or forge traffic.
var hostTamperSensitiveDomains = []string{
	"github.com", "registry.npmjs.org", "npmjs.org", "pypi.org", "files.pythonhosted.org",
}

// shellWriteToPathRes maps each sensitive path token to a regex that matches a
// shell WRITE toward it: a redirect (`> ` / `>> `), `tee [-a]`, or `sed -i`
// in-place edit. Reads (`cat`, `visudo -c`, `chmod`) do not match. Exact-file
// tokens carry a trailing path-boundary class so /etc/sudoers does not match
// /etc/sudoers.bak.
var shellWriteToPathRes = buildShellWriteToPathRes()

func buildShellWriteToPathRes() map[string]*regexp.Regexp {
	out := map[string]*regexp.Regexp{}
	// q allows an optional opening quote on the path operand (`>> '/etc/x'`,
	// `tee "/etc/x"`); the closing quote is already covered by the boundary
	// class for exact tokens (a quote is not a path byte).
	q := `['"` + "`" + `]?`
	// sep is a leading path boundary for the sed form, whose lazy pre-path
	// matcher would otherwise consume a leading path segment and match an
	// embedded /etc/... suffix (e.g. /tmp/etc/...). The redirect and tee forms
	// anchor the path immediately after the operator, so they need no sep.
	sep := `[\s'"` + "`" + `]`
	for _, hp := range allHostPaths() {
		p := q + regexp.QuoteMeta(hp.token)
		boundary := ""
		if hp.exact {
			boundary = `(?:[^a-zA-Z0-9._/-]|$)`
		}
		out[hp.token] = regexp.MustCompile(`(?i)(?:>>?\s*` + p + boundary +
			`|\btee\b\s+(?:-a\s+|--append\s+)?` + p + boundary +
			`|\bsed\b[^\n\r;|&]*?-i[^\n\r;|&]*?` + sep + p + boundary + `)`)
	}
	return out
}

// shellProgFirstArgRe matches when the FIRST argument (the spawned program) is
// a shell, and shellDashCFlagRe confirms a `-c` flag follows. Together they
// recognise the `spawn('sh', ['-c', '<script>'])` form, where the script
// argument is interpreted by that shell even though the call is a program API.
// Anchoring to the first argument rejects literal argv data like
// `spawn('echo', ['sh', '-c', ...])`. Bounded form recognition, not a parser.
var shellProgFirstArgRe = regexp.MustCompile(`(?i)^\s*['"` + "`" + `](?:/(?:usr/)?bin/)?(?:sh|bash|dash|zsh|ash)['"` + "`" + `]`)

// shellDashCFlagRe matches a `-c` shell flag, including clustered short-option
// forms (`-lc`, `-ec`), where the command string still follows the cluster.
var shellDashCFlagRe = regexp.MustCompile(`['"` + "`" + `]-[a-z]*c[a-z]*['"` + "`" + `]`)

// shellCommandStrRe matches a single command STRING that invokes a shell with
// `-c` (`execaCommand('sh -c "..."')`, `'bash -e -c "..."'`), allowing leading
// option tokens before -c; the rest of the string is interpreted by that
// shell.
var shellCommandStrRe = regexp.MustCompile(`(?i)^\s*['"` + "`" + `]\s*(?:/(?:usr/)?bin/)?(?:sh|bash|dash|zsh|ash)(?:\s+-[a-z]+)*\s+-[a-z]*c[a-z]*\b`)

func spawnRunsShell(firstArg, args []byte) bool {
	return shellProgFirstArgRe.Match(firstArg) && shellDashCFlagRe.Match(args)
}

// inlineDashCRe matches an UNQUOTED `-c` (or clustered `-lc`) flag inside a
// single command string (`sh -c "<script>"`).
var inlineDashCRe = regexp.MustCompile(`(?i)(?:^|\s)-[a-z]*c[a-z]*\s`)

// dashCBareRe matches a bare shell `-c` flag (possibly clustered: -lc, -ec).
var dashCBareRe = regexp.MustCompile(`(?i)^-[a-z]*c[a-z]*$`)

// shellScriptFromArgv returns the executed script of an argv-array shell
// invocation (`'sh', ['-c', '<cmd>', ...]`). Leading OPTION tokens (starting
// with `-`, e.g. `-e`) are allowed before `-c`; the first NON-option element
// ends option parsing, so in `['script.sh', '-c', ...]` the program runs
// script.sh and -c is a positional parameter (rejected). The script is the
// array element right after the -c flag; later elements are $0,$1,... and are
// excluded. Models the -c calling convention, not a full shell parser.
func shellScriptFromArgv(args []byte) ([]byte, bool) {
	lb := bytes.IndexByte(args, '[')
	if lb < 0 {
		return nil, false
	}
	pos := lb + 1
	for {
		flag, end, ok := shellStringLiteralAt(args, pos)
		if !ok {
			return nil, false
		}
		if dashCBareRe.Match(flag) {
			cmd, _, ok := shellStringLiteralAt(args, end)
			if !ok {
				return nil, false
			}
			return cmd, true
		}
		// A non-option token (a script file / program) before -c means -c is
		// a positional parameter, not the shell option.
		if len(flag) == 0 || flag[0] != '-' {
			return nil, false
		}
		pos = end
	}
}

// shellScriptFromCommandString returns the executed remainder of a single
// command string that starts with a shell + `-c` (`sh -c "<cmd>"`).
func shellScriptFromCommandString(s []byte) ([]byte, bool) {
	if m := inlineDashCRe.FindIndex(s); m != nil {
		return s[m[1]:], true
	}
	return nil, false
}

// shellStringLiteralAt returns the interior and the index past the closing
// quote of the next string literal at or after from, skipping only argument
// separators (whitespace, comma, `[`); a non-string token (a variable) yields
// ok=false so an unrelated later string is not grabbed.
func shellStringLiteralAt(b []byte, from int) (content []byte, end int, ok bool) {
	i := from
	for i < len(b) {
		c := b[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',' || c == '[' {
			i++
			continue
		}
		break
	}
	if i >= len(b) || (b[i] != '\'' && b[i] != '"' && b[i] != '`') {
		return nil, 0, false
	}
	q := b[i]
	for j := i + 1; j < len(b); j++ {
		if b[j] == '\\' {
			j++
			continue
		}
		if b[j] == q {
			return b[i+1 : j], j + 1, true
		}
	}
	return nil, 0, false
}

// hostTamperStrongPartner reports the strong supply-chain partner signals that
// escalate a host-trust write to CRITICAL (and that the net-resolution paths
// require to fire absent a sensitive domain).
func hostTamperStrongPartner(m *metrics) bool {
	return m.HasCISecretRead || m.HasNetworkSink || m.HasDaemonChain ||
		m.HasBunExecution || m.HasGitHubWriteChannel || m.HasSessionSink ||
		m.hasObfuscatorShape()
}

// lastShellSegment returns the tail of pre after the last command separator
// (`;`, newline, `&`/`&&`, `||`), which is the pipeline segment that feeds the
// redirect/tee at the end of pre. A single `|` pipe is NOT a separator (it
// feeds the next stage, e.g. `echo X | sudo tee FILE`), so the piped data is
// kept. This binds the domain/grant gate to the data actually written and
// excludes tokens from an earlier unrelated command. Not quote-aware: a
// separator char inside a quoted argument is a documented limit.
func lastShellSegment(pre []byte) []byte {
	last := -1
	for i := 0; i < len(pre); i++ {
		switch pre[i] {
		case ';', '\n', '\r', '&':
			last = i
		case '|':
			if i+1 < len(pre) && pre[i+1] == '|' {
				last = i + 1
				i++
			}
		}
	}
	return pre[last+1:]
}

func containsSensitiveDomain(b []byte) bool {
	lb := bytes.ToLower(b)
	for _, d := range hostTamperSensitiveDomains {
		db := []byte(d)
		for from := 0; from < len(lb); {
			i := bytes.Index(lb[from:], db)
			if i < 0 {
				break
			}
			at := from + i
			// Require domain-label boundaries so api.github.com matches (the
			// preceding '.' is a subdomain separator) but notgithub.com and
			// github.com.evil do not. A label byte is [a-z0-9-]; the leading
			// byte may also not be '.'-less continuation, and the trailing
			// byte may not extend the domain ('.' would add another label).
			leadOK := at == 0 || !isDomainLabelByte(lb[at-1])
			end := at + len(db)
			trailOK := end >= len(lb) || (!isDomainLabelByte(lb[end]) && lb[end] != '.')
			if leadOK && trailOK {
				return true
			}
			from = at + 1
		}
	}
	return false
}

func isDomainLabelByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-'
}

// detectHostTamper emits JS_SUDOERS_TAMPER_001 / JS_HOST_TRUST_TAMPER_001 when
// package code performs a REAL write to a sensitive host surface (a bound fs
// write whose path argument is the surface, or a bound child_process / execa /
// shelljs command that redirects / tees / sed -i's into it). It is
// self-contained like detectDNSTXTExfil: it recomputes the lexical view and
// call sites from content and reads only the partner booleans off m.
func detectHostTamper(path string, m *metrics, content []byte) []types.Finding {
	view := newJSLexicalView(content)
	code := view.Code
	stringRanges := view.StringRanges
	fsCalls := collectFSWriteCalls(code, stringRanges)
	cpCalls := collectChildProcessCalls(code)
	shelljsCalls := collectShelljsExecCalls(code)
	execaMatches := execaCallRe.FindAllIndex(code, -1)

	// Only shell-INTERPRETING calls parse redirects: child_process exec /
	// execSync run `/bin/sh -c`, and shelljs.exec runs a shell. Program APIs
	// (spawn, spawnSync, execFile, execFileSync) and execa (no shell by
	// default) pass their arguments literally, so a `>>`-looking string there
	// is a plain argument, not a redirect.
	// Only the FIRST argument is interpreted by the shell; a redirect-looking
	// string in an options/env/callback argument is not a write. Bound to the
	// first arg via firstArgEnd.
	//
	// KNOWN LIMITS (no shell parser, per the rule's scope):
	//   - the redirect/tee scan is not shell-quote-aware, so a command that
	//     merely PRINTS a quoted redirect string (`echo "x >> /etc/x"`) can
	//     over-fire, and distinguishing it from a real quoted tee target needs
	//     shell-quote parsing the analyzer does not do;
	//   - content is bound to the FIRST redirect/tee per command, so a second
	//     write to the same path in one command, and a payload that lives
	//     inside a `sed` script rather than before the operator, are not
	//     inspected for the domain/grant gate.
	var shellArgs [][]byte
	var shellStarts []int
	addShell := func(start, argsStart int) {
		if start < 0 || view.InString(start) {
			return
		}
		argEnd := firstArgEnd(code, argsStart-1, stringRanges)
		if argEnd <= argsStart {
			return
		}
		shellArgs = append(shellArgs, code[argsStart:argEnd])
		shellStarts = append(shellStarts, start)
	}
	for _, s := range cpCalls {
		switch s.Method {
		case "exec", "execsync":
			// exec / execSync run `/bin/sh -c <first arg>`.
			addShell(s.Start, s.ArgsStart)
		case "spawn", "spawnsync", "execfile", "execfilesync":
			// A program API still runs a shell when the program IS a shell
			// with -c; only the argument right after -c is the script (later
			// array elements are positional params $0,$1,...), so scan that.
			if s.Start < 0 || view.InString(s.Start) {
				continue
			}
			full := extractCallArgs(code, s.ArgsStart)
			argEnd := firstArgEnd(code, s.ArgsStart-1, stringRanges)
			if argEnd <= s.ArgsStart {
				continue
			}
			if spawnRunsShell(code[s.ArgsStart:argEnd], full) {
				if script, ok := shellScriptFromArgv(full); ok {
					shellArgs = append(shellArgs, script)
					shellStarts = append(shellStarts, s.Start)
				}
			}
		}
	}
	for _, s := range shelljsCalls {
		addShell(s.Start, s.ArgsStart)
	}
	// execa shells out only via execa('sh',['-c',...]) or
	// execaCommand('sh -c "..."'); a plain execa parses args without a shell.
	for _, loc := range execaMatches {
		start, argsStart := loc[0], loc[1]
		if view.InString(start) {
			continue
		}
		argEnd := firstArgEnd(code, argsStart-1, stringRanges)
		if argEnd <= argsStart {
			continue
		}
		full := extractCallArgs(code, argsStart)
		firstArg := code[argsStart:argEnd]
		var script []byte
		var ok bool
		switch {
		case spawnRunsShell(firstArg, full):
			script, ok = shellScriptFromArgv(full)
		case shellCommandStrRe.Match(firstArg):
			script, ok = shellScriptFromCommandString(firstArg)
		}
		if ok {
			shellArgs = append(shellArgs, script)
			shellStarts = append(shellStarts, start)
		}
	}

	indexAll := func(needle string) []int {
		var idxs []int
		nb := []byte(needle)
		for from := 0; from < len(code); {
			i := bytes.Index(code[from:], nb)
			if i < 0 {
				break
			}
			idxs = append(idxs, from+i)
			from = from + i + 1
		}
		return idxs
	}

	// boundWrites returns, for every real write targeting the path, the byte
	// span of the actual written CONTENT (so a grant/domain token elsewhere
	// does not count) plus the earliest matched offset. For an fs write the
	// content is the data (2nd) argument; for a shell write it is the command
	// portion BEFORE the redirect/tee operator (the echoed/piped data), which
	// excludes a domain sitting after the redirect in an unrelated `; curl ...`
	// segment. An exact-file path must satisfy a trailing path boundary so
	// /etc/sudoers does not match /etc/sudoers.bak.
	boundWrites := func(hp hostPath) (contentSpans [][]byte, firstPos int) {
		firstPos = -1
		for _, loc := range indexAll(hp.token) {
			if hp.exact && (!hostPathBoundaryOK(code, loc+len(hp.token)) ||
				pathExtendedByConcat(code, loc+len(hp.token))) {
				continue
			}
			for _, c := range fsCalls {
				if loc < c.pathStart || loc >= c.pathEnd {
					continue
				}
				// The path argument must be a STANDALONE string literal whose
				// content starts with the token, so a prefix concatenation
				// (tmp + '/etc/x'), a template prefix (`${tmp}/etc/x`), or an
				// in-string prefix (/myapp/etc/x) is not treated as a write to
				// the host path. The opening quote sits at the first non-space
				// byte of the argument and the token starts right after it.
				q := c.pathStart
				for q < c.pathEnd && (code[q] == ' ' || code[q] == '\t' || code[q] == '\n' || code[q] == '\r') {
					q++
				}
				if q >= c.pathEnd || (code[q] != '\'' && code[q] != '"' && code[q] != '`') || loc != q+1 {
					break
				}
				contentSpans = append(contentSpans, fsDataArg(code, c.pathEnd, stringRanges))
				if firstPos < 0 || loc < firstPos {
					firstPos = loc
				}
				break
			}
		}
		if re := shellWriteToPathRes[hp.token]; re != nil {
			for i, args := range shellArgs {
				m := re.FindIndex(args)
				if m == nil {
					continue
				}
				// For an exact token the match consumes a trailing boundary
				// byte (m[1]-1); reject a JS concat that extends the path
				// (`'... >> /etc/sudoers' + '.bak'`).
				if hp.exact && pathExtendedByConcat(args, m[1]-1) {
					continue
				}
				contentSpans = append(contentSpans, lastShellSegment(args[:m[0]]))
				if firstPos < 0 || shellStarts[i] < firstPos {
					firstPos = shellStarts[i]
				}
			}
		}
		return contentSpans, firstPos
	}

	lineFrom := func(pos int) int {
		if pos < 0 {
			return 1
		}
		return lineOf(code, pos)
	}

	strong := hostTamperStrongPartner(m)
	var out []types.Finding

	// JS_SUDOERS_TAMPER_001
	var sudoersSpans [][]byte
	sudoersPos := -1
	for _, hp := range sudoersPaths {
		spans, pos := boundWrites(hp)
		if len(spans) == 0 {
			continue
		}
		sudoersSpans = append(sudoersSpans, spans...)
		if sudoersPos < 0 || (pos >= 0 && pos < sudoersPos) {
			sudoersPos = pos
		}
	}
	if len(sudoersSpans) > 0 {
		grant := false
		for _, s := range sudoersSpans {
			if sudoersGrantRe.Match(s) {
				grant = true
				break
			}
		}
		sev := types.SeverityHigh
		if grant || strong {
			sev = types.SeverityCritical
		}
		out = append(out, types.Finding{
			RuleID:   RuleSudoersTamper,
			RuleName: "Sudoers privilege tampering",
			Severity: sev,
			Category: "supply-chain",
			Description: "Package JavaScript writes to /etc/sudoers or /etc/sudoers.d/* " +
				"during install or runtime, changing who can run commands as root. A bound " +
				"fs write or a shell redirect/tee/sed -i targets the sudoers surface. " +
				"CRITICAL when the written content grants passwordless or unrestricted sudo " +
				"(NOPASSWD, ALL=(ALL), %sudo, %wheel) or a strong supply-chain partner is " +
				"present. Validation only (visudo -c) and chmod without a write do not match.",
			FilePath:    path,
			Line:        lineFrom(sudoersPos),
			MatchedText: "write to sudoers surface",
			Analyzer:    AnalyzerName,
			Confidence:  0.85,
			Remediation: "Package install/runtime code has no legitimate reason to edit " +
				"sudoers. Inspect the file in a clean clone, remove the package, and audit " +
				"the host's sudoers configuration for unauthorized grants.",
		})
	}

	// JS_HOST_TRUST_TAMPER_001
	hostHit := false
	hostPos := -1
	note := func(pos int) {
		hostHit = true
		if hostPos < 0 || (pos >= 0 && pos < hostPos) {
			hostPos = pos
		}
	}
	for _, hp := range loaderTrustPaths {
		spans, pos := boundWrites(hp)
		if len(spans) > 0 {
			note(pos)
		}
	}
	for _, hp := range netResolutionPaths {
		spans, pos := boundWrites(hp)
		if len(spans) == 0 {
			continue
		}
		// The sensitive domain must be in the WRITTEN content (fs data arg or
		// the pre-redirect shell segment), so a domain in an unrelated command
		// segment does not satisfy the gate. Absent a domain, a strong partner
		// is required.
		domain := false
		for _, s := range spans {
			if containsSensitiveDomain(s) {
				domain = true
				break
			}
		}
		if domain || strong {
			note(pos)
		}
	}
	if hostHit {
		sev := types.SeverityHigh
		if strong {
			sev = types.SeverityCritical
		}
		out = append(out, types.Finding{
			RuleID:   RuleHostTrustTamper,
			RuleName: "Host trust surface tampering",
			Severity: sev,
			Category: "supply-chain",
			Description: "Package JavaScript writes to a host trust surface: the dynamic " +
				"linker preload (/etc/ld.so.preload), a CA certificate store, the SSH daemon " +
				"config, the global shell profile, or name resolution (/etc/hosts, " +
				"/etc/resolv.conf) pointed at a sensitive domain. These writes change code " +
				"loading, certificate trust, or where registry/forge traffic goes. CRITICAL " +
				"when paired with a strong supply-chain partner (secret read, exfil sink, " +
				"daemonization, Bun stage, GitHub channel, session sink, or obfuscation).",
			FilePath:    path,
			Line:        lineFrom(hostPos),
			MatchedText: "write to host trust surface",
			Analyzer:    AnalyzerName,
			Confidence:  0.8,
			Remediation: "Package code should not modify loader, certificate, SSH, profile, " +
				"or resolver configuration. Inspect the file in a clean clone, remove the " +
				"package, and audit the affected host surface for tampering.",
		})
	}
	return out
}

// collectShelljsExecCalls returns the call sites of real shelljs `.exec(...)`
// invocations: an inline require('shelljs').exec(...) or an alias bound to
// shelljs. Used both to detect a Bun command run via shelljs and to bind
// host data indicators (a publish/exfil URL inside sh.exec('...')).
func collectShelljsExecCalls(code []byte) []cpCallSite {
	var sites []cpCallSite
	// A shelljs binding or call quoted inside a string literal is text, not a
	// real import; skip those (mirrors collectChildProcessCalls).
	sr := jsStringInteriors(code)
	for _, loc := range shelljsInlineExecRe.FindAllIndex(code, -1) {
		if insideStringInterior(sr, loc[0]) {
			continue
		}
		sites = append(sites, cpCallSite{Start: loc[0], ArgsStart: loc[1]})
	}
	aliases := map[string]bool{}
	for _, mm := range shelljsAliasAssignRe.FindAllSubmatchIndex(code, -1) {
		if insideStringInterior(sr, mm[2]) {
			continue
		}
		aliases[string(code[mm[2]:mm[3]])] = true
	}
	for _, mm := range shelljsAliasESMRe.FindAllSubmatchIndex(code, -1) {
		if insideStringInterior(sr, mm[2]) {
			continue
		}
		aliases[string(code[mm[2]:mm[3]])] = true
	}
	if len(aliases) > 0 {
		for _, mm := range aliasExecCallRe.FindAllSubmatchIndex(code, -1) {
			if aliases[string(code[mm[2]:mm[3]])] {
				// mm[2] is the alias identifier start (mm[0] is the leading
				// boundary char from jsIdentBoundary); anchor the site there.
				sites = append(sites, cpCallSite{Start: mm[2], ArgsStart: mm[1]})
			}
		}
	}
	return sites
}

// findNetworkAliasSink walks imports of http/https/net and reports
// the line of the first <alias>.<method>(...) call against any of
// the imported aliases. The alias set is built from real require/
// import statements so an unrelated object named `h` does not trip
// the rule. Returns 0 when no alias has been imported or no aliased
// call appears.
func findNetworkAliasSink(content []byte) int {
	aliases := map[string]bool{}
	for _, m := range httpModuleAliasAssignRe.FindAllSubmatchIndex(content, -1) {
		aliases[string(content[m[2]:m[3]])] = true
	}
	for _, m := range httpModuleAliasESMRe.FindAllSubmatchIndex(content, -1) {
		aliases[string(content[m[2]:m[3]])] = true
	}
	if len(aliases) == 0 {
		return 0
	}
	for _, m := range identifierHTTPMethodCallRe.FindAllSubmatchIndex(content, -1) {
		if aliases[string(content[m[2]:m[3]])] {
			return lineOf(content, m[2])
		}
	}
	return 0
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

// inlineRequireReceiverRe matches a child_process method call whose
// receiver is the inline require chain itself, so the binding is
// unambiguous. Aliases bound via `const cp = require(...)` are
// discovered dynamically (see collectChildProcessAliases) and
// matched separately.
var inlineRequireReceiverRe = regexp.MustCompile(
	`require\s*\(\s*['"](?:node:)?child_process['"]\s*\)` +
		`\s*\.\s*(?:spawn|spawnSync|fork|exec|execSync|execFile|execFileSync)\s*\(`,
)

// childProcessAliasAssignRe captures the local variable that gets
// bound to the imported child_process module via require:
//
//	const cp = require('child_process')
//	let _cp = require("node:child_process")
//
// Submatch 1 is the local name.
// childProcessAliasAssignRe binds a local name to child_process. It
// accepts both the leading-declarator form (`const cp = require(...)`) and
// a declarator-continuation / sequence form (`const fs = ..., cp =
// require(...)`), so a multi-declarator const still binds the alias. The
// `= require('child_process')` tail keeps it from matching anything else.
var childProcessAliasAssignRe = regexp.MustCompile(
	`(?:(?:const|let|var)\s+|,\s*)([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*['"](?:node:)?child_process['"]\s*\)`,
)

// childProcessAliasESMRe captures the local variable bound via an
// ESM default or namespace import:
//
//	import cp from 'child_process'
//	import * as cp from 'node:child_process'
//
// Submatch 1 is the local name.
var childProcessAliasESMRe = regexp.MustCompile(
	`import\s+(?:\*\s+as\s+)?([A-Za-z_$][\w$]*)\s+from\s*['"](?:node:)?child_process['"]`,
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
	"fork": true,
	"exec": true, "execSync": true,
	"execFile": true, "execFileSync": true,
}

// identifierCPMethodCallRe captures `<identifier>.<cp-method>(` for
// any JS identifier, including ones beginning with `$`. The caller
// filters submatch 1 (the identifier) through the discovered alias
// set so unrelated objects do not satisfy the receiver match.
var identifierCPMethodCallRe = regexp.MustCompile(
	jsIdentBoundary + `([A-Za-z_$][\w$]*)\s*\.\s*(?:spawn|spawnSync|fork|exec|execSync|execFile|execFileSync)\s*\(`,
)

// identifierHTTPMethodCallRe captures `<identifier>.<method>(` for
// the http / https / net family. Caller filters submatch 1 through
// the discovered alias set.
var identifierHTTPMethodCallRe = regexp.MustCompile(
	jsIdentBoundary + `([A-Za-z_$][\w$]*)\s*\.\s*(?:request|get|post|put|connect|createConnection)\s*\(`,
)

// envReadRe captures direct env-variable reads in all the forms a
// real payload uses:
//
//	process.env.NAME
//	process.env?.NAME           (optional chaining)
//	process.env['NAME']         (string key)
//	process.env["NAME"]
//	process.env[`NAME`]         (template-literal key)
var envReadRe = regexp.MustCompile("process\\.env\\s*(?:\\??\\.|\\[\\s*['\"\x60])([A-Z][A-Z0-9_]+)")

// jsIdentBoundary is the leading-context fragment used for runtime
// alias regexes. JavaScript identifiers include `$`, so a literal
// regex `\b` does not establish a boundary before `$cp` (`$` is
// non-word in RE2's `\b` definition). Matching an explicit
// non-identifier character (or start-of-input) captures the
// boundary without requiring a lookbehind.
const jsIdentBoundary = `(?:^|[^A-Za-z0-9_$.])`

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
// dynamic forms: `'/mem'`, `"/maps"`, “ `/cmdline` “, and the
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
// socket call to an external endpoint via a fixed name (fetch, axios,
// got, http/https/net used as the literal module identifier, or the
// inline require chain). Aliased forms (`const h = require('https'); h.request(...)`)
// are handled separately by findNetworkAliasSink so the analyzer
// follows the same alias-discovery approach used for child_process.
//
// `fetch` is guarded with jsIdentBoundary (not `\b`) so that a local
// method call like `cache.fetch(...)` does not satisfy the sink: the
// `.` before fetch is in the exclusion set. The other alternations
// already contain a literal `.` and so cannot collide with local
// methods of the same name.
var networkSinkRe = regexp.MustCompile(
	`(?i)(?:` +
		jsIdentBoundary + `fetch\s*\(` +
		`|\baxios\.(?:post|put|request|get)\s*\(` +
		`|\bgot\.(?:post|put|get)\s*\(` +
		`|\bhttp\.request\s*\(|\bhttps\.(?:request|get)\s*\(` +
		`|\bnet\.connect\s*\(|\bnet\.createconnection\s*\(` +
		`|\bxmlhttprequest\s*\(` +
		// require chain variants: require('https').{request,get}(...)
		// and node: scheme. Single- and double-quoted module names.
		`|require\s*\(\s*['"](?:node:)?https?['"]\s*\)\s*\.\s*(?:request|get)\s*\(` +
		`)`,
)

// httpModuleAliasAssignRe captures local names bound to the http,
// https, or net modules via require, e.g.
// `const h = require('https')`, `let net = require('node:net')`.
// Submatch 1 is the local name.
var httpModuleAliasAssignRe = regexp.MustCompile(
	`(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*['"](?:node:)?(?:http|https|net)['"]\s*\)`,
)

// httpModuleAliasESMRe captures ESM default and namespace imports of
// http / https / net.
var httpModuleAliasESMRe = regexp.MustCompile(
	`import\s+(?:\*\s+as\s+)?([A-Za-z_$][\w$]*)\s+from\s*['"](?:node:)?(?:http|https|net)['"]`,
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

// githubGraphQLCallRe matches a `.graphql(` client call (octokit.graphql,
// graphqlClient.graphql), the second way a GitHub GraphQL mutation is sent
// without the literal api.github.com/graphql endpoint string.
var githubGraphQLCallRe = regexp.MustCompile(`(?i)\.\s*graphql\s*\(`)

// GitHub-C2 write/control channel signals (JS_GITHUB_C2_001).
//
// githubGraphQLMutationNeedles are GitHub-specific GraphQL write mutations
// that live inside query STRINGS, so they are matched by presence on
// comment-masked code. createRef / updateRef are DELIBERATELY excluded:
// the bare names collide with React.createRef / useRef and would
// false-positive across ordinary front-end code; the GitHub ref-write path
// is covered instead by the REST /git/refs endpoint + write-method check.
var githubGraphQLMutationNeedles = []string{
	"createcommitonbranch",
	"creategist",
}

// githubContentsEndpointRe / githubGitDataEndpointRe match GitHub REST
// write targets. Both require the api.github.com HOST plus the full
// /repos/<owner>/<repo>/ prefix, so a non-GitHub service that happens to use
// a GitHub-shaped path (internal.example/repos/o/r/contents/f) is not
// mistaken for a GitHub endpoint. They are write targets when paired with a
// PUT/PATCH/POST. (A GitHub Enterprise host uses /api/v3/repos/... and is not
// matched here -- the FP-safe direction for a brand-new rule; octokit calls
// against GHE are still covered by the Octokit write-method detectors.)
var githubContentsEndpointRe = regexp.MustCompile(`(?i)api\.github\.com/repos/[^/'"` + "`" + `\s]+/[^/'"` + "`" + `\s]+/contents/`)
var githubGitDataEndpointRe = regexp.MustCompile(`(?i)api\.github\.com/repos/[^/'"` + "`" + `\s]+/[^/'"` + "`" + `\s]+/git/(?:blobs|trees|commits|refs)`)

// octokitWriteRe matches Octokit write methods ONLY on an octokit / github /
// gh receiver chain, so an unrelated `db.createBlob(...)` or a method merely
// named `createForAuthenticatedUser` on a non-GitHub object is not treated as
// a GitHub write. createRef is excluded (React.createRef collision). This is
// a light receiver-name shape, not alias/variable tracking: a renamed Octokit
// instance is covered instead by the REST endpoint path.
var octokitWriteRe = regexp.MustCompile(`(?i)\b(?:octokit|github|gh)\b[\w.$]*\.\s*(?:createorupdatefilecontents|createforauthenticateduser|createblob|createtree|createcommit|updateref)\s*\(`)

// httpWriteMethodRe matches an HTTP write-method option (code token), e.g.
// `method: 'PUT'`, used to confirm a REST endpoint is a write.
var httpWriteMethodRe = regexp.MustCompile(`(?i)\bmethod\s*:\s*['"` + "`" + `](?:put|patch|post)['"` + "`" + `]`)

// githubRequestRouteRe matches the Octokit `request("POST /repos/.../...")`
// route form, where the write method and the contents/git-data endpoint
// live together in the route string. The `request(` prefix is required so
// a bare route string in a config/doc (never passed to a request call) is
// not treated as a write channel.
var githubRequestRouteRe = regexp.MustCompile(`(?i)\brequest\s*\(\s*['"` + "`" + `]\s*(?:put|patch|post)\s+/repos/[^/'"` + "`" + `\s]+/[^/'"` + "`" + `\s]+/(?:contents/|git/(?:blobs|trees|commits|refs))`)

var sessionSinkNeedles = []string{
	"filev2.getsession.org",
	"seed1.getsession.org",
	"seed2.getsession.org",
	"seed3.getsession.org",
}

// A Bun launch only counts as a second stage when it runs a local PAYLOAD:
// a path, a .js/.cjs/.mjs file, or an inline -e/--eval. Bare subcommands --
// `bun test`, `bun --version`, `bun run build` (a package script name, no
// path) -- are ordinary project usage and must not register, per the spec.
//
//   - bunProgramRe: first argument is the literal "bun" program
//     (spawn("bun", ...)). Anchored with ^ so a quoted "bun" appearing
//     only as DATA (spawn("echo", ["bun"])) does not match.
//   - bunPayloadTargetRe: a quoted path / .js file, or a -e/--eval flag,
//     anywhere in the args -- the suspicious target a bun program runs.
//   - bunCommandStrRe: the single-string command form bun [run] <path|.js>
//     or bun -e/--eval, used for exec("bun ...") and shelljs .exec(...).
var (
	bunProgramRe       = regexp.MustCompile(`(?i)^\s*['"` + "`" + `]bun['"` + "`" + `]`)
	bunPayloadTargetRe = regexp.MustCompile(`(?i)['"` + "`" + `](?:\.{0,2}/[^\s'"` + "`" + `]+|[a-z0-9_.@/-]*\.[cm]?js)['"` + "`" + `]|['"` + "`" + `]--eval['"` + "`" + `]|['"` + "`" + `]-e['"` + "`" + `]`)
	bunCommandStrRe    = regexp.MustCompile(`(?i)\bbun\s+(?:(?:run\s+)?(?:\.{0,2}/[^\s'"` + "`" + `]+|[a-z0-9_.@/-]*\.[cm]?js\b)|--eval\b|-e\b)`)
)

// cpMethodAtEndRe captures the method identifier immediately before the
// opening paren of a call (the last name in a `cp.spawn(` /
// `require('child_process').exec(` / `execa(` prefix).
var cpMethodAtEndRe = regexp.MustCompile(`([A-Za-z]+)\s*\(\s*$`)

// bunShellMethods are the process APIs that take a whole shell COMMAND as
// one string argument; for these, a `bun run ./x` anywhere in the command
// string is a launch. Every other API (spawn / spawnSync / execFile /
// execFileSync / fork / execa) takes the program as its FIRST argument and
// the rest as data, so `bun` must be that first program argument.
var bunShellMethods = map[string]bool{
	"exec": true, "execsync": true,
	"execacommand": true, "execacommandsync": true,
}

// callRunsBun reports whether a process call launches Bun on a local
// payload. `prefix` is the call text up to and including the opening paren
// (used to recover the method); `args` is the argument list. Shell-command
// APIs match a bun command string; program APIs require "bun" as the first
// program argument plus a payload target, so `spawn("echo", ["bun run x"])`
// (bun only as data) does not match.
func callRunsBun(prefix, args []byte) bool {
	method := ""
	if mm := cpMethodAtEndRe.FindSubmatch(prefix); mm != nil {
		method = strings.ToLower(string(mm[1]))
	}
	if bunShellMethods[method] {
		return bunCommandStrRe.Match(args)
	}
	return bunProgramRe.Match(args) && bunPayloadTargetRe.Match(args)
}

// execa is an unambiguous library name, so an execa(...) call is a real
// process launch.
var execaCallRe = regexp.MustCompile(`(?i)\bexeca(?:sync|command|commandsync)?\s*\(`)

// shelljs binding. `.exec(...)` is only a shell launch when its receiver
// is a name bound to shelljs (or an inline require('shelljs').exec(...)),
// so an unrelated `db.exec('bun run x')` in a shelljs-importing file is
// NOT treated as a shell command. Mirrors the child_process alias logic.
var (
	shelljsAliasAssignRe = regexp.MustCompile(`(?:(?:const|let|var)\s+|,\s*)([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*['"` + "`" + `]shelljs['"` + "`" + `]\s*\)`)
	shelljsAliasESMRe    = regexp.MustCompile(`import\s+(?:\*\s+as\s+)?([A-Za-z_$][\w$]*)\s+from\s*['"` + "`" + `]shelljs['"` + "`" + `]`)
	shelljsInlineExecRe  = regexp.MustCompile(`(?i)require\s*\(\s*['"` + "`" + `]shelljs['"` + "`" + `]\s*\)\s*\.\s*exec\s*\(`)
	aliasExecCallRe      = regexp.MustCompile(jsIdentBoundary + `([A-Za-z_$][\w$]*)\s*\.\s*exec\s*\(`)
)

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

// agentPersistenceNeedles are paths whose presence alone is
// sufficient evidence of editor-automation persistence. Each lives
// inside .claude/ and is a known surface that Claude Code reads or
// executes on workspace open (settings.json hooks, the router
// runtime, the setup hook, the hooks directory). VS Code paths are
// intentionally excluded from the standalone list: VS Code does
// not auto-execute arbitrary files under .vscode/, so VS Code
// persistence requires a tasks.json + runOn:folderOpen pair (see
// detection below).
var agentPersistenceNeedles = []string{
	".claude/settings.json",
	".claude/router_runtime.js",
	".claude/setup.mjs",
	".claude/hooks/",
}

// runOnFolderOpenRe captures the VS Code task trigger that turns a
// tasks.json entry into an auto-run on workspace open. Tolerates
// optional quotes around the key (`'runOn'`, `"runOn"`, bare runOn),
// whitespace, and either quote style around the `folderOpen` value.
// Persistence requires the file ALSO references .vscode/tasks.json
// (see detection below); this token does not fire on its own.
var runOnFolderOpenRe = regexp.MustCompile(`(?i)["']?runOn["']?\s*:\s*["']folderOpen["']`)

// --- DNS TXT exfil regexes ---
//
// The DNS TXT exfil detector deliberately requires a real `resolveTxt`
// call. A bare reference to the string "resolveTxt" (in a comment, a
// JSON manifest, a documentation example) does not satisfy any of the
// regexes below. Legitimate libraries that perform DNS TXT lookups
// would match, so the analyzer only fires the rule when at least one
// other chain signal (secret read, archive staging, daemon chain, or
// a known node-ipc IOC needle) accompanies the call.

// dnsInlineRequireResolveTxtRe matches inline-require resolveTxt
// calls against the Node dns module, in all the documented shapes:
//
//	require('dns').resolveTxt(name, cb)
//	require('node:dns').promises.resolveTxt(name)
//	require("dns/promises").resolveTxt(name)
//	require('dns')['resolveTxt']('zone')         (bracket access)
//	require('dns')?.resolveTxt(...)              (optional chain)
//	require('dns')?.['resolveTxt'](...)
//	require('dns').promises['resolveTxt'](...)
//
// Submatch 1 captures the `require` token so the caller can check
// its position against string interiors. The leading
// jsIdentBoundary prevents matching `myrequire(...)`.
var dnsInlineRequireResolveTxtRe = regexp.MustCompile(
	jsIdentBoundary + `(require)\s*\(\s*['"](?:node:)?dns(?:/promises)?['"]\s*\)` +
		// optional `.promises` / `?.promises` middle step
		`(?:\s*(?:\?\s*\.|\.)\s*promises)?` +
		// access to resolveTxt: dot, optional chain, or bracket
		`\s*(?:` +
		`(?:\?\s*\.|\.)\s*resolveTxt` +
		`|` +
		`(?:\?\s*\.\s*)?\[\s*['"` + "`" + `]resolveTxt['"` + "`" + `]\s*\]` +
		`)` +
		// optional `?.` before the call site
		`\s*(?:\?\s*\.\s*)?\(`,
)

// dnsAliasAssignRe captures the local variable bound to the dns module:
//
//	const dns = require('dns')
//	const dnsP = require('node:dns/promises')
//
// Submatch 1 is the local name. The caller then looks for
// `<name>.resolveTxt(` calls in the file.
var dnsAliasAssignRe = regexp.MustCompile(
	`(?:(?:const|let|var)\s+|,\s*)([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*['"](?:node:)?dns(?:/promises)?['"]\s*\)`,
)

// dnsAliasESMRe captures the local variable bound via ESM import:
//
//	import dns from 'dns'
//	import * as dns from 'node:dns'
//	import dnsP from 'dns/promises'
//	import dns, * as dnsP from 'dns'   (captures dnsP via the
//	                                    namespace clause)
//
// Submatch 1 is the local name. The optional default+comma prefix
// covers combined imports; the dnsAliasESMCombinedRe further down
// captures the default identifier from those same statements.
var dnsAliasESMRe = regexp.MustCompile(
	`import\s+(?:[A-Za-z_$][\w$]*\s*,\s*)?(?:\*\s+as\s+)?([A-Za-z_$][\w$]*)\s+from\s*['"](?:node:)?dns(?:/promises)?['"]`,
)

// dnsAliasESMCombinedRe handles the combined ESM import form, where a
// default identifier is followed by a comma and EITHER a namespace
// import OR a brace-destructure:
//
//	import dns, * as dnsP from 'dns'
//	import dns, { Resolver } from 'node:dns'
//	import dnsP, { resolveTxt } from 'dns/promises'
//
// The previous single-clause regex stops at the first `,` so the
// default identifier never registers. Submatch 1 is the default
// import name; the trailing clause is intentionally not captured
// here because the existing dnsAliasESMRe / destructure regexes
// will also match that same import statement and pick up the
// namespace / destructured names separately.
var dnsAliasESMCombinedRe = regexp.MustCompile(
	`import\s+([A-Za-z_$][\w$]*)\s*,\s*(?:\*\s+as\s+[A-Za-z_$][\w$]*|\{[^}]+\})\s+from\s*['"](?:node:)?dns(?:/promises)?['"]`,
)

// dnsPromisesCJSDestructureRe captures the FULL brace body of a CJS
// destructure of the dns module, regardless of how many members are
// listed. The caller parses the body looking for `promises` (bare or
// renamed) AND for `Resolver` (so destructured Resolver constructors
// from both `dns` and `dns/promises` are picked up). Submatch 1 is
// the brace body.
var dnsPromisesCJSDestructureRe = regexp.MustCompile(
	`(?:(?:const|let|var)\s+|,\s*)\{\s*([^}]+)\s*\}\s*=\s*require\s*\(\s*['"](?:node:)?dns(?:/promises)?['"]\s*\)`,
)

// dnsPromisesESMDestructureRe is the ESM equivalent: the brace body
// of `import { ... } from 'dns'` or `'dns/promises'`, with optional
// leading default import for the combined form.
var dnsPromisesESMDestructureRe = regexp.MustCompile(
	`import\s+(?:[A-Za-z_$][\w$]*\s*,\s*)?\{\s*([^}]+)\s*\}\s*from\s*['"](?:node:)?dns(?:/promises)?['"]`,
)

// parseDestructuredResolverAlias walks a destructure brace body and
// returns the local binding name for the `Resolver` member, plus a
// boolean indicating whether the member is present. Same shape as
// parseDestructuredPromisesAlias but for the Resolver constructor.
//
// Recognized forms (the brace body is the same; `as` is ESM-only):
//
//	Resolver
//	Resolver : alias        (CJS rename)
//	Resolver as alias       (ESM rename)
func parseDestructuredResolverAlias(body string, esm bool) (string, bool) {
	for _, raw := range strings.Split(body, ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if idx := strings.Index(entry, ":"); idx >= 0 {
			source := strings.TrimSpace(entry[:idx])
			local := strings.TrimSpace(entry[idx+1:])
			if source == "Resolver" && local != "" {
				return local, true
			}
			continue
		}
		if esm {
			if idx := strings.Index(entry, " as "); idx >= 0 {
				source := strings.TrimSpace(entry[:idx])
				local := strings.TrimSpace(entry[idx+len(" as "):])
				if source == "Resolver" && local != "" {
					return local, true
				}
				continue
			}
		}
		if entry == "Resolver" {
			return "Resolver", true
		}
	}
	return "", false
}

// newInstanceAssignRe captures the local variable bound to a
// `new <constructor>(...)` instance:
//
//	const r = new Resolver()
//	let res = new MyResolver(opts)
//
// Submatch 1 is the local name, submatch 2 is the constructor name.
// Used together with the destructured-Resolver alias set to register
// receivers for resolveTxt calls when the Resolver itself was
// destructured from the dns module.
var newInstanceAssignRe = regexp.MustCompile(
	`(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*new\s+([A-Za-z_$][\w$]*)\s*\(`,
)

// parseDestructuredPromisesAlias walks a destructure brace body and
// returns the local binding name for the `promises` member, plus a
// boolean indicating whether the member is present at all.
//
// Recognized CJS forms:
//
//	promises
//	promises : alias
//
// Recognized ESM forms (the brace body is the same; the `as`
// alternative is ESM-only):
//
//	promises
//	promises as alias
//
// Siblings in the brace body (e.g. `Resolver`, `lookup`) are ignored.
func parseDestructuredPromisesAlias(body string, esm bool) (string, bool) {
	for _, raw := range strings.Split(body, ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		// CJS rename: `promises : alias`
		if idx := strings.Index(entry, ":"); idx >= 0 {
			source := strings.TrimSpace(entry[:idx])
			local := strings.TrimSpace(entry[idx+1:])
			if source == "promises" && local != "" {
				return local, true
			}
			continue
		}
		// ESM rename: `promises as alias`
		if esm {
			if idx := strings.Index(entry, " as "); idx >= 0 {
				source := strings.TrimSpace(entry[:idx])
				local := strings.TrimSpace(entry[idx+len(" as "):])
				if source == "promises" && local != "" {
					return local, true
				}
				continue
			}
		}
		// Bare member: `promises`
		if entry == "promises" {
			return "promises", true
		}
	}
	return "", false
}

// dnsResolverAliasReceiverRe captures `new <alias>.Resolver(...)` or
// `new <alias>.promises.Resolver(...)` where <alias> is a separate
// identifier (a dns module binding). The caller verifies <alias>
// belongs to the dns-alias set before treating the instance as a
// real Resolver receiver; without that check, `new someSdk.Resolver()`
// from an unrelated library would be misread as a Node DNS resolver.
//
// Submatch 1 is the local variable (the new instance); submatch 2
// is the alias the Resolver is constructed against. The optional
// `.promises` segment lets `new dns.promises.Resolver()` register
// when `dns` is a confirmed binding.
var dnsResolverAliasReceiverRe = regexp.MustCompile(
	`(?:(?:const|let|var)\s+|,\s*)([A-Za-z_$][\w$]*)\s*=\s*new\s+([A-Za-z_$][\w$]*)\s*(?:\.\s*promises\s*)?\.\s*Resolver\s*\(`,
)

// dnsResolverInlineRequireRe captures the inline-require form
// `const r = new (require('dns').Resolver)()` and the promises
// equivalent `new (require('dns').promises.Resolver)()`.
// Submatch 1 is the local variable name.
var dnsResolverInlineRequireRe = regexp.MustCompile(
	`(?:(?:const|let|var)\s+|,\s*)([A-Za-z_$][\w$]*)\s*=\s*new\s+\(\s*require\s*\(\s*['"](?:node:)?dns(?:/promises)?['"]\s*\)(?:\s*\.\s*promises)?\s*\.\s*Resolver\s*\)\s*\(`,
)

// dnsResolveTxtDestructureRe matches destructured `resolveTxt` imports
// from the dns module, with or without an alias:
//
//	const { resolveTxt } = require('dns').promises
//	const { resolveTxt: lookup } = require('node:dns/promises')
//	import { resolveTxt } from 'dns/promises'
//
// Submatch 1 is the brace body. The caller parses each entry and, if
// the source name (everything before `:`) is `resolveTxt`, records the
// effective local binding (the part after `:`, or the name itself).
var dnsResolveTxtDestructureRe = regexp.MustCompile(
	`(?:` +
		`(?:(?:const|let|var)\s+|,\s*)\{\s*([^}]+)\s*\}\s*=\s*require\s*\(\s*['"](?:node:)?dns(?:/promises)?['"]\s*\)(?:\s*\.\s*promises)?` +
		`|` +
		`import\s+(?:[A-Za-z_$][\w$]*\s*,\s*)?\{\s*([^}]+)\s*\}\s*from\s*['"](?:node:)?dns(?:/promises)?['"]` +
		`)`,
)

// dnsResolveTxtFromAliasRe captures destructures whose right-hand
// side is a previously-bound dns alias (or its `.promises` sub-
// namespace), e.g. `const { resolveTxt } = dns.promises`. Submatch
// 1 is the brace body; submatch 2 is the alias on the RHS. The
// caller verifies the alias against the dns-binding set, then
// parses the body looking for `resolveTxt` (bare or renamed).
var dnsResolveTxtFromAliasRe = regexp.MustCompile(
	`(?:(?:const|let|var)\s+|,\s*)\{\s*([^}]+)\s*\}\s*=\s*([A-Za-z_$][\w$]*)(?:\s*\.\s*promises)?`,
)

// identifierResolveTxtCallRe captures the documented shapes of
// `<identifier>(.promises)?(.resolveTxt|['resolveTxt'])(?.)(`:
//
//	dns.resolveTxt(...)
//	dns?.resolveTxt(...)
//	dns.resolveTxt?.(...)
//	dns?.resolveTxt?.(...)
//	dns.promises.resolveTxt(...)
//	dns['resolveTxt'](...)
//	dns[`resolveTxt`](...)
//
// The caller filters submatch 1 (the receiver identifier) through
// the discovered dns / Resolver alias set so unrelated objects do
// not satisfy the receiver match.
var identifierResolveTxtCallRe = regexp.MustCompile(
	jsIdentBoundary + `([A-Za-z_$][\w$]*)` +
		// optional `.promises` / `?.promises` middle step
		`(?:\s*(?:\?\s*\.|\.)\s*promises)?` +
		// access to resolveTxt: dot, optional chain, or bracket
		// (bracket access may itself be preceded by an optional
		// chain marker `?.`).
		`\s*(?:` +
		`(?:\?\s*\.|\.)\s*resolveTxt` +
		`|` +
		`(?:\?\s*\.\s*)?\[\s*['"` + "`" + `]resolveTxt['"` + "`" + `]\s*\]` +
		`)` +
		// optional `?.` before the call site
		`\s*(?:\?\s*\.\s*)?\(`,
)

// bareResolveTxtCallRe captures `resolveTxt(...)` invoked directly on a
// name that was destructured from the dns module.
var bareResolveTxtCallRe = regexp.MustCompile(
	jsIdentBoundary + `([A-Za-z_$][\w$]*)\s*\(`,
)

// --- DNS TXT exfil supporting signals ---

// archiveTmpReceiverRe captures `<receiver>.tmpdir(` calls with the
// receiver name in submatch 1. The caller verifies that <receiver>
// is a binding of the Node os module (via collectOsBindings) before
// crediting the call as a real os.tmpdir() anchor. The leading
// jsIdentBoundary prevents matching the suffix of a longer property
// chain such as `wrapper.os.tmpdir()`.
var archiveTmpReceiverRe = regexp.MustCompile(
	jsIdentBoundary + `([A-Za-z_$][\w$]*)\s*\.\s*tmpdir\s*\(`,
)

// archiveTmpBareCallRe captures a bare `<name>(` invocation with
// the name in submatch 1, preceded by a non-identifier/non-`.`
// boundary so a method call on an unrelated object does not match.
// The caller verifies that <name> was destructured from the os
// module before crediting the call.
var archiveTmpBareCallRe = regexp.MustCompile(
	jsIdentBoundary + `([A-Za-z_$][\w$]*)\s*\(`,
)

// archiveTokenRe matches a tar.gz / gzip / nt-prefixed archive
// reference. These are usually quoted; the proximity check pairs
// the token with an executable archiveTmpAnchorRe match within
// 160 bytes.
var archiveTokenRe = regexp.MustCompile(`tar\.gz|\.gzip\b|\bnt-`)

// Comment masking is implemented as a string-and-regex-aware byte
// walker in stripJSCommentsPreservingOffsets rather than naive regex
// passes. Regex-based strips blank the `//` inside ordinary URL
// literals such as `https://example.com` (preserved by string state
// tracking) and also inside JS regex literals such as `/https?:\/\//`
// (preserved by regex state tracking).
//
// jsRegexLiteralStartingChars lists the characters that, when they
// are the most recent non-whitespace token before a `/`, indicate
// the `/` opens a regex literal rather than a division operator.
// Plus a small set of keywords handled separately in
// couldBeRegexStart. The list is conservative — it accepts as
// "regex context" anything that cannot be the left operand of a
// division. A few rare ambiguous cases (e.g. `++ / pattern /`) are
// treated as division; in practice that only matters when a payload
// uses such forms deliberately to evade comment stripping.
var jsRegexLiteralStartingChars = map[byte]bool{
	'=': true, '(': true, '[': true, '{': true, ',': true, ';': true,
	':': true, '?': true, '!': true, '|': true, '&': true, '^': true,
	'~': true, '+': true, '-': true, '*': true, '%': true, '<': true,
	'>': true, '\n': true,
}

// couldBeRegexStart returns true when the `/` at position i is the
// start of a regex literal. The classifier walks back over
// whitespace to the most recent non-whitespace token and checks it
// against the punctuation set above; otherwise it walks the trailing
// identifier and checks the set of keywords that can precede a
// regex literal (`return`, `typeof`, etc.).
func couldBeRegexStart(content []byte, i int) bool {
	j := i - 1
	for j >= 0 {
		c := content[j]
		if c == ' ' || c == '\t' || c == '\r' {
			j--
			continue
		}
		break
	}
	if j < 0 {
		return true
	}
	c := content[j]
	if jsRegexLiteralStartingChars[c] {
		return true
	}
	// `)` preceding the `/` can be either:
	//   - the closing of a function call: `f() / x` is division;
	//   - the closing of a control-flow header: `if (x) /regex/`
	//     is a regex literal. Walk back to the matching `(` and
	//     inspect the keyword before it. `if`, `while`, `for`,
	//     `switch`, `catch` signal control-flow.
	if c == ')' {
		depth := 1
		k := j - 1
		for k >= 0 && depth > 0 {
			switch content[k] {
			case ')':
				depth++
			case '(':
				depth--
			}
			k--
		}
		if depth != 0 {
			return false
		}
		// k now points one before the matching `(`.
		// Skip whitespace back to the preceding token.
		for k >= 0 {
			cc := content[k]
			if cc == ' ' || cc == '\t' || cc == '\r' || cc == '\n' {
				k--
				continue
			}
			break
		}
		if k < 0 {
			return false
		}
		end := k + 1
		for k >= 0 {
			cc := content[k]
			if (cc >= 'a' && cc <= 'z') || (cc >= 'A' && cc <= 'Z') ||
				cc == '_' || (cc >= '0' && cc <= '9') || cc == '$' {
				k--
				continue
			}
			break
		}
		switch string(content[k+1 : end]) {
		case "if", "while", "for", "switch", "catch":
			return true
		}
		return false
	}
	// Identifier / keyword preceding the `/`. Walk back over
	// identifier characters and check against a small list of
	// keywords whose syntactic position can precede a regex literal.
	if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') &&
		c != '_' && (c < '0' || c > '9') && c != '$' {
		return false
	}
	end := j + 1
	for j >= 0 {
		c := content[j]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			c == '_' || (c >= '0' && c <= '9') || c == '$' {
			j--
			continue
		}
		break
	}
	switch string(content[j+1 : end]) {
	case "return", "typeof", "instanceof", "in", "delete",
		"void", "new", "throw", "yield", "await", "case", "do":
		return true
	}
	return false
}

// envsTxtTokenRe matches an `envs.txt` filename reference. The
// filename boundary accepts the three quote families (`'`, `"`, and
// backtick) plus a forward / back path separator so a template-
// literal path like `${os.tmpdir()}/envs.txt` matches alongside the
// simple string forms.
var envsTxtTokenRe = regexp.MustCompile("['\"`/\\\\]envs\\.txt(?:['\"`]|\\b)")

// fsWriteReceiverRe captures `<receiver>.<write-method>(` calls
// with the receiver and method names in submatches 1 and 2. The
// caller verifies that <receiver> is a binding of the Node fs
// module (or fs-extra) via collectFsBindings before crediting the
// call as a real staging anchor. The set of write methods is
// reused by fsWriteBareCallRe. The leading jsIdentBoundary
// prevents matching the suffix of a longer chain such as
// `wrapper.fs.writeFileSync(...)`.
var fsWriteReceiverRe = regexp.MustCompile(
	jsIdentBoundary + `([A-Za-z_$][\w$]*)\s*\.\s*(writeFile(?:Sync)?|appendFile(?:Sync)?|writeSync|outputFile(?:Sync)?)\s*\(`,
)

// fsPromisesWriteReceiverRe captures the promises sub-namespace
// shape: `<alias>.promises.<write-method>(`. Submatch 1 is the
// receiver alias (must be a verified fs binding); submatch 2 is
// the method name.
var fsPromisesWriteReceiverRe = regexp.MustCompile(
	jsIdentBoundary + `([A-Za-z_$][\w$]*)\s*\.\s*promises\s*\.\s*(writeFile(?:Sync)?|appendFile(?:Sync)?|writeSync|outputFile(?:Sync)?)\s*\(`,
)

// fsWriteBareCallRe captures any bare `<name>(` invocation with the
// name in submatch 1. The caller verifies that <name> was
// destructured from the fs module AND that its source member is
// one of the fs write methods. This shape covers both literal
// destructures (`const { writeFileSync } = ...`) and renamed ones
// (`const { writeFileSync: w } = ...`).
var fsWriteBareCallRe = regexp.MustCompile(
	jsIdentBoundary + `([A-Za-z_$][\w$]*)\s*\(`,
)

// fsWriteMethodNames is the canonical list of fs write method names
// accepted as staging anchors. Kept in sync with the regexes above.
var fsWriteMethodNames = map[string]bool{
	"writeFile":      true,
	"writeFileSync":  true,
	"appendFile":     true,
	"appendFileSync": true,
	"writeSync":      true,
	"outputFile":     true,
	"outputFileSync": true,
}

// moduleBindings collects the local names bound to a Node core
// module and the local names that were destructured FROM that
// module. The archive and envs.txt partner checks consult these
// sets so an unrelated `config.tmpdir()` or local `writeFileSync`
// helper does not falsely satisfy a chain partner.
//
// sourceByLocal maps each destructured local back to its source
// member name (`{ tmpdir: t } = require('os')` -> sourceByLocal["t"]
// = "tmpdir"). For unrenamed destructures the local equals the
// source. The caller uses this map to verify that a bare call
// originates from a specific module member (e.g. `t()` qualifies
// as os.tmpdir when sourceByLocal["t"] == "tmpdir").
type moduleBindings struct {
	aliases       map[string]bool   // identifiers bound to the module itself
	names         map[string]bool   // identifiers destructured from the module
	sourceByLocal map[string]string // local name -> source member name
}

func newModuleBindings() moduleBindings {
	return moduleBindings{
		aliases:       map[string]bool{},
		names:         map[string]bool{},
		sourceByLocal: map[string]string{},
	}
}

// osModuleAliasRe / osModuleAliasESMRe / osDestructureRe /
// osDestructureESMRe mirror the dns binding regexes for the Node
// `os` module. ESM combined-import shape `import os, { tmpdir }
// from 'os'` is covered by accepting an optional `<id>,` prefix in
// each ESM clause.
var osModuleAliasRe = regexp.MustCompile(
	`(?:(?:const|let|var)\s+|,\s*)([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*['"](?:node:)?os['"]\s*\)`,
)
var osModuleAliasESMRe = regexp.MustCompile(
	`import\s+(?:[A-Za-z_$][\w$]*\s*,\s*)?(?:\*\s+as\s+)?([A-Za-z_$][\w$]*)\s+from\s*['"](?:node:)?os['"]`,
)

// osModuleAliasESMCombinedRe captures the DEFAULT alias in
// combined ESM imports of the os module:
//
//	import os, { platform } from 'os'
//	import os, * as osNs from 'os'
//
// Submatch 1 is the default identifier. The trailing clause is
// captured separately by osModuleAliasESMRe and osDestructureESMRe.
var osModuleAliasESMCombinedRe = regexp.MustCompile(
	`import\s+([A-Za-z_$][\w$]*)\s*,\s*(?:\*\s+as\s+[A-Za-z_$][\w$]*|\{[^}]+\})\s+from\s*['"](?:node:)?os['"]`,
)
var osDestructureRe = regexp.MustCompile(
	`(?:(?:const|let|var)\s+|,\s*)\{\s*([^}]+)\s*\}\s*=\s*require\s*\(\s*['"](?:node:)?os['"]\s*\)`,
)
var osDestructureESMRe = regexp.MustCompile(
	`import\s+(?:[A-Za-z_$][\w$]*\s*,\s*)?\{\s*([^}]+)\s*\}\s*from\s*['"](?:node:)?os['"]`,
)

// fs-equivalent regexes. fs-extra is included because it is a
// drop-in replacement that exposes the same write API surface; fs/
// promises is also included for the same reason. The caller treats
// any of these as fs for the staging partner check.
var fsModuleAliasRe = regexp.MustCompile(
	`(?:(?:const|let|var)\s+|,\s*)([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*['"](?:node:)?(?:fs|fs-extra|fs/promises)['"]\s*\)`,
)
var fsModuleAliasESMRe = regexp.MustCompile(
	`import\s+(?:[A-Za-z_$][\w$]*\s*,\s*)?(?:\*\s+as\s+)?([A-Za-z_$][\w$]*)\s+from\s*['"](?:node:)?(?:fs|fs-extra|fs/promises)['"]`,
)

// fsModuleAliasESMCombinedRe captures the DEFAULT alias in combined
// ESM imports of the fs / fs-extra / fs/promises modules:
//
//	import fs, { writeFileSync } from 'fs'
var fsModuleAliasESMCombinedRe = regexp.MustCompile(
	`import\s+([A-Za-z_$][\w$]*)\s*,\s*(?:\*\s+as\s+[A-Za-z_$][\w$]*|\{[^}]+\})\s+from\s*['"](?:node:)?(?:fs|fs-extra|fs/promises)['"]`,
)
var fsDestructureRe = regexp.MustCompile(
	`(?:(?:const|let|var)\s+|,\s*)\{\s*([^}]+)\s*\}\s*=\s*require\s*\(\s*['"](?:node:)?(?:fs|fs-extra|fs/promises)['"]\s*\)`,
)
var fsDestructureESMRe = regexp.MustCompile(
	`import\s+(?:[A-Za-z_$][\w$]*\s*,\s*)?\{\s*([^}]+)\s*\}\s*from\s*['"](?:node:)?(?:fs|fs-extra|fs/promises)['"]`,
)

// collectModuleBindings walks the relevant alias/destructure
// regexes and populates a moduleBindings struct. stringRanges
// filter binding statements that live inside string literals so a
// stringified example like `"require('os')"` does not register a
// real binding. The optional combinedESMRe captures the default
// identifier in combined imports such as `import os, { platform }
// from 'os'`.
func collectModuleBindings(content []byte, stringRanges [][2]int,
	aliasRe, aliasESMRe, destructureRe, destructureESMRe, combinedESMRe *regexp.Regexp) moduleBindings {
	b := newModuleBindings()
	for _, mt := range aliasRe.FindAllSubmatchIndex(content, -1) {
		if insideStringInterior(stringRanges, mt[0]) {
			continue
		}
		b.aliases[string(content[mt[2]:mt[3]])] = true
	}
	for _, mt := range aliasESMRe.FindAllSubmatchIndex(content, -1) {
		if insideStringInterior(stringRanges, mt[0]) {
			continue
		}
		b.aliases[string(content[mt[2]:mt[3]])] = true
	}
	if combinedESMRe != nil {
		for _, mt := range combinedESMRe.FindAllSubmatchIndex(content, -1) {
			if insideStringInterior(stringRanges, mt[0]) {
				continue
			}
			b.aliases[string(content[mt[2]:mt[3]])] = true
		}
	}
	for _, mt := range destructureRe.FindAllSubmatchIndex(content, -1) {
		if insideStringInterior(stringRanges, mt[0]) {
			continue
		}
		body := string(content[mt[2]:mt[3]])
		for _, raw := range strings.Split(body, ",") {
			entry := strings.TrimSpace(raw)
			if entry == "" {
				continue
			}
			// In JS, only the LOCAL binding name (after `:` if a
			// rename is present, otherwise the entry itself) is
			// introduced into scope. Track the source member
			// name separately so the partner check can verify
			// that a renamed local (e.g. `t` from `{ tmpdir: t
			// }`) originated from the expected method.
			source := entry
			local := entry
			if idx := strings.Index(entry, ":"); idx >= 0 {
				source = strings.TrimSpace(entry[:idx])
				local = strings.TrimSpace(entry[idx+1:])
			}
			if local != "" {
				b.names[local] = true
				b.sourceByLocal[local] = source
			}
		}
	}
	for _, mt := range destructureESMRe.FindAllSubmatchIndex(content, -1) {
		if insideStringInterior(stringRanges, mt[0]) {
			continue
		}
		body := string(content[mt[2]:mt[3]])
		for _, raw := range strings.Split(body, ",") {
			entry := strings.TrimSpace(raw)
			if entry == "" {
				continue
			}
			// ESM `import { x as y } from 'm'` introduces `y`,
			// not `x`. Track source member separately.
			source := entry
			local := entry
			if idx := strings.Index(entry, " as "); idx >= 0 {
				source = strings.TrimSpace(entry[:idx])
				local = strings.TrimSpace(entry[idx+len(" as "):])
			}
			if local != "" {
				b.names[local] = true
				b.sourceByLocal[local] = source
			}
		}
	}
	return b
}

// inlineRequireOsTmpdirRe matches an inline-require os.tmpdir
// invocation: `require('os').tmpdir(...)`. Submatch 1 captures the
// `require` token so the caller filters on the token position, not
// the boundary character.
var inlineRequireOsTmpdirRe = regexp.MustCompile(
	jsIdentBoundary + `(require)\s*\(\s*['"](?:node:)?os['"]\s*\)\s*\.\s*tmpdir\s*\(`,
)

// inlineRequireFsWriteRe matches inline-require fs write calls.
// Submatch 1 captures the `require` token (for string-interior
// filtering); submatch 2 captures the method name.
var inlineRequireFsWriteRe = regexp.MustCompile(
	jsIdentBoundary + `(require)\s*\(\s*['"](?:node:)?(?:fs|fs-extra|fs/promises)['"]\s*\)(?:\s*\.\s*promises)?\s*\.\s*(writeFile(?:Sync)?|appendFile(?:Sync)?|writeSync|outputFile(?:Sync)?)\s*\(`,
)

// wholeProcessEnvRe matches forms that exfiltrate VALUES from the
// `process.env` object as a whole. Excludes name-only enumerations
// (`Object.keys`, `for ... in process.env`) and the target-position
// form `Object.assign(process.env, ...)` (which MUTATES process.env
// rather than reading from it). The dynamic-bracket form is
// matched here but post-filtered by the caller to exclude
// assignment LHS like `process.env[k] = ...`.
var wholeProcessEnvRe = regexp.MustCompile(
	`JSON\.stringify\s*\([^)]*process\.env\b` +
		`|Object\.(?:values|entries|fromEntries)\s*\([^)]*process\.env\b` +
		`|Object\.assign\s*\([^)]*,\s*process\.env\b` +
		`|process\.env\s*\[\s*[A-Za-z_$][\w$]*\s*\]`,
)

// wholeProcessEnvDumpRe matches only TRUE whole-environment dumps -- every
// variable serialised at once. It deliberately omits the single-key
// `process.env[k]` dynamic lookup, which resolves to one variable (possibly
// GITHUB_TOKEN) and is the ordinary release-bot shape, not a credential dump.
// Used by the GitHub-C2 strong-secret partner check.
var wholeProcessEnvDumpRe = regexp.MustCompile(
	`JSON\.stringify\s*\([^)]*process\.env\b` +
		`|Object\.(?:values|entries|fromEntries)\s*\([^)]*process\.env\b` +
		`|Object\.assign\s*\([^)]*,\s*process\.env\b`,
)

// processEnvBracketLHSAssignRe identifies the LHS-assignment shape
// `process.env[<id>] = ...` (single `=`, not `==` / `===`).
var processEnvBracketLHSAssignRe = regexp.MustCompile(
	`process\.env\s*\[\s*[A-Za-z_$][\w$]*\s*\]\s*=[^=]`,
)

// processEnvDotLHSAssignRe identifies the LHS-assignment shape
// `process.env.NAME = ...` (or the bracket-string equivalent
// `process.env['NAME'] = ...`) where the assignment writes rather
// than reads. The caller filters envReadRe matches that start at
// the same position so setup/test code that initializes env vars
// is not credited as a secret read.
var processEnvDotLHSAssignRe = regexp.MustCompile(
	`process\.env\s*\.\s*[A-Za-z_$][\w$]*\s*=[^=]` +
		`|process\.env\s*\[\s*['"` + "`" + `][^'"` + "`" + `]+['"` + "`" + `]\s*\]\s*=[^=]`,
)

// nodeIPCIOCNeedles lists literal strings from the May 2026 node-ipc
// compromise. Presence of any of these strings inside a real JS file
// is high signal on its own; combined with a resolveTxt call it
// confirms the chain.
var nodeIPCIOCNeedles = []string{
	"bt.node.js",
	"sh.azurestaticprovider.net",
	"__ntw",
	"__ntRun",
}

// --- detection ---

func detect(path string, m *metrics, content []byte) []types.Finding {
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
	if f := detectDNSTXTExfil(path, m, content); f != nil {
		out = append(out, *f)
	}
	if f := detectBunSecondStage(path, m); f != nil {
		out = append(out, *f)
	}
	if f := detectGitHubC2(path, m); f != nil {
		out = append(out, *f)
	}
	out = append(out, detectHostTamper(path, m, content)...)
	return out
}

// hasObfuscatorShape reports whether the file carries an
// obfuscator-specific signal (hex identifier density, dispatcher-call
// density, or a while(!![]) loop). It mirrors the obfuscator-specific
// half of detectObfuscation's gate and is used as a Bun second-stage
// partner. JS_OBF_001 may also fire independently; the two findings are
// complementary (one names the runtime, one the payload shape).
func (m *metrics) hasObfuscatorShape() bool {
	return m.HexIdentifierCount > hexIdentifierThreshold ||
		m.DispatcherCallCount > dispatcherCallThreshold ||
		m.HasWhileTruePattern
}

// detectBunSecondStage emits JS_BUN_SECOND_STAGE_001 when a file uses the
// Bun runtime as a second stage. Bun execution ALONE never fires (that
// would flag ordinary Bun projects); a partner signal is required:
// Bun download, obfuscator shape, a CI/cloud secret read, an exfil sink,
// or a staged-payload write. Severity is HIGH for the chain, CRITICAL
// when a CI/cloud secret read AND an exfil sink are both present (the
// credential-theft-via-Bun-loader shape). Informational partners like a
// bare process.env read are deliberately NOT sufficient: ordinary Bun
// apps read env vars, so the credential partner is the CI/cloud-specific
// secret signal only.
func detectBunSecondStage(path string, m *metrics) *types.Finding {
	if !m.HasBunExecution {
		return nil
	}
	// Require a STRONG partner: a structural / call-bound signal, not a
	// string-presence one. Obfuscator shape is structural; the CI/cloud
	// secret read is bound to a real process.env.SECRET access; the
	// network sink is bound to a fetch()/http.request() call. String-only
	// signals (a download URL, a chmod/writeFileSync mention, a registry
	// host) are deliberately NOT sufficient on their own: separating a
	// documented mention from a real one needs data-flow we do not do, so
	// the gate stays on the signals that cannot be faked by a doc string.
	strongPartner := m.hasObfuscatorShape() || m.HasCISecretRead || m.HasNetworkSink
	if !strongPartner {
		return nil
	}
	// CRITICAL is the credential-theft-via-Bun-loader shape: a real secret
	// read AND an exfil sink. The secret read is the strong anchor, so the
	// (weaker, needle-based) publish / GitHub / session hosts are accepted
	// here only as the sink half alongside it.
	sink := m.HasNetworkSink || m.HasPublishSink || m.HasGitHubGraphQLSink || m.HasSessionSink
	sev := types.SeverityHigh
	if m.HasCISecretRead && sink {
		sev = types.SeverityCritical
	}
	line := m.LineBun
	if line == 0 {
		line = 1
	}
	return &types.Finding{
		RuleID:   RuleBunSecondStage,
		RuleName: "Bun second-stage execution",
		Severity: sev,
		Category: "supply-chain",
		Description: "JavaScript runs the Bun runtime as a second stage alongside a " +
			"supply-chain signal: an obfuscator-shape payload, a CI/cloud secret read, or a " +
			"network exfil sink. The Red Hat/Miasma worm used a Node preinstall hook to " +
			"download a pinned Bun and execute its heavier second stage outside the Node " +
			"runtime to dodge Node-focused monitoring.",
		FilePath:    path,
		Line:        line,
		MatchedText: "bun runtime execution + supply-chain partner signal",
		Analyzer:    AnalyzerName,
		Confidence:  0.85,
		Remediation: "A package that shells out to Bun during install is almost never " +
			"legitimate. Inspect the file in a clean clone, identify what the Bun stage " +
			"executes, rotate any credentials reachable from the environment it ran in, and " +
			"pin the dependency to a reviewed version (install with --ignore-scripts).",
	}
}

// jsStringInteriors returns sorted, non-overlapping byte ranges
// (half-open: [start, end)) covering the INTERIOR of every JS string
// literal in content. The quote characters themselves are NOT included
// in the ranges so a literal `'dns'` exposes its `dns` bytes only at
// offsets that fall inside the returned interval, and the outer
// regexes that anchor on `require('dns')` still see the quoted token
// in the raw content.
//
// Used together with comment masking to ignore stringified
// documentation examples like `const doc = "uses dns.resolveTxt"`
// when scanning for executable sink calls. The walker keeps comment
// handling so a `//` or `/* */` inside a string literal is preserved
// (the comment-masking pass below is the one that actually blanks
// comment bytes; this helper only reports string ranges).
func jsStringInteriors(content []byte) [][2]int {
	var out [][2]int
	const (
		stCode = iota
		stStringSingle
		stStringDouble
		stStringTemplate
		stLineComment
		stBlockComment
		stRegex
		stRegexCharClass
	)
	state := stCode
	n := len(content)
	startInterior := -1
	var templateStack []int
	for i := 0; i < n; i++ {
		switch state {
		case stCode:
			if content[i] == '/' && i+1 < n {
				switch content[i+1] {
				case '/':
					state = stLineComment
					i++
					continue
				case '*':
					state = stBlockComment
					i++
					continue
				}
				if couldBeRegexStart(content, i) {
					state = stRegex
					continue
				}
			}
			if len(templateStack) > 0 {
				// Inside a ${...} expression of an outer template
				// literal. Track brace depth so the matching `}`
				// transitions back to stStringTemplate.
				switch content[i] {
				case '{':
					templateStack[len(templateStack)-1]++
				case '}':
					templateStack[len(templateStack)-1]--
					if templateStack[len(templateStack)-1] == 0 {
						templateStack = templateStack[:len(templateStack)-1]
						state = stStringTemplate
						startInterior = i + 1
						continue
					}
				}
			}
			switch content[i] {
			case '\'':
				state = stStringSingle
				startInterior = i + 1
			case '"':
				state = stStringDouble
				startInterior = i + 1
			case '`':
				state = stStringTemplate
				startInterior = i + 1
			}
		case stStringSingle:
			if content[i] == '\\' && i+1 < n {
				i++
				continue
			}
			if content[i] == '\'' {
				if startInterior >= 0 && i > startInterior {
					out = append(out, [2]int{startInterior, i})
				}
				startInterior = -1
				state = stCode
			}
		case stStringDouble:
			if content[i] == '\\' && i+1 < n {
				i++
				continue
			}
			if content[i] == '"' {
				if startInterior >= 0 && i > startInterior {
					out = append(out, [2]int{startInterior, i})
				}
				startInterior = -1
				state = stCode
			}
		case stStringTemplate:
			if content[i] == '\\' && i+1 < n {
				i++
				continue
			}
			// `${...}` interpolation expressions inside a template
			// literal execute as code at evaluation time. Close
			// the current string-interior segment before the `${`
			// and push a templateDepth entry so the walker can
			// resume the template state when the matching closing
			// `}` is found. The interior of `${...}` is walked
			// with the full state machine (strings, comments,
			// regex) so nested strings inside the expression are
			// still recorded as string interiors.
			if content[i] == '$' && i+1 < n && content[i+1] == '{' {
				if startInterior >= 0 && i > startInterior {
					out = append(out, [2]int{startInterior, i})
				}
				startInterior = -1
				templateStack = append(templateStack, 1)
				state = stCode
				i++ // skip `{`
				continue
			}
			if content[i] == '`' {
				if startInterior >= 0 && i > startInterior {
					out = append(out, [2]int{startInterior, i})
				}
				startInterior = -1
				state = stCode
			}
		case stLineComment:
			if content[i] == '\n' {
				state = stCode
			}
		case stBlockComment:
			if content[i] == '*' && i+1 < n && content[i+1] == '/' {
				i++
				state = stCode
			}
		case stRegex:
			if content[i] == '\\' && i+1 < n {
				i++
				continue
			}
			if content[i] == '[' {
				state = stRegexCharClass
				continue
			}
			if content[i] == '/' {
				state = stCode
				for i+1 < n {
					f := content[i+1]
					if (f >= 'a' && f <= 'z') || (f >= 'A' && f <= 'Z') {
						i++
						continue
					}
					break
				}
			}
		case stRegexCharClass:
			if content[i] == '\\' && i+1 < n {
				i++
				continue
			}
			if content[i] == ']' {
				state = stRegex
			}
		}
	}
	return out
}

// insideStringInterior returns true when idx falls inside one of the
// sorted, non-overlapping string interior ranges. Used to filter
// regex matches that originate from documentation strings rather
// than executable code. Binary search keeps the partner-detection
// loops linear in total (O(N log K) instead of O(N*K)) when a
// minified JavaScript file contributes many candidate matches
// alongside many string literals.
func insideStringInterior(ranges [][2]int, idx int) bool {
	lo, hi := 0, len(ranges)
	for lo < hi {
		mid := (lo + hi) / 2
		r := ranges[mid]
		if idx < r[0] {
			hi = mid
		} else if idx >= r[1] {
			lo = mid + 1
		} else {
			return true
		}
	}
	return false
}

// jsLexicalView is a single, offset-preserving lexical pass over a JS
// file, shared by every jsrisk signal so a match in a comment, regex
// literal, or example string does not raise a finding.
//
//   - Code is content with comments AND regex-literal bodies masked to
//     spaces (via stripJSCommentsPreservingOffsets). Offsets and line
//     numbers match the original, so lineOf(view.Code, idx) is correct.
//   - StringRanges are the string interiors of Code (sorted, from
//     jsStringInteriors), with `${...}` template expressions treated as
//     code.
//
// Signals scan Code, so a commented or regex-literal occurrence never
// counts. CODE-TOKEN signals (a call keyword, an env read, an obfuscator
// identifier) additionally skip matches whose offset is InString, since a
// call keyword inside a string literal is data, not a call. DATA-indicator
// needles (URLs, credential paths) deliberately do NOT use InString: they
// live legitimately inside the string arguments of real calls.
//
// This is a lexical view only: no scope analysis, AST, or taint.
type jsLexicalView struct {
	Code         []byte
	StringRanges [][2]int
}

func newJSLexicalView(content []byte) jsLexicalView {
	code := stripJSCommentsPreservingOffsets(content)
	return jsLexicalView{Code: code, StringRanges: jsStringInteriors(code)}
}

// InString reports whether the byte offset falls inside a string interior
// of the masked code.
func (v jsLexicalView) InString(idx int) bool {
	return insideStringInterior(v.StringRanges, idx)
}

// CodeTokenAt reports whether a signal match at idx is a real code token:
// not masked away (Code is already comment/regex-free) and not inside a
// string literal. Use for call keywords, env reads, obfuscator idents.
func (v jsLexicalView) CodeTokenAt(idx int) bool {
	return idx >= 0 && !v.InString(idx)
}

// matchInCode reports whether a regex match [start,end] is real code, not
// inside a string literal. It tests the start AND start+1, not the end:
//   - Some jsrisk regexes carry a leading identifier-boundary char
//     (jsIdentBoundary, up to 1 byte) that, for a stringified call like
//     "fetch('x')", is the string's opening quote -- OUTSIDE the interior
//     -- while the real keyword (start+1) is inside it. Testing start+1
//     catches that.
//   - The end is unreliable for env reads: `process.env['NAME']` ends
//     inside the quoted KEY, which is a legitimate string in real code.
//
// So the construct is "stringified" only when its first keyword byte
// (start or start+1) lies in a string interior.
func matchInCode(view jsLexicalView, m []int) bool {
	if view.InString(m[0]) {
		return false
	}
	if m[0]+1 < len(view.Code) && view.InString(m[0]+1) {
		return false
	}
	return true
}

// countCodeTokenMatches streams matches of re through view.Code (one at a
// time via FindIndex on the unscanned suffix, never materializing every
// match), counts those that are real code tokens up to threshold+1, and
// returns that count plus the offset of the first code-token match (or
// -1). Streaming caps on code-token matches rather than raw matches, so
// any number of stringified examples before the real payload is skipped
// without exhausting a budget, while memory stays O(1).
func countCodeTokenMatches(view jsLexicalView, re *regexp.Regexp, threshold int) (int, int) {
	code := view.Code
	count, first := 0, -1
	for pos := 0; pos < len(code); {
		loc := re.FindIndex(code[pos:])
		if loc == nil {
			break
		}
		start, end := pos+loc[0], pos+loc[1]
		if matchInCode(view, []int{start, end}) {
			if first < 0 {
				first = start
			}
			count++
			if count > threshold {
				break
			}
		}
		if end > start {
			pos = end
		} else {
			pos = start + 1
		}
	}
	return count, first
}

// firstCodeTokenIndex streams matches of re and returns the start offset
// of the first real-code match (not in a string), or -1, without
// materializing every match (a file full of stringified `fetch(` examples
// imposes no large allocation).
func firstCodeTokenIndex(view jsLexicalView, re *regexp.Regexp) int {
	code := view.Code
	for pos := 0; pos < len(code); {
		loc := re.FindIndex(code[pos:])
		if loc == nil {
			return -1
		}
		start, end := pos+loc[0], pos+loc[1]
		if matchInCode(view, []int{start, end}) {
			return start
		}
		if end > start {
			pos = end
		} else {
			pos = start + 1
		}
	}
	return -1
}

// asciiLowerBytes returns a length-preserving lowercase copy: only A-Z are
// folded, every other byte is left as-is. Unlike bytes.ToLower (which is
// Unicode-aware and can change byte length), this keeps offsets identical
// to the input, so offsets computed in the folded copy still line up with
// view.Code and the call-argument ranges. The sink needles are ASCII.
func asciiLowerBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}

// whileTrueIndex returns the offset of the first `while(!![])` /
// `while (!![])` in code that is a code token, or -1.
func whileTrueIndex(view jsLexicalView) int {
	best := -1
	for _, lit := range []string{"while(!![])", "while (!![])"} {
		needle := []byte(lit)
		for from := 0; from < len(view.Code); {
			i := bytes.Index(view.Code[from:], needle)
			if i < 0 {
				break
			}
			abs := from + i
			if view.CodeTokenAt(abs) {
				if best < 0 || abs < best {
					best = abs
				}
				break
			}
			from = abs + 1
		}
	}
	return best
}

// hasCodeToken reports whether the lowercase literal occurs in lowerCode as
// a code token (not inside a string literal).
func hasCodeToken(view jsLexicalView, lowerCode []byte, literal string) bool {
	needle := []byte(literal)
	for from := 0; from < len(lowerCode); {
		i := bytes.Index(lowerCode[from:], needle)
		if i < 0 {
			return false
		}
		abs := from + i
		if view.CodeTokenAt(abs) {
			return true
		}
		from = abs + 1
	}
	return false
}

// stripJSCommentsPreservingOffsets returns a copy of content with
// `// ...` line comments and `/* ... */` block comments overwritten
// by spaces. Newlines are kept so byte offsets and lineOf() results
// match the original content exactly. This lets sink detection ignore
// commented example invocations like `// dns.resolveTxt(...)` without
// changing line numbers reported in findings.
//
// The walker tracks string state so that `//` and `/*` sequences
// inside single-, double-, or backtick-quoted strings are preserved
// untouched. The most common case this protects is URL literals like
// `'https://attacker/'` on the same line as a real resolveTxt call:
// blanking past the `//` would erase the rest of the line and hide
// the sink. Template-bracket expressions (`${...}`) are not
// recursively scanned; a resolveTxt call buried inside an
// interpolated expression is rare and the conservative false-negative
// is acceptable.
func stripJSCommentsPreservingOffsets(content []byte) []byte {
	out := make([]byte, len(content))
	copy(out, content)
	const (
		stCode = iota
		stStringSingle
		stStringDouble
		stStringTemplate
		stLineComment
		stBlockComment
		stRegex
		stRegexCharClass
	)
	state := stCode
	n := len(out)
	var templateStack []int
	for i := 0; i < n; i++ {
		switch state {
		case stCode:
			if out[i] == '/' && i+1 < n {
				switch out[i+1] {
				case '/':
					state = stLineComment
					out[i] = ' '
					out[i+1] = ' '
					i++
					continue
				case '*':
					state = stBlockComment
					out[i] = ' '
					out[i+1] = ' '
					i++
					continue
				}
				if couldBeRegexStart(out, i) {
					state = stRegex
					out[i] = ' '
					continue
				}
			}
			if len(templateStack) > 0 {
				switch out[i] {
				case '{':
					templateStack[len(templateStack)-1]++
				case '}':
					templateStack[len(templateStack)-1]--
					if templateStack[len(templateStack)-1] == 0 {
						templateStack = templateStack[:len(templateStack)-1]
						state = stStringTemplate
						continue
					}
				}
			}
			switch out[i] {
			case '\'':
				state = stStringSingle
			case '"':
				state = stStringDouble
			case '`':
				state = stStringTemplate
			}
		case stStringSingle:
			if out[i] == '\\' && i+1 < n {
				i++
				continue
			}
			if out[i] == '\'' {
				state = stCode
			}
		case stStringDouble:
			if out[i] == '\\' && i+1 < n {
				i++
				continue
			}
			if out[i] == '"' {
				state = stCode
			}
		case stStringTemplate:
			if out[i] == '\\' && i+1 < n {
				i++
				continue
			}
			if out[i] == '$' && i+1 < n && out[i+1] == '{' {
				templateStack = append(templateStack, 1)
				state = stCode
				i++ // skip `{`
				continue
			}
			if out[i] == '`' {
				state = stCode
			}
		case stLineComment:
			if out[i] == '\n' {
				state = stCode
				continue
			}
			out[i] = ' '
		case stBlockComment:
			if out[i] == '*' && i+1 < n && out[i+1] == '/' {
				out[i] = ' '
				out[i+1] = ' '
				i++
				state = stCode
				continue
			}
			if out[i] != '\n' {
				out[i] = ' '
			}
		case stRegex:
			if out[i] == '\\' && i+1 < n {
				if out[i+1] != '\n' {
					out[i+1] = ' '
				}
				out[i] = ' '
				i++
				continue
			}
			if out[i] == '[' {
				state = stRegexCharClass
				out[i] = ' '
				continue
			}
			if out[i] == '/' {
				state = stCode
				out[i] = ' '
				for i+1 < n {
					f := out[i+1]
					if (f >= 'a' && f <= 'z') || (f >= 'A' && f <= 'Z') {
						out[i+1] = ' '
						i++
						continue
					}
					break
				}
				continue
			}
			if out[i] != '\n' {
				out[i] = ' '
			}
		case stRegexCharClass:
			if out[i] == '\\' && i+1 < n {
				if out[i+1] != '\n' {
					out[i+1] = ' '
				}
				out[i] = ' '
				i++
				continue
			}
			if out[i] == ']' {
				state = stRegex
				out[i] = ' '
				continue
			}
			if out[i] != '\n' {
				out[i] = ' '
			}
		}
	}
	return out
}

// findDNSTXTSink returns the 1-based line of the first real resolveTxt
// call against the Node dns module, or 0 when no such call exists.
// The function ties resolveTxt invocations to a discovered binding
// (require / ESM import / new dns.Resolver()) so a bare string mention
// of resolveTxt does not satisfy the signal. Comments are masked
// before pattern matching so commented documentation examples never
// register as sinks.
func findDNSTXTSink(rawContent []byte) int {
	content := stripJSCommentsPreservingOffsets(rawContent)
	stringRanges := jsStringInteriors(rawContent)
	_ = stringRanges // referenced below via insideStringInterior
	// Inline-require chain: require('dns').resolveTxt(...)
	for _, mt := range dnsInlineRequireResolveTxtRe.FindAllSubmatchIndex(content, -1) {
		// The boundary byte at mt[0] can be a quote opening a
		// string literal; the actual `require` token at mt[2]
		// is the position we must verify is in executable code.
		if insideStringInterior(stringRanges, mt[2]) {
			continue
		}
		return lineOf(content, mt[2])
	}

	// Build the set of identifiers that are bound to the dns module or
	// to a Resolver instance constructed from it. Every binding match
	// is filtered through stringRanges so a stringified example like
	// `const help = "require('dns')";` does not register a real
	// alias.
	aliases := map[string]bool{}
	resolverCtorNames := map[string]bool{}
	for _, mt := range dnsAliasAssignRe.FindAllSubmatchIndex(content, -1) {
		if insideStringInterior(stringRanges, mt[0]) {
			continue
		}
		aliases[string(content[mt[2]:mt[3]])] = true
	}
	for _, mt := range dnsAliasESMRe.FindAllSubmatchIndex(content, -1) {
		if insideStringInterior(stringRanges, mt[0]) {
			continue
		}
		aliases[string(content[mt[2]:mt[3]])] = true
	}
	// Combined ESM imports register the default identifier; the
	// trailing namespace / destructure clause is picked up by the
	// existing dnsAliasESMRe / dnsPromisesESMDestructureRe /
	// dnsResolveTxtDestructureRe regexes which now accept an
	// optional leading `<default>,` prefix.
	for _, mt := range dnsAliasESMCombinedRe.FindAllSubmatchIndex(content, -1) {
		if insideStringInterior(stringRanges, mt[0]) {
			continue
		}
		aliases[string(content[mt[2]:mt[3]])] = true
	}
	// `<alias>.Resolver` constructors only count when <alias> is a
	// confirmed dns binding; otherwise an unrelated SDK whose own
	// constructor happens to be named `Resolver` would be misread
	// as a Node DNS resolver and produce false positives.
	for _, mt := range dnsResolverAliasReceiverRe.FindAllSubmatchIndex(content, -1) {
		if insideStringInterior(stringRanges, mt[0]) {
			continue
		}
		if aliases[string(content[mt[4]:mt[5]])] {
			aliases[string(content[mt[2]:mt[3]])] = true
		}
	}
	// `new (require('dns').Resolver)()` is unambiguous and registers
	// without an alias-set check.
	for _, mt := range dnsResolverInlineRequireRe.FindAllSubmatchIndex(content, -1) {
		if insideStringInterior(stringRanges, mt[0]) {
			continue
		}
		aliases[string(content[mt[2]:mt[3]])] = true
	}
	// Destructured `promises` namespace bindings count as dns
	// receivers. Two regexes (CJS + ESM) capture the FULL brace body,
	// and parseDestructuredPromisesAlias walks the body to find the
	// effective local binding regardless of whether `promises` is the
	// sole destructured member or sits alongside siblings such as
	// `Resolver` or `lookup`. The same regexes also drive Resolver
	// constructor extraction (parseDestructuredResolverAlias) so
	// `const { Resolver } = require('dns'); const r = new Resolver()`
	// can register `r` as a resolveTxt receiver through the
	// new-instance assignment scan below.
	for _, mt := range dnsPromisesCJSDestructureRe.FindAllSubmatchIndex(content, -1) {
		if insideStringInterior(stringRanges, mt[0]) {
			continue
		}
		body := string(content[mt[2]:mt[3]])
		if local, ok := parseDestructuredPromisesAlias(body, false); ok {
			aliases[local] = true
		}
		if local, ok := parseDestructuredResolverAlias(body, false); ok {
			resolverCtorNames[local] = true
		}
	}
	for _, mt := range dnsPromisesESMDestructureRe.FindAllSubmatchIndex(content, -1) {
		if insideStringInterior(stringRanges, mt[0]) {
			continue
		}
		body := string(content[mt[2]:mt[3]])
		if local, ok := parseDestructuredPromisesAlias(body, true); ok {
			aliases[local] = true
		}
		if local, ok := parseDestructuredResolverAlias(body, true); ok {
			resolverCtorNames[local] = true
		}
	}

	// For every Resolver constructor name destructured from the dns
	// module, register `new <ctor>()` instance bindings as receivers
	// so `r.resolveTxt(...)` later in the file fires the sink.
	if len(resolverCtorNames) > 0 {
		for _, mt := range newInstanceAssignRe.FindAllSubmatchIndex(content, -1) {
			if insideStringInterior(stringRanges, mt[0]) {
				continue
			}
			if resolverCtorNames[string(content[mt[4]:mt[5]])] {
				aliases[string(content[mt[2]:mt[3]])] = true
			}
		}
	}

	if len(aliases) > 0 {
		for _, mt := range identifierResolveTxtCallRe.FindAllSubmatchIndex(content, -1) {
			if !aliases[string(content[mt[2]:mt[3]])] {
				continue
			}
			if insideStringInterior(stringRanges, mt[2]) {
				continue
			}
			return lineOf(content, mt[2])
		}
	}

	// Destructured resolveTxt imports: collect the effective local
	// binding (alias if `:` is present, otherwise the source name)
	// when the source name is `resolveTxt`. Then look for bare calls
	// to that binding.
	bareNames := map[string]bool{}
	// Also pick up destructures whose RHS is a previously-bound
	// dns alias (e.g. `const { resolveTxt } = dns.promises`).
	for _, mt := range dnsResolveTxtFromAliasRe.FindAllSubmatchIndex(content, -1) {
		if insideStringInterior(stringRanges, mt[0]) {
			continue
		}
		if !aliases[string(content[mt[4]:mt[5]])] {
			continue
		}
		body := string(content[mt[2]:mt[3]])
		for _, raw := range strings.Split(body, ",") {
			entry := strings.TrimSpace(raw)
			source := entry
			local := entry
			if idx := strings.Index(entry, ":"); idx >= 0 {
				source = strings.TrimSpace(entry[:idx])
				local = strings.TrimSpace(entry[idx+1:])
			}
			if source == "resolveTxt" && local != "" {
				bareNames[local] = true
			}
		}
	}
	for _, mt := range dnsResolveTxtDestructureRe.FindAllSubmatchIndex(content, -1) {
		if insideStringInterior(stringRanges, mt[0]) {
			continue
		}
		// Two alternation slots; only one is populated per match.
		var body string
		if mt[2] >= 0 {
			body = string(content[mt[2]:mt[3]])
		} else if mt[4] >= 0 {
			body = string(content[mt[4]:mt[5]])
		}
		if body == "" {
			continue
		}
		for _, raw := range strings.Split(body, ",") {
			entry := strings.TrimSpace(raw)
			source := entry
			local := entry
			if idx := strings.Index(entry, ":"); idx >= 0 {
				source = strings.TrimSpace(entry[:idx])
				local = strings.TrimSpace(entry[idx+1:])
			}
			// ESM `as` aliasing: `resolveTxt as lookup`.
			if idx := strings.Index(local, " as "); idx >= 0 {
				source = strings.TrimSpace(local[:idx])
				local = strings.TrimSpace(local[idx+len(" as "):])
			}
			if source == "resolveTxt" && local != "" {
				bareNames[local] = true
			}
		}
	}

	if len(bareNames) > 0 {
		for _, mt := range bareResolveTxtCallRe.FindAllSubmatchIndex(content, -1) {
			if !bareNames[string(content[mt[2]:mt[3]])] {
				continue
			}
			if insideStringInterior(stringRanges, mt[2]) {
				continue
			}
			// Method-definition shapes (`resolveTxt(args) { ... }`,
			// `function resolveTxt(args) { ... }`, class method
			// declarations, async method bodies) are not invocations.
			// Skip the match when the closing `)` is followed by a
			// `{` (function body opener), or when the call is
			// preceded by `function` / `async function`.
			if isFunctionDefinition(content, mt[1]) || isFunctionKeywordBefore(content, mt[2]) {
				continue
			}
			return lineOf(content, mt[2])
		}
	}

	return 0
}

// firstArgEnd returns the byte offset one past the end of the FIRST
// argument of a call whose opening `(` sits at openParen. The
// returned position is either the byte of the first `,` at the
// call's argument depth, or the matching `)` (when the call has a
// single argument), or -1 when the call is unbalanced. String
// interiors are skipped so a `,` or `)` quoted inside an argument
// does not falsely terminate the arg list.
func firstArgEnd(content []byte, openParen int, stringRanges [][2]int) int {
	if openParen < 0 || openParen >= len(content) || content[openParen] != '(' {
		return -1
	}
	depth := 1
	for i := openParen + 1; i < len(content); i++ {
		if insideStringInterior(stringRanges, i) {
			continue
		}
		switch content[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if depth == 0 {
				return i
			}
		case ',':
			if depth == 1 {
				return i
			}
		}
	}
	return -1
}

// enclosingOpenParen returns the byte offset of the most recently
// unclosed `(` at position idx, or -1 when idx is at the top level
// (no enclosing function call / parenthesized expression). String
// interiors are skipped so a `(` quoted inside a string does not
// shift the scope. The walk is O(idx); callers should cache when
// inspecting many positions in the same file.
func enclosingOpenParen(content []byte, idx int, stringRanges [][2]int) int {
	var stack []int
	for i := 0; i < idx && i < len(content); i++ {
		if insideStringInterior(stringRanges, i) {
			continue
		}
		switch content[i] {
		case '(':
			stack = append(stack, i)
		case ')':
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
	}
	if len(stack) == 0 {
		return -1
	}
	return stack[len(stack)-1]
}

// sameStatement returns true when positions a and b lie within
// maxBytes of each other AND belong to the same call-scope AND no
// statement boundary sits between them. Boundaries:
//
//   - a `;` in executable code,
//   - a `,` in executable code when both positions share the SAME
//     enclosing `(` (or are both at the top level): a top-level
//     `, help=...` sequence expression separates partners, whereas
//     a `,` INSIDE the same function call's argument list does not
//     (`path.join(os.tmpdir(), 'stage.tar.gz')` keeps both args
//     in the same scope), and
//   - a newline `\n` whose preceding line does NOT end with a
//     continuation character.
//
// The caller supplies a sorted, non-overlapping list of string-
// interior ranges so quoted characters do not contribute
// boundaries.
func sameStatement(content []byte, a, b, maxBytes int, stringRanges [][2]int) bool {
	if a > b {
		a, b = b, a
	}
	if b-a > maxBytes {
		return false
	}
	// When the anchor sits inside a call (e.g. `path.join(...)`),
	// a `,` at the anchor's depth is the call's arg separator and
	// the args are typically COMBINED into one value by the call;
	// the partner check accepts them as related. When the anchor
	// sits at the TOP level, a `,` at the anchor's depth is a
	// sequence-expression separator — a hard split. The token is
	// allowed to live at a deeper depth than the anchor (for
	// example the envs.txt filename token sitting INSIDE the
	// write call's argument list while the anchor identifier is
	// at the top level outside the parens).
	commaAtAnchorLevelIsSeparator := enclosingOpenParen(content, a, stringRanges) < 0
	parenDepth := 0
	exitedAnchorScope := false
	for i := a + 1; i < b; i++ {
		c := content[i]
		if insideStringInterior(stringRanges, i) {
			continue
		}
		if c == '(' || c == '[' || c == '{' {
			parenDepth++
			continue
		}
		if c == ')' || c == ']' || c == '}' {
			parenDepth--
			if parenDepth < 0 {
				// Walked past the anchor's enclosing
				// `(` / `[` / `{`. From this point on the
				// walk is at a SHALLOWER scope than the
				// anchor, so a `,` at depth 0 is a top-
				// level sequence separator regardless of
				// the original anchor scope.
				exitedAnchorScope = true
				parenDepth = 0
			}
			continue
		}
		if c == ',' && parenDepth == 0 {
			if commaAtAnchorLevelIsSeparator || exitedAnchorScope {
				return false
			}
		}
		if c == ';' {
			return false
		}
		if c != '\n' {
			continue
		}
		// Skip newlines inside string interiors (template literals).
		if insideStringInterior(stringRanges, i) {
			continue
		}
		// Newline-as-boundary heuristic: walk back from \n to find
		// the last non-whitespace char on the previous line (if
		// it's a continuation operator, the statement continues),
		// AND walk forward to find the first non-whitespace char
		// of the next line (if it's a leading operator like `+`
		// `.` `?`, the statement also continues). Either check
		// passing is enough to treat the newline as continuation.
		lastCodeChar := byte(0)
		for k := i - 1; k > a; k-- {
			kc := content[k]
			if kc == '\n' {
				break
			}
			if kc == ' ' || kc == '\t' || kc == '\r' {
				continue
			}
			if insideStringInterior(stringRanges, k) {
				continue
			}
			lastCodeChar = kc
			break
		}
		isTrailingCont := false
		switch lastCodeChar {
		case ',', '(', '[', '{', '+', '-', '*', '/', '?', ':',
			'=', '<', '>', '&', '|', '!', '.':
			isTrailingCont = true
		}
		nextCodeChar := byte(0)
		for k := i + 1; k < b; k++ {
			kc := content[k]
			if kc == ' ' || kc == '\t' || kc == '\r' || kc == '\n' {
				continue
			}
			if insideStringInterior(stringRanges, k) {
				continue
			}
			nextCodeChar = kc
			break
		}
		isLeadingCont := false
		switch nextCodeChar {
		case '+', '-', '*', '/', '?', ':', '=', '<', '>',
			'&', '|', '!', '.', ',', ')', ']', '}':
			isLeadingCont = true
		}
		if isTrailingCont || isLeadingCont {
			continue
		}
		// Blank intervening line OR identifier on next line
		// without a continuation operator: treat as a boundary.
		if lastCodeChar == 0 && nextCodeChar == 0 {
			continue
		}
		return false
	}
	return true
}

// isFunctionDefinition returns true when the byte immediately after
// the call's argument list (after the matching `)`) is `{` AND no
// newline separates the `)` from the `{`. A `{` on a NEW line is a
// separate block statement, not a function body, so a bare
// `resolveTxt(...)` call followed by `{ audit(); }` on the next line
// must still register as a call. argsStart is one past the opening
// paren.
func isFunctionDefinition(content []byte, argsStart int) bool {
	depth := 1
	i := argsStart
	n := len(content)
	for i < n && depth > 0 {
		switch content[i] {
		case '(':
			depth++
		case ')':
			depth--
		case '"', '\'', '`':
			quote := content[i]
			i++
			for i < n && content[i] != quote {
				if content[i] == '\\' && i+1 < n {
					i += 2
					continue
				}
				i++
			}
		}
		i++
	}
	for i < n {
		c := content[i]
		if c == ' ' || c == '\t' {
			i++
			continue
		}
		if c == '\n' || c == '\r' {
			// Newline separates the call from any following
			// block; not a function definition.
			return false
		}
		return c == '{'
	}
	return false
}

// isFunctionKeywordBefore returns true when `function` (optionally
// preceded by `async`) appears immediately before the identifier at
// nameStart. Catches `function resolveTxt(` declarations.
func isFunctionKeywordBefore(content []byte, nameStart int) bool {
	if nameStart <= 0 {
		return false
	}
	i := nameStart - 1
	for i >= 0 {
		c := content[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			i--
			continue
		}
		break
	}
	if i < 0 {
		return false
	}
	end := i + 1
	for i >= 0 {
		c := content[i]
		if c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			i--
			continue
		}
		break
	}
	word := string(content[i+1 : end])
	return word == "function"
}

// detectDNSTXTExfil flags resolveTxt-based credential exfiltration. A
// bare resolveTxt call by itself is permitted: many legitimate
// libraries (DMARC checkers, SPF tools, monitoring) use DNS TXT
// lookups. The rule fires only when the call is accompanied by at
// least one further risk signal:
//   - CI/cloud secret read (process.env or known cred path),
//   - on-disk credential staging file (envs.txt),
//   - archive packaging into a temp directory (tar.gz + os.tmpdir),
//   - install-time daemonization, or
//   - a known node-ipc compromise IOC string (bt.node.js, __ntw, etc.).
//
// Severity is HIGH for a single partner signal; presence of a known
// IOC needle or three or more chain partners escalates to CRITICAL.
func detectDNSTXTExfil(path string, m *metrics, content []byte) *types.Finding {
	if !m.HasDNSTXTSink {
		return nil
	}
	// Partner signals are evaluated on a comment-masked copy of the
	// file so that documentation lines like `// uses process.env in
	// CI` or `/* writes envs.txt */` do not satisfy a chain partner
	// for a legitimate library that calls resolveTxt. The other
	// jsrisk rules continue to read the raw-content metrics; the
	// stricter check applies here because this rule fires on a
	// single partner.
	stripped := stripJSCommentsPreservingOffsets(content)
	stringRanges := jsStringInteriors(content)
	hasSecret := false
	// Collect positions of `process.env.NAME = ...` / `process.env
	// ['NAME'] = ...` assignment LHS so envReadRe matches at those
	// positions are recognized as writes (not reads) and excluded
	// from the secret partner.
	envLHSStarts := map[int]bool{}
	for _, loc := range processEnvDotLHSAssignRe.FindAllIndex(stripped, -1) {
		envLHSStarts[loc[0]] = true
	}
	for _, match := range envReadRe.FindAllSubmatchIndex(stripped, -1) {
		// Skip stringified examples like
		// "export process.env.GITHUB_TOKEN in CI".
		if insideStringInterior(stringRanges, match[0]) {
			continue
		}
		if envLHSStarts[match[0]] {
			continue
		}
		name := string(stripped[match[2]:match[3]])
		for _, n := range ciSecretEnvVars {
			if name == n {
				hasSecret = true
				break
			}
		}
		if hasSecret {
			break
		}
	}
	if !hasSecret {
		for _, match := range envDestructureRe.FindAllSubmatchIndex(stripped, -1) {
			if insideStringInterior(stringRanges, match[0]) {
				continue
			}
			body := string(stripped[match[2]:match[3]])
			for _, raw := range strings.Split(body, ",") {
				entry := strings.TrimSpace(raw)
				// Strip any default initializer
				// (`NAME = default`) before extracting the
				// source member name.
				if idx := strings.Index(entry, "="); idx >= 0 {
					entry = strings.TrimSpace(entry[:idx])
				}
				if idx := strings.Index(entry, ":"); idx >= 0 {
					entry = strings.TrimSpace(entry[:idx])
				}
				for _, n := range ciSecretEnvVars {
					if entry == n {
						hasSecret = true
						break
					}
				}
				if hasSecret {
					break
				}
			}
			if hasSecret {
				break
			}
		}
	}
	if !hasSecret {
		// Credential paths and cloud-metadata IPs are normally
		// quoted in executable code (`fs.readFileSync(
		// '/var/run/secrets/kubernetes.io/serviceaccount/token')`
		// or `fetch('http://169.254.169.254/latest/meta-data/...')`),
		// so a string-interior filter here would suppress real
		// reads. The needles are specific enough that a help string
		// merely mentioning them is the rarer case; accept the
		// trade-off.
		for _, n := range ciSecretLiteralNeedles {
			if bytes.Contains(stripped, []byte(n)) {
				hasSecret = true
				break
			}
		}
	}
	if !hasSecret {
		// Whole-process env reads are the most direct credential-
		// exfil shape (`JSON.stringify(process.env)`,
		// `Object.values(process.env).forEach(...)`, etc.). The
		// match must originate in executable code, not inside a
		// help string. Bracket-access matches that are the LHS of
		// an assignment (`process.env[k] = ...`) are WRITES, not
		// reads, and must be excluded.
		assignLHSStarts := map[int]bool{}
		for _, loc := range processEnvBracketLHSAssignRe.FindAllIndex(stripped, -1) {
			assignLHSStarts[loc[0]] = true
		}
		for _, loc := range wholeProcessEnvRe.FindAllIndex(stripped, -1) {
			if insideStringInterior(stringRanges, loc[0]) {
				continue
			}
			if assignLHSStarts[loc[0]] {
				continue
			}
			hasSecret = true
			break
		}
	}
	// envs.txt staging partner: an fs-write/append call must be in
	// executable code (not inside a string and not inside a comment)
	// within ~200 bytes of an `envs.txt` filename token. Decoupling
	// the write anchor from the token keeps a documentation string
	// like `"fs.writeFileSync('/envs.txt')"` from satisfying the
	// partner, while still allowing the natural form where the
	// filename is quoted inside an executable call.
	hasEnvsTxt := false
	// Each verified fs write call exposes its first-argument (path) range;
	// the envs.txt token must fall INSIDE that range (the path argument).
	// Presence in the data position of the call, or in an unrelated
	// statement, does not register. Shared with the host-trust tamper rule.
	fsCalls := collectFSWriteCalls(stripped, stringRanges)
	if len(fsCalls) > 0 {
		for _, loc := range envsTxtTokenRe.FindAllIndex(stripped, -1) {
			for _, c := range fsCalls {
				if loc[0] >= c.pathStart && loc[0] < c.pathEnd {
					hasEnvsTxt = true
					break
				}
			}
			if hasEnvsTxt {
				break
			}
		}
	}

	// Archive partner: at least one executable os.tmpdir / tmpdir
	// anchor (in code, not inside a string) must share a statement
	// with a tar.gz / gzip / nt- token within 160 bytes. Statement
	// sharing rejects a help-string archive mention adjacent to an
	// unrelated tmpdir call.
	hasArchive := false
	osBindingsDNS := collectModuleBindings(stripped, stringRanges,
		osModuleAliasRe, osModuleAliasESMRe, osDestructureRe, osDestructureESMRe, osModuleAliasESMCombinedRe)
	var archiveTmpPositions []int
	for _, mt := range archiveTmpReceiverRe.FindAllSubmatchIndex(stripped, -1) {
		if insideStringInterior(stringRanges, mt[2]) {
			continue
		}
		if !osBindingsDNS.aliases[string(stripped[mt[2]:mt[3]])] {
			continue
		}
		archiveTmpPositions = append(archiveTmpPositions, mt[2])
	}
	for _, mt := range archiveTmpBareCallRe.FindAllSubmatchIndex(stripped, -1) {
		if insideStringInterior(stringRanges, mt[2]) {
			continue
		}
		if osBindingsDNS.sourceByLocal[string(stripped[mt[2]:mt[3]])] != "tmpdir" {
			continue
		}
		archiveTmpPositions = append(archiveTmpPositions, mt[2])
	}
	for _, mt := range inlineRequireOsTmpdirRe.FindAllSubmatchIndex(stripped, -1) {
		if insideStringInterior(stringRanges, mt[2]) {
			continue
		}
		archiveTmpPositions = append(archiveTmpPositions, mt[2])
	}
	if len(archiveTmpPositions) > 0 {
		for _, loc := range archiveTokenRe.FindAllIndex(stripped, -1) {
			for _, a := range archiveTmpPositions {
				if sameStatement(stripped, a, loc[0], 160, stringRanges) {
					hasArchive = true
					break
				}
			}
			if hasArchive {
				break
			}
		}
	}
	hasIOC := false
	iocMatch := ""
	for _, n := range nodeIPCIOCNeedles {
		if bytes.Contains(stripped, []byte(n)) {
			hasIOC = true
			if iocMatch == "" {
				iocMatch = n
			}
		}
	}
	// Daemon partner is re-derived on stripped content AND filtered
	// by string interiors so a daemon snippet quoted inside a help
	// string does not satisfy the partner. The detached:true and
	// stdio:'ignore' matches inside the extracted args are also
	// passed through a per-args string-interior filter so a
	// `child_process.spawn('cmd', ['{detached: true, stdio: \'ignore\'}'])`
	// shell-snippet argument cannot satisfy the daemon partner.
	// The raw-content metric `m.HasDaemonChain` powers JS_DAEMON_001
	// as before; that rule's single-signal scope keeps its
	// existing behavior.
	hasDaemon := false
	for _, site := range collectChildProcessCalls(stripped) {
		if insideStringInterior(stringRanges, site.Start) {
			continue
		}
		args := extractCallArgs(stripped, site.ArgsStart)
		argRanges := jsStringInteriors(args)
		foundDetached := false
		for _, loc := range detachedTrueRe.FindAllIndex(args, -1) {
			if !insideStringInterior(argRanges, loc[0]) {
				foundDetached = true
				break
			}
		}
		if !foundDetached {
			continue
		}
		foundStdio := false
		for _, loc := range stdioIgnoredRe.FindAllIndex(args, -1) {
			if !insideStringInterior(argRanges, loc[0]) {
				foundStdio = true
				break
			}
		}
		if !foundStdio {
			continue
		}
		hasDaemon = true
		break
	}

	// Each signal is a distinct partner: a payload that BOTH reads
	// process.env secrets AND stages them to envs.txt is two separate
	// behaviors in the exfil chain, not one collapsed condition. The
	// CRITICAL escalation only triggers on three-plus partners, so
	// keeping them separate matters for severity.
	partners := 0
	if hasSecret {
		partners++
	}
	if hasEnvsTxt {
		partners++
	}
	if hasArchive {
		partners++
	}
	if hasDaemon {
		partners++
	}
	if hasIOC {
		partners++
	}
	if partners == 0 {
		return nil
	}

	sev := types.SeverityHigh
	if hasIOC || partners >= 3 {
		sev = types.SeverityCritical
	}

	line := m.LineDNSTXT
	if line == 0 {
		line = 1
	}
	matched := "resolveTxt(...) + chain"
	if hasIOC && iocMatch != "" {
		matched = "resolveTxt(...) + " + iocMatch
	}
	return &types.Finding{
		RuleID:   RuleDNSTXTExfil,
		RuleName: "DNS TXT exfiltration chain in JavaScript",
		Severity: sev,
		Category: "supply-chain",
		Description: "JavaScript invokes resolveTxt against the Node dns module and " +
			"pairs it with at least one further exfiltration signal: a CI / cloud " +
			"secret read, an envs.txt credential stage, a tar.gz archive staged " +
			"under os.tmpdir(), an install-time daemon chain, or a known IOC " +
			"string from the May 2026 node-ipc compromise. DNS TXT queries are " +
			"the covert channel of choice when an attacker cannot rely on an " +
			"HTTPS sink reaching the target environment.",
		FilePath:    path,
		Line:        line,
		MatchedText: matched,
		Analyzer:    AnalyzerName,
		Confidence:  0.9,
		Remediation: "Treat the surrounding package as compromised. Rotate any tokens the " +
			"affected host has held, audit recent DNS egress for the suspicious zone, " +
			"and pin the dependency to a known-clean version. Legitimate DNS TXT " +
			"libraries do not combine resolveTxt with secret reads and archive staging.",
	}
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
