// Package npmpolicy is a small, auditable analyzer for npm
// supply-chain posture under the npm v12 trust model. It does NOT
// resolve package@version against threat intel (that is packagecheck's
// job); it reads the project's committed npm configuration and reports
// where the v12 trust controls have been weakened or pinned open.
//
// npm v12 (announced 2026-06-09, estimated July 2026; preparable on npm
// 11.16.0+) makes three install-time decisions explicit: dependency
// install scripts run only when approved in the package.json
// `allowScripts` policy, git dependencies resolve only under
// `allow-git`, and remote-tarball dependencies only under
// `allow-remote`. All three are configured in files a repository ships,
// which makes them posture the repo can weaken for everyone who clones.
//
// Design rules (mirroring pnpm-policy):
//   - Two targets, matched by base name: `package.json` (the
//     `allowScripts` policy field) and `.npmrc` (project config).
//     No cross-file correlation, no npm-version inference. Severities
//     are fixed so the catalog and scan output never disagree.
//   - Defaults are never findings. The analyzer fires only on an
//     explicit value that is less safe than the npm v12 baseline;
//     absence stays silent.
//   - Only shapes npm actually honors fire (ground-truthed against npm
//     11.16.0, 2026-06-10):
//   - `allowScripts` entries are written by `npm approve-scripts` as
//     pinned `name@version: true`. A name-only entry with value `true`
//     allows every future version (written when `allow-scripts-pin` is
//     false). A name-only entry with value `false` is a DENY (`npm
//     deny-scripts` always writes name-only) and must never fire.
//   - There is no wildcard approve: `npm approve-scripts '*'` is
//     rejected, so a literal "*" key is not a shape npm honors and is
//     not flagged. The real approve-all is the
//     `dangerously-allow-all-scripts` escape hatch in .npmrc.
//   - `allow-git` / `allow-remote` accept "all" | "none" | "root"
//     ("root" = direct dependencies only). Their npm 11.x default is
//     "all"; npm v12 flips both to "none". An explicit value in a
//     committed .npmrc pins the relaxed behavior through the upgrade.
//
// .npmrc parsing is deliberately narrow: top-level `key=value` lines
// (npm's ini dialect), `#`/`;` comments ignored, a bare `key` line
// reads as true (ini semantics), surrounding quotes stripped, exact
// lowercase keys only, and values containing `${...}` env expansion are
// treated as ambiguous and skipped rather than guessed. Lines inside an
// `[section]` are ignored (npm does not read our keys from sections).
package npmpolicy

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/garagon/aguara/internal/rulemeta"
	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/types"
)

// Rule IDs emitted by this analyzer.
const (
	RuleDangerousAllScripts  = "NPM_DANGEROUS_ALL_SCRIPTS_001"
	RuleAllowScriptsUnpinned = "NPM_ALLOW_SCRIPTS_UNPINNED_001"
	RuleAllowGitRelaxed      = "NPM_ALLOW_GIT_RELAXED_001"
	RuleAllowRemoteRelaxed   = "NPM_ALLOW_REMOTE_RELAXED_001"
)

// AnalyzerName is the analyzer identifier surfaced on findings.
const AnalyzerName = rulemeta.AnalyzerNpmPolicy

// findingConfidence: the keys are exact and the values explicit; the
// only uncertainty is whether the file is consumed by the npm version
// in use. High, mirroring agent-policy's posture findings.
const findingConfidence = 0.9

// Analyzer implements scanner.Analyzer.
type Analyzer struct{}

// New constructs the npm-policy analyzer.
func New() *Analyzer { return &Analyzer{} }

// Name returns the analyzer identifier.
func (a *Analyzer) Name() string { return AnalyzerName }

// Analyze inspects package.json (allowScripts policy) and project
// .npmrc files for npm v12 trust-model weakenings. Non-target files,
// malformed input, and absent settings all return no findings.
func (a *Analyzer) Analyze(_ context.Context, target *scanner.Target) ([]types.Finding, error) {
	switch filepath.Base(filepath.ToSlash(target.RelPath)) {
	case "package.json":
		return a.analyzePackageJSON(target), nil
	case ".npmrc":
		return a.analyzeNpmrc(target), nil
	default:
		return nil, nil
	}
}

// ---------------------------------------------------------------------------
// package.json: the allowScripts policy field

// analyzePackageJSON flags name-only allowScripts entries whose value is
// true: they approve install scripts for every future version of the
// package, where `npm approve-scripts` would have written a pinned
// `name@version` entry. Deny entries (value false) and pinned allows
// never fire.
func (a *Analyzer) analyzePackageJSON(target *scanner.Target) []types.Finding {
	// Decode the root as a raw map and look up the exact "allowScripts"
	// key: encoding/json struct fields match case-insensitively, but npm
	// reads manifest keys case-sensitively, so a mis-cased field like
	// "AllowScripts" is inert for npm and must stay silent here.
	var root map[string]json.RawMessage
	if err := json.Unmarshal(target.Content, &root); err != nil {
		return nil // malformed JSON: stay silent rather than guess
	}
	rawPolicy, ok := root["allowScripts"]
	if !ok {
		return nil
	}
	var policy map[string]json.RawMessage
	if err := json.Unmarshal(rawPolicy, &policy); err != nil || len(policy) == 0 {
		return nil // wrong type or empty: not a shape npm honors
	}

	// Iterate in sorted key order: Go map order is random, and the
	// scanner deduplicates findings by (file, rule, line), so minified
	// manifests with several entries on one line must emit
	// deterministically across runs.
	keys := make([]string, 0, len(policy))
	for k := range policy {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var findings []types.Finding
	for _, key := range keys {
		raw := policy[key]
		if strings.TrimSpace(string(raw)) != "true" {
			continue // false = deny (always name-only); non-bool = not a shape npm writes
		}
		if isPinnedEntry(key) {
			continue // name@version: the shape approve-scripts writes by default
		}
		if !plausiblePackageName(key) {
			// Ground truth npm 11.16.0: an entry like "*" is not a glob;
			// it could only match a package literally named "*", which
			// cannot exist, so the entry is inert and never flagged.
			continue
		}
		findings = append(findings, a.finding(
			RuleAllowScriptsUnpinned, target,
			allowScriptsEntryLine(target.Content, key),
			fmt.Sprintf("allowScripts entry %q is name-only with value true: install scripts are approved for every future version of the package, not the version that was reviewed.", key),
			key+": true",
		))
	}
	return findings
}

// plausiblePackageName reports whether key could name a real npm
// package (letters, digits, @scope/ separators, ., _, -). Keys with
// glob or whitespace characters cannot match any installable package,
// so npm's allowScripts evaluation never honors them.
func plausiblePackageName(key string) bool {
	if key == "" {
		return false
	}
	for _, r := range key {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '@' || r == '/' || r == '.' || r == '_' || r == '-':
		default:
			return false
		}
	}
	return true
}

// isPinnedEntry reports whether an allowScripts key carries a version
// pin (`name@version`, including scoped `@scope/name@version`). A
// scoped name's leading "@" is not a pin.
func isPinnedEntry(key string) bool {
	return strings.LastIndex(key, "@") > 0
}

// ---------------------------------------------------------------------------
// .npmrc: project config

// analyzeNpmrc evaluates the project .npmrc. npm's ini config applies
// last-wins precedence for repeated top-level keys (ground truth npm
// 11.16.0: `allow-git=all` followed by `allow-git=none` is effectively
// "none"), so values are collected first and each key is evaluated once
// on its final value. For boolean keys, both a bare `key` line and an
// empty `key=` assignment read as true (also ground-truthed); for the
// enum keys an empty value is not a relaxation and stays silent.
func (a *Analyzer) analyzeNpmrc(target *scanner.Target) []types.Finding {
	type kv struct {
		val  string
		bare bool
		line int
		raw  string
	}
	last := make(map[string]kv, 4)
	inSection := false
	for i, rawLine := range strings.Split(string(target.Content), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			inSection = true // npm does not read these keys from ini sections
			continue
		}
		if inSection {
			continue
		}
		key, val, bare := splitNpmrcLine(line)
		switch key {
		case "dangerously-allow-all-scripts", "allow-scripts-pin", "allow-git", "allow-remote":
			last[key] = kv{val: val, bare: bare, line: i + 1, raw: line}
		}
	}

	var findings []types.Finding
	for key, e := range last {
		if strings.Contains(e.val, "${") {
			continue // env-expanded value: ambiguous, skip rather than guess
		}
		switch key {
		case "dangerously-allow-all-scripts":
			// Boolean: bare key, empty assignment, and explicit true all
			// read as enabled in npm's ini dialect.
			if e.bare || e.val == "" || e.val == "true" {
				findings = append(findings, a.finding(
					RuleDangerousAllScripts, target, e.line,
					"dangerously-allow-all-scripts=true bypasses the allowScripts policy entirely: every dependency install script runs regardless of approval or denial. npm documents it as a migration escape hatch whose use is strongly discouraged.",
					e.raw,
				))
			}
		case "allow-scripts-pin":
			if e.val == "false" {
				findings = append(findings, a.finding(
					RuleAllowScriptsUnpinned, target, e.line,
					"allow-scripts-pin=false makes `npm approve-scripts` write name-only allowScripts entries, approving install scripts for every future version instead of the version that was reviewed.",
					e.raw,
				))
			}
		case "allow-git":
			if e.val == "all" || e.val == "root" {
				findings = append(findings, a.finding(
					RuleAllowGitRelaxed, target, e.line,
					fmt.Sprintf("allow-git=%s pins git-dependency resolution open; npm v12 defaults it to \"none\" because a git dependency's own .npmrc can override the git executable, a code-execution path that survives --ignore-scripts. %s", e.val, relaxScope(e.val)),
					e.raw,
				))
			}
		case "allow-remote":
			if e.val == "all" || e.val == "root" {
				findings = append(findings, a.finding(
					RuleAllowRemoteRelaxed, target, e.line,
					fmt.Sprintf("allow-remote=%s pins remote-tarball dependency resolution open; npm v12 defaults it to \"none\" so unreviewed URL sources need an explicit decision. %s", e.val, relaxScope(e.val)),
					e.raw,
				))
			}
		}
	}
	return findings
}

// relaxScope phrases how far a "all"/"root" value opens resolution.
func relaxScope(val string) string {
	if val == "root" {
		return "\"root\" limits this to direct dependencies, a bounded but still explicit relaxation."
	}
	return "\"all\" extends this to transitive dependencies as well."
}

// splitNpmrcLine splits an .npmrc line into key, value, and whether the
// line was a bare key (which npm's ini dialect reads as true).
//
// Ground truth against npm 11.16.0:
//   - inline comments on unquoted values are stripped regardless of
//     preceding whitespace (`allow-git=all#note` reads as "all");
//   - a fully quoted value is unquoted (`allow-git="all"` reads "all");
//   - a quoted value followed by trailing content keeps its quotes
//     literally (`allow-git="all" # temporary` reads the string
//     `"all"`, which is not a valid enum value, so the setting is NOT
//     honored). Such values are returned verbatim so they never match
//     our enum/boolean comparisons.
func splitNpmrcLine(line string) (key, val string, bare bool) {
	eq := strings.Index(line, "=")
	if eq < 0 {
		k := line
		if i := strings.IndexAny(k, "#;"); i >= 0 {
			k = k[:i]
		}
		return strings.TrimSpace(k), "", true
	}
	key = strings.TrimSpace(line[:eq])
	raw := strings.TrimSpace(line[eq+1:])
	if len(raw) >= 2 && (raw[0] == '"' || raw[0] == '\'') {
		q := raw[0]
		if raw[len(raw)-1] == q && strings.IndexByte(raw[1:len(raw)-1], q) < 0 {
			return key, raw[1 : len(raw)-1], false // fully quoted: unquote
		}
		return key, raw, false // quoted + trailing junk: kept literal by npm
	}
	if i := strings.IndexAny(raw, "#;"); i >= 0 {
		raw = strings.TrimSpace(raw[:i])
	}
	return key, raw, false
}

// ---------------------------------------------------------------------------

// finding assembles a Finding with metadata derived from the catalog,
// so emit-site name/severity/category cannot drift from explain output.
func (a *Analyzer) finding(ruleID string, target *scanner.Target, line int, desc, matched string) types.Finding {
	meta := ruleIndex[ruleID]
	return types.Finding{
		RuleID:      ruleID,
		RuleName:    meta.Name,
		Severity:    meta.SeverityLevel(),
		Category:    meta.Category,
		FilePath:    target.RelPath,
		Line:        line,
		Description: desc,
		MatchedText: matched,
		Remediation: meta.Remediation,
		Analyzer:    AnalyzerName,
		Confidence:  findingConfidence,
	}
}

// allowScriptsEntryLine locates an allowScripts entry key in the raw
// manifest. It tries the literal spelling first, then the
// JSON-escaped-slash spelling (`@scope\/pkg`, produced by some
// serializers and decoded identically by json.Unmarshal), and finally
// falls back to the allowScripts block itself so the finding always
// carries a valid 1-based line.
func allowScriptsEntryLine(content []byte, key string) int {
	if l := lineOfAfter(content, `"allowScripts"`, `"`+key+`"`); l > 0 {
		return l
	}
	escaped := strings.ReplaceAll(key, "/", `\/`)
	if escaped != key {
		if l := lineOfAfter(content, `"allowScripts"`, `"`+escaped+`"`); l > 0 {
			return l
		}
	}
	if l := lineOfAfter(content, `"allowScripts"`, `"allowScripts"`); l > 0 {
		return l
	}
	// Exotic but valid JSON encodings (e.g. a unicode-escaped property
	// name) can defeat every literal anchor; keep the 1-based contract.
	return 1
}

// lineOfAfter locates needle at or after the first occurrence of
// anchor and returns its 1-based line number (0 when not found). The
// anchor keeps allowScripts findings pointing inside the policy block
// even when the same package name appears earlier in the manifest
// (for example under dependencies).
func lineOfAfter(content []byte, anchor, needle string) int {
	text := string(content)
	start := strings.Index(text, anchor)
	if start < 0 {
		return 0
	}
	idx := strings.Index(text[start:], needle)
	if idx < 0 {
		return 0
	}
	return strings.Count(text[:start+idx], "\n") + 1
}

// ruleIndex is built once from RuleMetadata so finding() lookups are
// O(1) and guaranteed present (rulecatalog tests lock the set).
var ruleIndex = func() map[string]rulemeta.Rule {
	m := make(map[string]rulemeta.Rule)
	for _, r := range RuleMetadata() {
		m[r.ID] = r
	}
	return m
}()
