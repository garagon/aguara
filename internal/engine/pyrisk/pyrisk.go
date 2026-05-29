// Package pyrisk is a small, auditable analyzer for Python install/import
// time code (setup.py, __init__.py). It upgrades the
// PY_IMPORTTIME_REMOTE_JS_001 detection from co-presence ("a remote .js
// fetch AND a node -e somewhere in the file") to a real binding: the
// value passed to `node -e` must trace back, in one or two simple hops,
// to a remote-JavaScript fetch.
//
// It is deliberately NOT a Python parser. It works on lines, tracks
// variable assignments, and propagates taint at most two hops. It does
// no interprocedural analysis and resolves no dynamic imports. When the
// shape is more complex than that, it stays silent rather than guess.
package pyrisk

import (
	"context"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/garagon/aguara/internal/rulemeta"
	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/types"
)

// RulePyImportTimeRemoteJS is the (analyzer-emitted) rule ID. It keeps the
// same ID the retired YAML rule used so existing references and the
// catalog entry stay stable.
const RulePyImportTimeRemoteJS = "PY_IMPORTTIME_REMOTE_JS_001"

// AnalyzerName is the analyzer identifier surfaced on findings.
const AnalyzerName = rulemeta.AnalyzerPyRisk

// Analyzer implements scanner.Analyzer.
type Analyzer struct{}

// New constructs the pyrisk analyzer.
func New() *Analyzer { return &Analyzer{} }

// Name returns the analyzer identifier.
func (a *Analyzer) Name() string { return AnalyzerName }

var (
	// assignRe matches `name = <rhs>` (simple LHS identifier only).
	assignRe = regexp.MustCompile(`^([A-Za-z_]\w*)\s*=\s*(.+)$`)

	// jsURLLiteralRe marks a string literal as a JavaScript payload URL:
	// a .js path (optionally with query/fragment) or a known campaign
	// host. Used both for the fetch argument and for a url variable.
	jsURLLiteralRe = regexp.MustCompile(`(?i)(\.js["'?#)\s]|\.js$|ddjidd564\.github\.io|defi-security-best-practices)`)

	// fetchCallRe matches a remote retrieval whose result is read as a
	// string/body: requests.get(...).text, httpx.get(...).text,
	// urllib...urlopen(...).read(), etc. Group 1 is the call argument(s).
	fetchCallRe = regexp.MustCompile(`(?i)(?:requests\.get|httpx\.get|urllib\.request\.urlopen|urllib\.request\.urlretrieve|\burlopen|\burlretrieve)\s*\(([^)]*)\)\s*\.\s*(?:text|read|content)\b`)

	// nodeEvalArgvRe matches an EXECUTION of node -e in argv form:
	// subprocess.run/call/check_call/check_output/Popen(["node", "-e", PAYLOAD]).
	// The execution call is required so merely BUILDING a command list
	// (cmd = ["node", "-e", payload]) does not count -- a CRITICAL rule
	// must see the payload actually run. PAYLOAD must be a bare identifier
	// (a variable); an inline string-literal script is not bound here.
	// (cmd = [...] then subprocess.run(cmd) is intentionally out of scope:
	// it would need a separate command-variable binding hop.)
	nodeEvalArgvRe = regexp.MustCompile(`(?i)subprocess\.(?:run|call|check_call|check_output|Popen)\s*\(\s*\[\s*["']node["']\s*,\s*["'](?:-e|--eval)["']\s*,\s*([A-Za-z_]\w*)\b`)

	// nodeEvalShellRe matches an EXECUTION of node -e in shell-string
	// form: os.system("node -e " + PAYLOAD). The os.system call is
	// required so building a command string without running it does not
	// count; group 1 is the concatenated var.
	nodeEvalShellRe = regexp.MustCompile(`(?i)os\.system\s*\(\s*["']node\s+(?:-e|--eval)\b[^"']*["']\s*\+\s*([A-Za-z_]\w*)\b`)

	// identRe extracts bare identifiers referenced on a RHS, for taint
	// propagation (a hop is "this assignment references a tainted var").
	identRe = regexp.MustCompile(`[A-Za-z_]\w*`)
)

// maxHops bounds taint propagation (the source itself is depth 0; a
// node -e on a var up to 2 derivation hops away binds).
const maxHops = 2

// Analyze reports PY_IMPORTTIME_REMOTE_JS_001 when a node -e payload is
// bound (<= maxHops) to a remote-JavaScript fetch in the same file.
//
// The analysis is a single in-order, flow-sensitive pass: variable taint
// is updated as assignments are seen (and CLEARED when a variable is
// reassigned to something that does not trace back to a fetch), and a
// sink is evaluated against the taint state at the point the sink
// appears. This way a sink before the fetch, a tainted variable later
// overwritten by a safe literal, and a same-named-but-safe variable at
// the sink all correctly do NOT fire.
func (a *Analyzer) Analyze(_ context.Context, target *scanner.Target) ([]types.Finding, error) {
	if !isTarget(target) || len(target.Content) == 0 {
		return nil, nil
	}

	// taint[var] = hop depth (0 = the fetch result itself). Absence means
	// untainted. jsURLVars[var] = assigned a .js / campaign-host literal.
	taint := map[string]int{}
	jsURLVars := map[string]bool{}

	for _, ln := range codeLines(string(target.Content)) {
		// 1. Apply an assignment's effect on taint state first, so a
		//    reassignment on this line is reflected before any sink on
		//    the same line is evaluated.
		if m := assignRe.FindStringSubmatch(ln.text); m != nil {
			lhs, rhs := m[1], m[2]
			switch {
			case isJSFetch(rhs, jsURLVars):
				taint[lhs] = 0
				delete(jsURLVars, lhs)
			default:
				if d, ok := derivedDepth(rhs, taint); ok {
					// 1- or 2-hop derivation of a currently tainted var.
					taint[lhs] = d
					delete(jsURLVars, lhs)
				} else {
					// Reassigned to something that does not trace back to
					// a fetch: clear any prior taint on this variable.
					delete(taint, lhs)
					if isStringLiteralAssign(rhs) && jsURLLiteralRe.MatchString(rhs) {
						jsURLVars[lhs] = true
					} else {
						delete(jsURLVars, lhs)
					}
				}
			}
		}

		// 2. A node -e sink whose payload variable is tainted RIGHT NOW
		//    is the bound finding.
		if payload := nodeEvalPayloadVar(ln.text); payload != "" {
			if _, ok := taint[payload]; ok {
				return []types.Finding{{
					RuleID:      RulePyImportTimeRemoteJS,
					RuleName:    "PyPI import-time remote JavaScript execution",
					Severity:    types.SeverityCritical,
					Category:    "supply-chain",
					Description: "A remote JavaScript payload fetched at install/import time is passed to node -e: the value executed traces back to the download.",
					FilePath:    target.RelPath,
					Line:        ln.num,
					MatchedText: strings.TrimSpace(ln.text),
					Remediation: "Remove the remote fetch and Node execution from package import/setup code. Packages must never download and run remote code at install or import time. Audit the host for credential exposure and rotate any tokens reachable from the build or import environment.",
					Analyzer:    AnalyzerName,
				}}, nil
			}
		}
	}
	return nil, nil
}

// derivedDepth reports the taint depth lhs would take if rhs derives from
// a currently tainted variable (the shallowest referenced taint + 1),
// and whether that is within the hop limit. Returns ok=false when rhs
// references no tainted variable or the derivation would exceed maxHops.
func derivedDepth(rhs string, taint map[string]int) (int, bool) {
	best := -1
	for _, id := range identRe.FindAllString(rhs, -1) {
		if d, ok := taint[id]; ok && (best == -1 || d < best) {
			best = d
		}
	}
	if best == -1 {
		return 0, false
	}
	if nd := best + 1; nd <= maxHops {
		return nd, true
	}
	return 0, false
}

// isJSFetch reports whether rhs is a remote-JavaScript fetch: a fetch
// call whose argument contains a .js / campaign-host literal, or whose
// argument is a variable previously assigned such a literal (one hop on
// the URL side).
func isJSFetch(rhs string, jsURLVars map[string]bool) bool {
	m := fetchCallRe.FindStringSubmatch(rhs)
	if m == nil {
		return false
	}
	arg := m[1]
	if jsURLLiteralRe.MatchString(arg) {
		return true
	}
	for _, id := range identRe.FindAllString(arg, -1) {
		if jsURLVars[id] {
			return true
		}
	}
	return false
}

// nodeEvalPayloadVar returns the variable passed to node -e / --eval on
// this line (argv or shell-concat form), or "" if there is none / it is
// an inline literal rather than a variable.
func nodeEvalPayloadVar(line string) string {
	if m := nodeEvalArgvRe.FindStringSubmatch(line); m != nil {
		return m[1]
	}
	if m := nodeEvalShellRe.FindStringSubmatch(line); m != nil {
		return m[1]
	}
	return ""
}

// isStringLiteralAssign reports whether rhs looks like a plain string
// literal assignment (so `url = "...p.js"` taints url as a js-url var,
// but `url = build_url()` does not).
func isStringLiteralAssign(rhs string) bool {
	t := strings.TrimSpace(rhs)
	return strings.HasPrefix(t, `"`) || strings.HasPrefix(t, `'`) ||
		strings.HasPrefix(t, `f"`) || strings.HasPrefix(t, `f'`)
}

func isTarget(t *scanner.Target) bool {
	if t == nil {
		return false
	}
	for _, p := range []string{t.Path, t.RelPath} {
		if p == "" {
			continue
		}
		base := filepath.Base(filepath.ToSlash(p))
		if base == "setup.py" || base == "__init__.py" {
			return true
		}
	}
	return false
}

type codeLine struct {
	num  int
	text string
}

// codeLines strips comments and docstrings so a commented-out or
// documented fetch/eval does not produce a finding. It removes `#`
// line comments (naively, at the first '#' outside a quote) and skips
// lines inside triple-quoted blocks.
func codeLines(src string) []codeLine {
	var out []codeLine
	inDoc := false
	var docDelim string
	for i, raw := range strings.Split(src, "\n") {
		line := raw
		if inDoc {
			if idx := strings.Index(line, docDelim); idx >= 0 {
				inDoc = false
				line = line[idx+len(docDelim):]
			} else {
				continue
			}
		}
		// Opening triple-quote that does not close on the same line
		// starts a docstring block.
		for _, d := range []string{`"""`, `'''`} {
			if idx := strings.Index(line, d); idx >= 0 {
				if rest := line[idx+len(d):]; !strings.Contains(rest, d) {
					inDoc = true
					docDelim = d
					line = line[:idx]
					break
				}
			}
		}
		line = strings.TrimSpace(stripLineComment(line))
		if line == "" {
			continue
		}
		// Store the de-indented line so assignment matching (^name = ...)
		// works inside try:, def, with, and other indented blocks, which
		// are common in setup.py / __init__.py. The original line number
		// is preserved for the finding.
		out = append(out, codeLine{num: i + 1, text: line})
	}
	return out
}

// stripLineComment removes a trailing/whole-line `#` comment, ignoring
// `#` that appears inside a single- or double-quoted string.
func stripLineComment(line string) string {
	inSingle, inDouble := false, false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble {
				return line[:i]
			}
		}
	}
	return line
}
