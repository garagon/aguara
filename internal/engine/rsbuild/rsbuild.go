// Package rsbuild is a small, auditable analyzer for Cargo build
// scripts (build.rs). It upgrades RS_BUILD_WALLET_EXFIL_001 from
// co-presence ("a wallet/keystore read AND a network sink somewhere in
// build.rs") to a real binding: the material sent over the network must
// trace back, in one or two simple let-binding hops, to a read of a
// wallet/keystore path.
//
// It is deliberately NOT a Rust parser. It works on lines, tracks let
// bindings, and propagates taint at most two hops. When the shape is
// more complex than that, it stays silent rather than guess. It follows
// the binding-analyzer contract: a proven source, a bound value, and a
// real exfil sink that the bound value reaches.
package rsbuild

import (
	"context"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/garagon/aguara/internal/rulemeta"
	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/types"
)

// RuleBuildWalletExfil is the (analyzer-emitted) rule ID, unchanged from
// the retired YAML rule.
const RuleBuildWalletExfil = "RS_BUILD_WALLET_EXFIL_001"

// AnalyzerName is the analyzer identifier surfaced on findings.
const AnalyzerName = rulemeta.AnalyzerRSBuild

// maxHops bounds taint propagation (the read result is depth 0).
const maxHops = 2

// Analyzer implements scanner.Analyzer.
type Analyzer struct{}

// New constructs the rsbuild analyzer.
func New() *Analyzer { return &Analyzer{} }

// Name returns the analyzer identifier.
func (a *Analyzer) Name() string { return AnalyzerName }

var (
	// letRe matches `let [mut] name [: Type] = <rhs>`; group 1 is the
	// bound name, group 2 the right-hand side.
	letRe = regexp.MustCompile(`^let\s+(?:mut\s+)?([A-Za-z_]\w*)\s*(?::[^=]+)?=\s*(.+)$`)

	// walletReadRe matches a wallet/keystore path read through an actual
	// Rust read/open call (within the same statement). A path that is
	// merely constructed (format!/PathBuf/join) without a read API does
	// not match.
	walletReadRe = regexp.MustCompile(`(?i)(read_to_string|read_to_end|fs::read\b|File::open)[^;]{0,120}(sui\.keystore|\.sui/|\.solana/|solana/id\.json|\.aptos/|wallet\.dat|\.electrum/|keystore\.json)`)

	// networkSinkRe matches a network exfil sink.
	networkSinkRe = regexp.MustCompile(`(?i)(reqwest::|ureq::|hyper::Client|surf::|isahc::|api\.github\.com/gists|gist\.github\.com|TcpStream::connect)`)

	// sendMethodRe matches the call sites that actually put a value ON the
	// wire: request bodies (.body/.json/.send_json/.send_string) and raw
	// socket writes (.write_all/.write). .send is included only when it
	// carries an argument (the no-arg reqwest .send() terminal contributes
	// no material). Group 1 is the method name; the match ends just past
	// the opening paren so the argument can be extracted with balanced
	// parens. Merely referencing the tainted variable elsewhere on the
	// line (a separate statement, a debug bind, a println!) is not a send.
	sendMethodRe = regexp.MustCompile(`\.(body|json|send_json|send_string|write_all|write|send)\s*\(`)

	// identRe extracts bare identifiers for taint propagation / sink
	// reference checks.
	identRe = regexp.MustCompile(`[A-Za-z_]\w*`)
)

// Analyze reports RS_BUILD_WALLET_EXFIL_001 when a network sink in
// build.rs sends material bound (<= maxHops) to a wallet/keystore read.
//
// Single in-order, flow-sensitive pass: let bindings update taint as
// they are seen (and CLEAR it when a variable is rebound to something
// that does not trace back to a read); a network sink fires only when it
// references a currently tainted variable at the sink's position.
func (a *Analyzer) Analyze(_ context.Context, target *scanner.Target) ([]types.Finding, error) {
	if !isTarget(target) || len(target.Content) == 0 {
		return nil, nil
	}

	taint := map[string]int{} // var -> hop depth (0 = the read result)

	for _, ln := range codeLines(string(target.Content)) {
		// 1. Apply a let binding's effect on taint first.
		if m := letRe.FindStringSubmatch(ln.text); m != nil {
			lhs, rhs := m[1], m[2]
			switch {
			case walletReadRe.MatchString(rhs):
				taint[lhs] = 0
			default:
				if d, ok := derivedDepth(rhs, taint); ok {
					taint[lhs] = d
				} else {
					// Rebound to something that does not trace back to a
					// wallet read: clear any prior taint (Rust shadowing).
					delete(taint, lhs)
				}
			}
		}

		// 2. The bound exfil finding requires BOTH a network sink on the
		//    line AND the tainted material appearing inside a send/body
		//    argument on that sink (not merely referenced somewhere on the
		//    line). That is the difference between "key reaches the request"
		//    and "key is mentioned next to a request".
		if networkSinkRe.MatchString(ln.text) && sinkSendsTainted(ln.text, taint) {
			return []types.Finding{{
				RuleID:      RuleBuildWalletExfil,
				RuleName:    "Rust build.rs wallet/keystore exfiltration",
				Severity:    types.SeverityCritical,
				Category:    "supply-chain",
				Description: "A Cargo build script reads wallet/keystore material and sends it over the network: the value reaching the network sink traces back to the keystore read.",
				FilePath:    target.RelPath,
				Line:        ln.num,
				MatchedText: strings.TrimSpace(ln.text),
				Remediation: "Build scripts must never read wallet or keystore material or open network connections to send it. Remove the keystore read and the network sink from build.rs. Audit the host and rotate any wallet keys, mnemonics, or signing keys reachable from the build environment.",
				Analyzer:    AnalyzerName,
			}}, nil
		}
	}
	return nil, nil
}

// derivedDepth returns the taint depth lhs would take if rhs derives from
// a currently tainted variable (shallowest referenced taint + 1), and
// whether that is within the hop limit. Covers transforms like
// base64::encode(key) and xor(key, ...) and direct rebinds.
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

// sinkSendsTainted reports whether any send/body method call on the line
// carries a currently tainted variable inside its (balanced-paren)
// argument. This is what proves the material reaches the wire, rather
// than merely sitting in an unrelated statement on the same line
// (e.g. `let _dbg = &key; ureq::get(url).call();` or a trailing
// `println!("{}", key);`).
func sinkSendsTainted(line string, taint map[string]int) bool {
	for _, loc := range sendMethodRe.FindAllStringIndex(line, -1) {
		// loc[1]-1 is the opening paren of the matched method call.
		if referencesTainted(balancedArg(line, loc[1]-1), taint) {
			return true
		}
	}
	return false
}

// balancedArg returns the argument substring of a call whose opening
// paren is at index open, tracking nested parens. If the parens do not
// close on the line (a statement split across lines), it returns the
// remainder, which the single-line model treats as the argument.
func balancedArg(s string, open int) string {
	depth := 0
	start := open + 1
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return s[start:i]
			}
		}
	}
	return s[start:]
}

func referencesTainted(line string, taint map[string]int) bool {
	for _, id := range identRe.FindAllString(line, -1) {
		if _, ok := taint[id]; ok {
			return true
		}
	}
	return false
}

func isTarget(t *scanner.Target) bool {
	if t == nil {
		return false
	}
	for _, p := range []string{t.Path, t.RelPath} {
		if p == "" {
			continue
		}
		if filepath.Base(filepath.ToSlash(p)) == "build.rs" {
			return true
		}
	}
	return false
}

type codeLine struct {
	num  int
	text string
}

// codeLines strips // line comments and /* */ block comments (so a
// commented-out read or a doc comment does not produce a finding) and
// returns de-indented lines with their original line numbers, so let
// bindings inside blocks still match.
func codeLines(src string) []codeLine {
	var out []codeLine
	inBlock := false
	for i, raw := range strings.Split(src, "\n") {
		line := raw
		if inBlock {
			if idx := strings.Index(line, "*/"); idx >= 0 {
				inBlock = false
				line = line[idx+2:]
			} else {
				continue
			}
		}
		line = stripComments(line, &inBlock)
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		out = append(out, codeLine{num: i + 1, text: line})
	}
	return out
}

// stripComments removes // line comments and inline/opening /* ... */
// block comments outside string literals. If a block comment opens and
// does not close on this line, *inBlock is set so subsequent lines are
// skipped until the closing */.
func stripComments(line string, inBlock *bool) string {
	var b strings.Builder
	inStr := false
	for i := 0; i < len(line); i++ {
		if inStr {
			b.WriteByte(line[i])
			if line[i] == '"' && (i == 0 || line[i-1] != '\\') {
				inStr = false
			}
			continue
		}
		if line[i] == '"' {
			inStr = true
			b.WriteByte(line[i])
			continue
		}
		if line[i] == '/' && i+1 < len(line) && line[i+1] == '/' {
			break // rest of line is a comment
		}
		if line[i] == '/' && i+1 < len(line) && line[i+1] == '*' {
			if idx := strings.Index(line[i:], "*/"); idx >= 0 {
				i += idx + 1 // skip past the closing */
				continue
			}
			*inBlock = true
			break
		}
		b.WriteByte(line[i])
	}
	return b.String()
}
