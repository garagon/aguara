package jsrisk

import (
	"bytes"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The lexer walkers used to classify the slash after a `)` by walking back
// to the matching `(` on every question. regexContext answers from a
// forward paren stack instead. Two kinds of reference are kept here:
//
//   - backwardMatchingOpen is the unbounded backward scan to the matching
//     `(`. A regexContext that uses it instead of the stack must read every
//     input exactly like the production one, in both dialects;
//   - mainCouldBeRegexStart (the JavaScript classifier before TypeScript
//     support, copied verbatim) and backwardCouldBeRegexStart (the same plus
//     the TypeScript non-null check as it was before brace tracking) are
//     the classifiers the brace-aware one replaced. Their answers may differ
//     from the current ones only at the shapes listed in intendedChange.

// backwardMatchingOpen returns the offset of the `(` matching the `)` at
// closeParen by counting backwards, or -1.
func backwardMatchingOpen(buf []byte, closeParen int) int {
	depth := 1
	for k := closeParen - 1; k >= 0; k-- {
		switch buf[k] {
		case ')':
			depth++
		case '(':
			depth--
			if depth == 0 {
				return k
			}
		}
	}
	return -1
}

func mainCouldBeRegexStart(content []byte, i int) bool {
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

func backwardCouldBeRegexStart(content []byte, i int) bool {
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
	if c == '!' && backwardBangIsNonNull(content, j) {
		return false
	}
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

func backwardBangIsNonNull(content []byte, bang int) bool {
	if bang == 0 {
		return false
	}
	isJSIdentByte := func(b byte) bool {
		return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_' || b == '$'
	}
	k := bang - 1
	c := content[k]
	switch {
	case c == ']':
		return true
	case c == ')':
		depth := 1
		k--
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
		for k >= 0 && (content[k] == ' ' || content[k] == '\t' || content[k] == '\r' || content[k] == '\n') {
			k--
		}
		end := k + 1
		for k >= 0 && isJSIdentByte(content[k]) {
			k--
		}
		switch string(content[k+1 : end]) {
		case "if", "while", "for", "switch", "catch", "with":
			return false
		case "await":
			j := k
			for j >= 0 && (content[j] == ' ' || content[j] == '\t' || content[j] == '\r' || content[j] == '\n') {
				j--
			}
			wordEnd := j + 1
			for j >= 0 && isJSIdentByte(content[j]) {
				j--
			}
			if string(content[j+1:wordEnd]) == "for" {
				return false
			}
		}
		return true
	case isJSIdentByte(c):
		end := k + 1
		for k >= 0 && isJSIdentByte(content[k]) {
			k--
		}
		switch string(content[k+1 : end]) {
		case "return", "typeof", "instanceof", "in", "of", "delete", "void", "new",
			"throw", "yield", "await", "case", "default", "do", "else":
			return false
		}
		return true
	}
	return false
}

func indexClassifier(buf []byte) regexClassifier { return newRegexContext(buf) }

func typeScriptIndexClassifier(buf []byte) regexClassifier {
	return (&jsLexer{typescript: true}).context(buf)
}

// backwardScanClassifier is the production classifier with the paren stack
// replaced by backwardMatchingOpen.
func backwardScanClassifier(typescript bool) func([]byte) regexClassifier {
	return func(buf []byte) regexClassifier {
		rc := newRegexContext(buf)
		rc.typescript = typescript
		rc.findOpen = backwardMatchingOpen
		return rc
	}
}

// lexerViews runs both walkers the way the analyzer does: comment and regex
// masking over the raw bytes, string interiors over the masked view, and
// string interiors over the raw bytes (the DNS TXT detector's second pass).
type lexerViews struct {
	code    []byte
	strings [][2]int
	rawStrs [][2]int
}

func viewsWith(src []byte, classifier func([]byte) regexClassifier) lexerViews {
	code := stripJSCommentsWith(src, classifier)
	return lexerViews{
		code:    code,
		strings: jsStringInteriorsWith(code, classifier),
		rawStrs: jsStringInteriorsWith(src, classifier),
	}
}

func sameViews(a, b lexerViews) bool {
	return bytes.Equal(a.code, b.code) && reflect.DeepEqual(a.strings, b.strings) && reflect.DeepEqual(a.rawStrs, b.rawStrs)
}

// lexerDifferentialPieces are the token shapes the generator combines:
// unbalanced and nested parentheses and braces, parentheses inside strings,
// template literals with interpolation, regex literals and character
// classes, comments, escapes, keywords that precede regex literals, brace
// openers (function and arrow bodies, object literals, labels), update
// operators, property names spelled like keywords, and non-null
// assertions.
var lexerDifferentialPieces = []string{
	"(", ")", "((", "))", "/", "/", "//", "/*", "*/", "!", "! ", "[", "]", "{", "}",
	"'", "\"", "`", "${", "\\", "\n", " ", "\t", "if", "if (", "while", "for", "return",
	"typeof", "x", "ab", "=", "+", ",", ";", ":", "?", "*", "2", "/re/", "/[/]/g",
	"'(/'", "\")\"", "`${a(}`", "a!", "f()!", "xs[0]!", "(x)", "catch", "in", "do",
	"<", ">", "&&", "||", ".", "%", "} ", "{}", "else", "default", "of", "=>", "++", "--",
	"function", "function f()", "class A", ".default", "?.new", "const {", "with (", "for await (",
	"'x'!", "`t`!", "\r\n", ".catch(", "p.if (", "#do", ".\n", "// c.\n", "? 1 : {", "> {", "<T>", ": T {",
	"class extends B", "function someLongName()",
}

// plainLexerPieces leaves out `!`, so snippets built from them read the
// same in both dialects.
var plainLexerPieces = func() []string {
	var out []string
	for _, p := range lexerDifferentialPieces {
		if !strings.Contains(p, "!") {
			out = append(out, p)
		}
	}
	return out
}()

func randomLexerSnippet(r *rand.Rand, pieces []string, maxPieces int) []byte {
	var b strings.Builder
	for n := r.Intn(maxPieces); n > 0; n-- {
		b.WriteString(pieces[r.Intn(len(pieces))])
	}
	return []byte(b.String())
}

// Real-world-style snippets: minified and formatted code with regex
// literals after control-flow headers, divisions after calls, template
// literals, comments containing slashes and quotes, and TypeScript.
var lexerDifferentialSamples = []string{
	"if(a)/x/.test(b)&&c();var d=e(f)/2,g=/\\//g;",
	"while (i < n) /=/.exec(s); // trailing ` quote",
	"const r = (a + b) / (c - d); const t = `${(a)/2} and ${/x/.source}`;",
	"for (const k of o) /[)(]/.test(k) ? f(k) : g(k);",
	"x = y\n/re/g.exec(z)\nreturn!/^a/.test(e)",
	"function f(){return /\\d+/.exec(s)}; f() / 3;",
	"if ((a && b) || (c(d) / e)) /done/.test(x);",
	"/* (( */ a = b(/* ) */) / 2; '(' + \")\" + `(${')'}`;",
	"switch (v) { case 1: /x/.test(v); }",
	"const n = total! / count; const m = xs[0]! / 2; const q = f()! / 4;",
	"if (x) !/re/.test(s); y = !/re/.test(z);",
	"catch (e) /x/.test(e.message)",
	"if (a) { b(); } /`/.test(s); f(1); // `",
	"export default /`/.test(s);\nconst o = {a: 1} / 2; const f = function () {} / 3;\n// `",
	"const p = () => {}\n/re/.test(s); i++ / 2; --j / 3; x = cfg.default / 2;",
	"for (const m of /x/g.exec(s)) {} const of = 4; y = of / 2; if (a) b(); else /e/.test(c);",
	"const s = 'unterminated\nfetch(x); const r = a / b; const t = '/`';\nnext();",
}

// structuredLexerHeaders builds headers of chosen lengths around the
// distances that matter to a bounded scan: a keyword or callee, `(`, nested
// groups and filler, `)`, then a slash read as a regex literal or as a
// division, with code after it that a misreading would hide.
func structuredLexerHeaders(r *rand.Rand) [][]byte {
	var out [][]byte
	heads := []string{"if", "while", "for", "switch", "catch", "f", "return", "x =", ""}
	tails := []string{" /`/.test(s); g(1); // `", " / 2; const s = '/`'; g(1); // `", "! / 2; h('`');", " !/x/.test(y);"}
	for _, length := range []int{0, 1, 10, 500, 1023, 1024, 1025, 2000, 5000} {
		for _, head := range heads {
			for _, tail := range tails {
				for _, depth := range []int{0, 1, 3} {
					filler := string(randomLexerSnippet(r, []string{"a", " ", "+", "b.c", "'x'", "\"x\"", "1", ","}, length+1))
					body := strings.Repeat("(", depth) + filler + strings.Repeat(")", depth)
					out = append(out, []byte(head+" ("+body+")"+tail))
				}
			}
		}
	}
	return out
}

// maxDecisionCheckInput bounds the inputs whose decisions are compared with
// the previous classifiers, whose backward scans make long inputs slow;
// short inputs cover every shape.
const maxDecisionCheckInput = 4096

// checkLexerDifferential compares, on one input, each dialect's reading with
// the same classifier using the backward scan for parentheses, and checks
// that the two dialects read an input without `!` the same way. On inputs
// up to maxDecisionCheckInput bytes every classifier decision is also
// compared with the classifier brace tracking replaced
// (checkDecisionsAgainstMain).
func checkLexerDifferential(t *testing.T, src []byte) {
	t.Helper()
	js := viewsWith(src, indexClassifier)
	if want := viewsWith(src, backwardScanClassifier(false)); !sameViews(js, want) {
		t.Fatalf("JavaScript reading differs from the backward scan on %q", src)
	}
	ts := viewsWith(src, typeScriptIndexClassifier)
	if want := viewsWith(src, backwardScanClassifier(true)); !sameViews(ts, want) {
		t.Fatalf("TypeScript reading differs from the backward scan on %q", src)
	}
	if !bytes.Contains(src, []byte("!")) && !sameViews(js, ts) {
		t.Fatalf("JavaScript and TypeScript read %q differently without a `!`", src)
	}
	if len(src) <= maxDecisionCheckInput {
		checkDecisionsAgainstMain(t, src)
	}
}

// decisionRecorder wraps a classifier and compares every answer with the
// classifier that brace tracking replaced, on the same buffer at the same
// moment of the pass.
type decisionRecorder struct {
	*regexContext
	t   *testing.T
	src []byte
}

func (d decisionRecorder) regexStartsAt(i int) bool {
	got := d.regexContext.regexStartsAt(i)
	old := mainCouldBeRegexStart(d.buf, i)
	if d.typescript {
		old = backwardCouldBeRegexStart(d.buf, i)
	}
	if got != old && !intendedChange(d.regexContext, i) {
		d.t.Fatalf("slash at %d of %q: regex=%v, previous classifier %v, at a shape the change does not cover", i, d.src, got, old)
	}
	return got
}

// checkDecisionsAgainstMain runs the masking pass and the raw string pass,
// whose buffers differ (comments blanked or not), in both dialects.
func checkDecisionsAgainstMain(t *testing.T, src []byte) {
	t.Helper()
	for _, typescript := range []bool{false, true} {
		rec := func(buf []byte) regexClassifier {
			rc := newRegexContext(buf)
			rc.typescript = typescript
			return decisionRecorder{regexContext: rc, t: t, src: src}
		}
		stripJSCommentsWith(src, rec)
		jsStringInteriorsWith(src, rec)
	}
}

// intendedChange reports whether the slash at i follows one of the shapes
// whose reading the brace-aware classifier changed: a `}`, `else`,
// `default` or `of`, a property name spelled like a keyword (private names
// and a dot at the end of the line above included), a postfix `++` or
// `--`, a `with (...)` or `for await (...)` header, a method named like a
// statement keyword (`p.catch(f)`) and, in TypeScript, a `!` after any of
// these, a closing quote or backtick, or a `}`.
func intendedChange(rc *regexContext, i int) bool {
	buf := rc.buf
	j := i - 1
	for j >= 0 && (buf[j] == ' ' || buf[j] == '\t' || buf[j] == '\r') {
		j--
	}
	if j < 0 {
		return false
	}
	wordChanged := func(end int) bool {
		word := keywordEndingAt(buf, end)
		if word == "" {
			return false
		}
		switch word {
		case "else", "default", "of":
			return true
		}
		return rc.afterDot(end - len(word))
	}
	// headerChanged reports whether the `)` at k closes a `with (...)` or
	// `for await (...)` header or a method named like a statement keyword
	// (`p.catch(f)`).
	headerChanged := func(k int) bool {
		open := backwardMatchingOpen(buf, k)
		if open < 0 {
			return false
		}
		word := keywordBefore(buf, open)
		switch word {
		case "with", "await":
			return true
		}
		e := open - 1
		for e >= 0 && (buf[e] == ' ' || buf[e] == '\t' || buf[e] == '\r' || buf[e] == '\n') {
			e--
		}
		return word != "" && rc.afterDot(e+1-len(word))
	}
	switch c := buf[j]; {
	case c == '}':
		return true
	case c == '+' || c == '-':
		return j > 0 && buf[j-1] == c
	case c == ')':
		return headerChanged(j)
	case c == '!' && rc.typescript && j > 0:
		p := buf[j-1]
		if p == '\'' || p == '"' || p == '`' || p == '}' {
			return true
		}
		if p == ')' {
			return headerChanged(j - 1)
		}
		return isJSIdentifierByte(p) && wordChanged(j)
	case isJSIdentifierByte(c):
		return wordChanged(j + 1)
	}
	return false
}

func TestRegexContextMatchesBackwardScan(t *testing.T) {
	r := rand.New(rand.NewSource(20261124))
	inputs := make([][]byte, 0, 52000)
	for _, s := range lexerDifferentialSamples {
		inputs = append(inputs, []byte(s))
	}
	for i := 0; i < 50000; i++ {
		inputs = append(inputs, randomLexerSnippet(r, lexerDifferentialPieces, 60))
	}
	// Long inputs put matching parentheses thousands of bytes apart.
	for i := 0; i < 150; i++ {
		inputs = append(inputs, randomLexerSnippet(r, lexerDifferentialPieces, 4000))
		inputs = append(inputs, randomLexerSnippet(r, plainLexerPieces, 4000))
	}
	inputs = append(inputs, structuredLexerHeaders(r)...)
	for _, src := range inputs {
		checkLexerDifferential(t, src)
	}
	t.Logf("%d inputs: each dialect identical to the backward scan, decisions changed only at the intended shapes", len(inputs))
}

// TestRegexContextMatchesBackwardScanOnDirectory repeats the differential
// over real files when AGUARA_LEXER_DIFF_DIR names a directory.
func TestRegexContextMatchesBackwardScanOnDirectory(t *testing.T) {
	dir := os.Getenv("AGUARA_LEXER_DIFF_DIR")
	if dir == "" {
		t.Skip("AGUARA_LEXER_DIFF_DIR not set")
	}
	files := 0
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts":
		default:
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files++
		checkLexerDifferential(t, src)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d files: each dialect identical to the backward scan, decisions changed only at the intended shapes", files)
}

// Each walker pass consumes every byte into the paren stack at most once,
// whatever the nesting depth.
func TestRegexContextConsumesEachByteOnce(t *testing.T) {
	n := 48 * 1024 / 5
	inputs := map[string][]byte{
		"non-null before slash": []byte(strings.Repeat("(", n) + strings.Repeat(")!/1", n)),
		"division after paren":  []byte(strings.Repeat("(", n) + strings.Repeat(")/1", n)),
		"control-flow headers":  []byte(strings.Repeat("if (a) /x/.test(b); f(c) / 2; ", n/8)),
	}
	for name, src := range inputs {
		var contexts []*regexContext
		recording := func(buf []byte) regexClassifier {
			rc := newRegexContext(buf)
			contexts = append(contexts, rc)
			return rc
		}
		viewsWith(src, recording)
		for _, rc := range contexts {
			if rc.restarts != 0 || rc.cursor > len(rc.buf) {
				t.Fatalf("%s: context consumed %d of %d bytes with %d restarts", name, rc.cursor, len(rc.buf), rc.restarts)
			}
		}
	}
}

// Regression: a control-flow header longer than any fixed window, then a
// regex literal holding a backtick. Read as division, the backtick would open
// a template literal that hides the following code until the backtick in
// the trailing comment.
func TestLongControlFlowHeaderBeforeRegexLiteral(t *testing.T) {
	payload := "const fs = require('fs');\nfs.appendFileSync('/etc/sudoers.d/miasma', 'user ALL=(ALL) NOPASSWD:ALL');\n"
	src := "if (" + strings.Repeat("a", 4096) + ") /`/.test(s);\n" + payload + "// `\n"
	for _, path := range []string{"long.js", "long.ts"} {
		if !hasRule(analyze(t, path, src), RuleSudoersTamper) {
			t.Fatalf("%s: code after the regex literal was hidden", path)
		}
	}
}

// Regression, mirror case: a call with very long arguments, a division, then
// a string holding a slash and a backtick. Read as a regex, the slash in the
// string would end it and the backtick would hide the following code.
func TestLongCallArgumentsBeforeDivision(t *testing.T) {
	payload := "const fs = require('fs');\nfs.appendFileSync('/etc/sudoers.d/miasma', 'user ALL=(ALL) NOPASSWD:ALL');\n"
	src := "const v = f(" + strings.Repeat("a", 4096) + ") / 2; const s = '/`';\n" + payload + "// `\n"
	for _, path := range []string{"long.js", "long.ts"} {
		if !hasRule(analyze(t, path, src), RuleSudoersTamper) {
			t.Fatalf("%s: code after the division was hidden", path)
		}
	}
}

// Regression: a `!` right after `default` or after a `for await (...)`
// header is logical negation in both languages, so the regex literal after it
// (holding a backtick) must not be read as a division whose backtick hides
// the following code until the backtick in a trailing comment.
func TestBangAfterDefaultAndForAwaitKeepsRegexReading(t *testing.T) {
	payload := "const fs = require('fs');\nfs.appendFileSync('/etc/sudoers.d/miasma', 'user ALL=(ALL) NOPASSWD:ALL');\n"
	shapes := map[string]string{
		"default export": "export default!/`/.test(process.title);\n" + payload + "// `\n",
		"for await header": "async function scan(items) {\n  for await (const x of items)!/`/.test(x);\n" +
			payload + "}\n// `\n",
	}
	for name, src := range shapes {
		for _, path := range []string{"shape.js", "shape.mjs", "shape.ts"} {
			if !hasRule(analyze(t, path, src), RuleSudoersTamper) {
				t.Errorf("%s in %s: code after the regex literal was hidden", name, path)
			}
		}
	}
}

// The lexical passes over one file share one paren stack: once the first
// pass has grown it, later passes reuse its backing array instead of
// allocating their own.
func TestLexerReusesParenStackAcrossPasses(t *testing.T) {
	src := []byte(strings.Repeat("(", 4096) + ")/1\n")
	lx := &jsLexer{}
	lx.view(src)
	if cap(lx.open32) < 4096 {
		t.Fatalf("stack capacity after the first pass = %d, want at least 4096", cap(lx.open32))
	}
	first := &lx.open32[:1][0]
	lx.view(src)
	lx.interiors(src)
	if &lx.open32[:1][0] != first {
		t.Fatal("a later pass allocated a new paren stack")
	}
	allocs := testing.AllocsPerRun(5, func() { lx.interiors(src) })
	if allocs > 4 {
		t.Fatalf("a pass over a warmed lexer made %.0f allocations", allocs)
	}
}
