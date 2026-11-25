package jsrisk

import (
	"bytes"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// The lexer walkers used to classify the slash after a `)` by walking back
// to the matching `(` on every question. regexContext answers from a
// forward paren stack instead. The functions below are the backward-scan
// references, kept here only to prove the answers are unchanged:
//
//   - mainCouldBeRegexStart is the classifier as it was before TypeScript
//     support, copied verbatim;
//   - backwardCouldBeRegexStart is the same plus the TypeScript non-null
//     check (backwardBangIsNonNull), both scanning backwards without bound.

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
		}
		return true
	case isJSIdentByte(c):
		end := k + 1
		for k >= 0 && isJSIdentByte(content[k]) {
			k--
		}
		switch string(content[k+1 : end]) {
		case "return", "typeof", "instanceof", "in", "of", "delete", "void", "new",
			"throw", "yield", "await", "case", "do", "else":
			return false
		}
		return true
	}
	return false
}

type backwardClassifier struct {
	buf  []byte
	bang bool
}

func (b backwardClassifier) regexStartsAt(i int) bool {
	if b.bang {
		return backwardCouldBeRegexStart(b.buf, i)
	}
	return mainCouldBeRegexStart(b.buf, i)
}

func mainClassifier(buf []byte) regexClassifier   { return backwardClassifier{buf: buf} }
func backwardWithBang(buf []byte) regexClassifier { return backwardClassifier{buf: buf, bang: true} }
func indexClassifier(buf []byte) regexClassifier  { return newRegexContext(buf) }

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

// nonNullShape matches the only syntax whose reading differs from the
// pre-TypeScript classifier on purpose: `!` right after an operand, then a
// slash (`total! / n`). It is not valid JavaScript.
var nonNullShape = regexp.MustCompile(`[A-Za-z0-9_$)\]]![ \t\r]*/`)

// lexerDifferentialPieces are the token shapes the generator combines:
// unbalanced and nested parentheses, parentheses inside strings, template
// literals with interpolation, regex literals and character classes,
// comments, escapes, keywords that precede regex literals, and non-null
// assertions.
var lexerDifferentialPieces = []string{
	"(", ")", "((", "))", "/", "/", "//", "/*", "*/", "!", "! ", "[", "]", "{", "}",
	"'", "\"", "`", "${", "\\", "\n", " ", "\t", "if", "if (", "while", "for", "return",
	"typeof", "x", "ab", "=", "+", ",", ";", ":", "?", "*", "2", "/re/", "/[/]/g",
	"'(/'", "\")\"", "`${a(}`", "a!", "f()!", "xs[0]!", "(x)", "catch", "in", "do",
	"<", ">", "&&", "||", ".", "%",
}

// plainLexerPieces leaves out `!`, so snippets built from them are always
// compared with the pre-TypeScript classifier too.
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

func checkLexerDifferential(t *testing.T, src []byte) (comparedToMain bool) {
	t.Helper()
	got := viewsWith(src, indexClassifier)
	if want := viewsWith(src, backwardWithBang); !sameViews(got, want) {
		t.Fatalf("index and backward scan disagree on %q", src)
	}
	if nonNullShape.Match(src) {
		return false
	}
	if main := viewsWith(src, mainClassifier); !sameViews(got, main) {
		t.Fatalf("index and the pre-TypeScript classifier disagree on %q", src)
	}
	return true
}

func TestRegexContextMatchesBackwardScan(t *testing.T) {
	r := rand.New(rand.NewSource(20261124))
	total, plain := 0, 0
	inputs := make([][]byte, 0, 50000+len(lexerDifferentialSamples))
	for _, s := range lexerDifferentialSamples {
		inputs = append(inputs, []byte(s))
	}
	for i := 0; i < 50000; i++ {
		inputs = append(inputs, randomLexerSnippet(r, lexerDifferentialPieces, 60))
	}
	// Long inputs put matching parentheses thousands of bytes apart.
	for i := 0; i < 300; i++ {
		inputs = append(inputs, randomLexerSnippet(r, lexerDifferentialPieces, 4000))
		inputs = append(inputs, randomLexerSnippet(r, plainLexerPieces, 4000))
	}
	inputs = append(inputs, structuredLexerHeaders(r)...)
	for _, src := range inputs {
		total++
		if checkLexerDifferential(t, src) {
			plain++
		}
	}
	if plain < total/2 {
		t.Fatalf("only %d of %d inputs compared to the pre-TypeScript classifier", plain, total)
	}
	t.Logf("%d inputs identical to the backward scan, %d also identical to the pre-TypeScript classifier", total, plain)
}

// TestRegexContextMatchesBackwardScanOnDirectory repeats the differential
// over real files when AGUARA_LEXER_DIFF_DIR names a directory.
func TestRegexContextMatchesBackwardScanOnDirectory(t *testing.T) {
	dir := os.Getenv("AGUARA_LEXER_DIFF_DIR")
	if dir == "" {
		t.Skip("AGUARA_LEXER_DIFF_DIR not set")
	}
	files, plain := 0, 0
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
		if checkLexerDifferential(t, src) {
			plain++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d files identical to the backward scan, %d also identical to the pre-TypeScript classifier", files, plain)
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
