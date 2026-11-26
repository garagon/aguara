package packagecheck

import (
	"path"
	"strings"
)

// setup.py is a Python program and is never run. setupPyReader reads its
// tokens (names, string literals, operators, statement ends) the way the
// Python tokenizer splits them, and recognises a few literal shapes:
//
//   - install_requires=[...] or (...) passed as a keyword argument, whose
//     elements are all string literals (adjacent literals concatenate);
//   - extras_require={"extra": [...], ...} with literal lists;
//   - either keyword given a name bound, at statement level, only to such
//     literal lists and used nowhere else (a name that is appended to,
//     extended, compared or passed elsewhere is not trusted);
//   - string literals naming a .txt or .in file, joined when they are
//     consecutive arguments of one call or operands of "/", which are the
//     files the script reads its dependencies from.
//
// Anything else given to those keywords leaves the names unknown; string
// elements of list displays inside such a value are still read as names.
// Keyword unpacking into a setup() call (`setup(**config)`) leaves them
// unknown too.

type pyTokKind byte

const (
	pyName pyTokKind = iota + 1
	pyString
	pyOther   // a number, an f-string or a bytes literal
	pyOp      // an operator or a bracket; text holds it
	pyNewline // the end of a statement (outside brackets)
	pyEOF
)

type pyTok struct {
	kind pyTokKind
	text string // name, operator, or the string literal's value
	// depth is the bracket depth the token sits at; for an opening
	// bracket, the depth outside it.
	depth int
	line  int
}

type pyLexer struct {
	src   string
	pos   int
	line  int
	depth int
	peeks []pyTok
}

var pyTwoCharOps = []string{"**", "==", "!=", "<=", ">=", ":=", "->", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "//", "<<", ">>", "@="}

func (l *pyLexer) next() pyTok {
	if len(l.peeks) > 0 {
		t := l.peeks[0]
		l.peeks = l.peeks[1:]
		return t
	}
	return l.scan()
}

func (l *pyLexer) peek(n int) pyTok {
	for len(l.peeks) <= n {
		l.peeks = append(l.peeks, l.scan())
	}
	return l.peeks[n]
}

func (l *pyLexer) scan() pyTok {
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		switch {
		case c == '\n':
			l.pos++
			l.line++
			if l.depth == 0 {
				return pyTok{kind: pyNewline, line: l.line - 1}
			}
		case c == ' ' || c == '\t' || c == '\r' || c == '\f':
			l.pos++
		case c == '\\' && l.pos+1 < len(l.src) && (l.src[l.pos+1] == '\n' || l.src[l.pos+1] == '\r'):
			l.pos += 2
			if l.src[l.pos-1] == '\r' && l.pos < len(l.src) && l.src[l.pos] == '\n' {
				l.pos++
			}
			l.line++
		case c == '#':
			for l.pos < len(l.src) && l.src[l.pos] != '\n' {
				l.pos++
			}
		case c == ';' && l.depth == 0:
			l.pos++
			return pyTok{kind: pyNewline, line: l.line}
		case c == '"' || c == '\'':
			return l.scanString("")
		case isPyNameStart(c):
			start := l.pos
			for l.pos < len(l.src) && isPyNameByte(l.src[l.pos]) {
				l.pos++
			}
			word := l.src[start:l.pos]
			if l.pos < len(l.src) && (l.src[l.pos] == '"' || l.src[l.pos] == '\'') && len(word) <= 2 && isPyStringPrefix(word) {
				return l.scanString(word)
			}
			return pyTok{kind: pyName, text: word, depth: l.depth, line: l.line}
		case c >= '0' && c <= '9' || c == '.' && l.pos+1 < len(l.src) && l.src[l.pos+1] >= '0' && l.src[l.pos+1] <= '9':
			for l.pos < len(l.src) && (isPyNameByte(l.src[l.pos]) || l.src[l.pos] == '.') {
				l.pos++
			}
			return pyTok{kind: pyOther, depth: l.depth, line: l.line}
		default:
			op := string(c)
			for _, two := range pyTwoCharOps {
				if strings.HasPrefix(l.src[l.pos:], two) {
					op = two
					break
				}
			}
			l.pos += len(op)
			t := pyTok{kind: pyOp, text: op, depth: l.depth, line: l.line}
			switch op {
			case "(", "[", "{":
				l.depth++
			case ")", "]", "}":
				if l.depth > 0 {
					l.depth--
				}
				t.depth = l.depth
			}
			return t
		}
	}
	return pyTok{kind: pyEOF, line: l.line}
}

// scanString reads a string literal after its prefix. A raw string keeps
// backslashes; other strings undo the common escapes. An f-string or a
// bytes literal is not a string value here.
func (l *pyLexer) scanString(prefix string) pyTok {
	line := l.line
	quote := l.src[l.pos]
	q := string(quote)
	if strings.HasPrefix(l.src[l.pos:], strings.Repeat(q, 3)) {
		q = strings.Repeat(q, 3)
	}
	l.pos += len(q)
	raw := strings.ContainsAny(prefix, "rR")
	var b strings.Builder
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		if strings.HasPrefix(l.src[l.pos:], q) {
			l.pos += len(q)
			kind := pyString
			if strings.ContainsAny(prefix, "fFbB") {
				kind = pyOther
			}
			return pyTok{kind: kind, text: b.String(), depth: l.depth, line: line}
		}
		if c == '\n' {
			l.line++
			if len(q) == 1 {
				// An unterminated single-quoted string ends at the line.
				break
			}
		}
		if c == '\\' && l.pos+1 < len(l.src) {
			next := l.src[l.pos+1]
			l.pos += 2
			if next == '\n' {
				l.line++
				if !raw {
					continue
				}
			}
			if raw {
				b.WriteByte('\\')
				b.WriteByte(next)
				continue
			}
			switch next {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case '\\', '\'', '"':
				b.WriteByte(next)
			default:
				b.WriteByte('\\')
				b.WriteByte(next)
			}
			continue
		}
		b.WriteByte(c)
		l.pos++
	}
	return pyTok{kind: pyOther, depth: l.depth, line: line}
}

func isPyNameStart(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80
}

func isPyNameByte(c byte) bool { return isPyNameStart(c) || c >= '0' && c <= '9' }

func isPyStringPrefix(w string) bool {
	for i := 0; i < len(w); i++ {
		if !strings.ContainsRune("rRbBuUfF", rune(w[i])) {
			return false
		}
	}
	return true
}

// pyListValue is what a value expression turned out to be: a literal list
// (strings, with their lines), a reference to a name, a literal extras
// dict, or something else.
type pyListValue struct {
	literal bool
	items   []pyStringItem
	ref     string
	extras  map[string][]pyStringItem
	// listed holds string elements of list displays found inside a
	// value that is not literal as a whole.
	listed []pyStringItem
}

type pyStringItem struct {
	value string
	line  int
}

// pyBinding is a name bound at statement level.
type pyBinding struct {
	lists      [][]pyStringItem
	dicts      []map[string][]pyStringItem
	nonLiteral bool
}

type setupPyScan struct {
	lex      *pyLexer
	bindings map[string]*pyBinding
	// uses counts every other appearance of a name (read, called,
	// passed, compared, changed in place), wherever it is in the file.
	uses     map[string]int
	overflow bool
	install  []pyListValue
	extras   []pyListValue
	files    []string
	calls    bool
	unpacks  bool
	// pathParts collects consecutive string literals joined as a path.
	pathParts []string
}

// maxSetupPyNames bounds the distinct names one scan tracks. Past it, no
// bound name is trusted.
const maxSetupPyNames = 10_000

func scanSetupPy(src string) *setupPyScan {
	s := &setupPyScan{lex: &pyLexer{src: src, line: 1}, bindings: map[string]*pyBinding{}, uses: map[string]int{}}
	prev := pyTok{kind: pyNewline}
	for {
		t := s.lex.next()
		if t.kind == pyEOF {
			s.flushPath()
			return s
		}
		s.trackPath(prev, t)
		attribute := prev.kind == pyOp && prev.text == "."
		switch {
		case t.kind == pyName && t.text == "setup" && s.lex.peek(0).text == "(":
			s.calls = true
		case t.kind == pyOp && t.text == "**" && prev.kind == pyOp && (prev.text == "(" || prev.text == ","):
			s.unpacks = true
		case t.kind == pyName && !attribute && s.lex.peek(0).kind == pyOp && s.lex.peek(0).text == "=":
			s.lex.next() // "="
			s.assign(t)
			prev = pyTok{kind: pyOp, text: "="}
			continue
		case t.kind == pyName && !attribute:
			s.use(t.text)
		}
		prev = t
	}
}

func (s *setupPyScan) use(name string) {
	if _, ok := s.uses[name]; !ok && len(s.uses) >= maxSetupPyNames {
		s.overflow = true
		return
	}
	s.uses[name]++
}

// assign handles `name = value` at statement level (a binding) and
// `keyword=value` inside a call.
func (s *setupPyScan) assign(name pyTok) {
	value := s.parseValue()
	dependencyKeyword := name.depth > 0 && (name.text == "install_requires" || name.text == "extras_require")
	if value.ref != "" && !dependencyKeyword {
		// Aliased or passed elsewhere: the list may change through it.
		s.use(value.ref)
	}
	if name.depth == 0 {
		b := s.bindings[name.text]
		if b == nil {
			if len(s.bindings) >= maxSetupPyNames {
				s.overflow = true
				return
			}
			b = &pyBinding{}
			s.bindings[name.text] = b
		}
		switch {
		case !value.literal || value.ref != "":
			b.nonLiteral = true
		case value.extras != nil:
			b.dicts = append(b.dicts, value.extras)
		default:
			b.lists = append(b.lists, value.items)
		}
		return
	}
	switch name.text {
	case "install_requires":
		s.install = append(s.install, value)
	case "extras_require":
		s.extras = append(s.extras, value)
	}
}

// parseValue reads one value expression: up to a ",", a closing bracket
// or a statement end at the value's own depth.
func (s *setupPyScan) parseValue() pyListValue {
	first := s.lex.peek(0)
	var v pyListValue
	switch {
	case first.kind == pyOp && (first.text == "[" || first.text == "("):
		v = s.parseList()
	case first.kind == pyOp && first.text == "{":
		v = s.parseDict()
	case first.kind == pyName:
		s.lex.next()
		v = pyListValue{literal: true, ref: first.text}
	}
	if !s.atValueEnd(first.depth) {
		if v.ref != "" {
			s.use(v.ref)
		}
		// Inside a list display that stopped at a computed element, the
		// rest of its string elements still count.
		var open []bool
		if !v.literal && first.kind == pyOp && first.text != "{" && s.lex.peek(0).depth > first.depth {
			open = []bool{true}
		}
		v.literal = false
		v.ref = ""
		v.listed = append(v.listed, v.items...)
		v.listed = append(v.listed, s.skipValue(first.depth, open)...)
	}
	return v
}

func (s *setupPyScan) atValueEnd(depth int) bool {
	t := s.lex.peek(0)
	switch t.kind {
	case pyEOF, pyNewline:
		return true
	case pyOp:
		switch t.text {
		case ",", ")", "]", "}":
			return t.depth < depth || t.depth == depth && t.text == ","
		}
	}
	return false
}

// skipValue consumes the rest of a value expression and returns the
// string elements of list displays inside it.
func (s *setupPyScan) skipValue(depth int, displays []bool) []pyStringItem {
	var listed []pyStringItem
	prev := pyTok{}
	// displays holds, per open bracket, whether it is a list display.
	for !s.atValueEnd(depth) {
		t := s.lex.next()
		s.trackPath(prev, t)
		switch {
		case t.kind == pyOp && (t.text == "[" || t.text == "(" || t.text == "{"):
			display := t.text == "[" && !(prev.kind == pyName || prev.kind == pyString || prev.kind == pyOp && (prev.text == ")" || prev.text == "]"))
			displays = append(displays, display)
		case t.kind == pyOp && (t.text == "]" || t.text == ")" || t.text == "}"):
			if len(displays) > 0 {
				displays = displays[:len(displays)-1]
			}
		case t.kind == pyString && len(displays) > 0 && displays[len(displays)-1]:
			if n := s.lex.peek(0); n.kind == pyOp && (n.text == "," || n.text == "]") {
				listed = append(listed, pyStringItem{t.text, t.line})
			}
		case t.kind == pyName && !(prev.kind == pyOp && prev.text == "."):
			s.use(t.text)
		}
		prev = t
	}
	return listed
}

// parseList reads [ "a", "b" ] or ( "a", ), with adjacent literals
// concatenated. It stops at the first element that is not a string,
// leaving the rest to the caller.
func (s *setupPyScan) parseList() pyListValue {
	open := s.lex.next()
	closer := "]"
	if open.text == "(" {
		closer = ")"
	}
	var items []pyStringItem
	for {
		t := s.lex.peek(0)
		if t.kind == pyOp && t.text == closer && t.depth == open.depth {
			s.lex.next()
			return pyListValue{literal: true, items: items}
		}
		if t.kind != pyString {
			return pyListValue{items: items}
		}
		s.lex.next()
		item := pyStringItem{t.text, t.line}
		for s.lex.peek(0).kind == pyString {
			item.value += s.lex.next().text
		}
		s.noteFile(item.value)
		items = append(items, item)
		switch n := s.lex.peek(0); {
		case n.kind == pyOp && n.text == ",":
			s.lex.next()
		case n.kind == pyOp && n.text == closer && n.depth == open.depth:
		default:
			return pyListValue{items: items}
		}
	}
}

// parseDict reads { "extra": [ ... ], ... } with literal lists.
func (s *setupPyScan) parseDict() pyListValue {
	open := s.lex.next()
	extras := map[string][]pyStringItem{}
	var all []pyStringItem
	for {
		t := s.lex.peek(0)
		if t.kind == pyOp && t.text == "}" && t.depth == open.depth {
			s.lex.next()
			return pyListValue{literal: true, extras: extras, items: all}
		}
		if t.kind != pyString || s.lex.peek(1).text != ":" {
			return pyListValue{items: all}
		}
		s.lex.next()
		s.lex.next() // ":"
		if n := s.lex.peek(0); n.kind != pyOp || n.text != "[" && n.text != "(" {
			return pyListValue{items: all}
		}
		list := s.parseList()
		all = append(all, list.items...)
		if !list.literal {
			return pyListValue{items: all}
		}
		if len(extras) < maxSetupPyNames {
			extras[t.text] = append(extras[t.text], list.items...)
		}
		switch n := s.lex.peek(0); {
		case n.kind == pyOp && n.text == ",":
			s.lex.next()
		case n.kind == pyOp && n.text == "}" && n.depth == open.depth:
		default:
			return pyListValue{items: all}
		}
	}
}

// trackPath joins string literals that are consecutive arguments of a
// call ("a", "b") or operands of "/", and notes the ones that name a
// .txt or .in file.
func (s *setupPyScan) trackPath(prev, t pyTok) {
	switch {
	case t.kind == pyString:
		if len(s.pathParts) == 0 || !(prev.kind == pyOp && (prev.text == "," || prev.text == "/")) {
			s.flushPath()
		}
		if len(s.pathParts) < 16 {
			s.pathParts = append(s.pathParts, t.text)
		}
	case t.kind == pyOp && (t.text == "," || t.text == "/"):
	case t.kind == pyName && prev.kind == pyOp && prev.text == ",":
		// A name argument between literals (os.path.join(here, "a")) does
		// not end the sequence.
	default:
		s.flushPath()
	}
}

func (s *setupPyScan) flushPath() {
	if len(s.pathParts) > 0 {
		s.noteFile(path.Join(s.pathParts...))
	}
	s.pathParts = s.pathParts[:0]
}

// noteFile records a literal that names a dependency file relative to
// setup.py: no white space, not a URL, ending in .txt or .in.
func (s *setupPyScan) noteFile(v string) {
	if v == "" || len(s.files) >= 100 || strings.ContainsAny(v, " \t\n\\") || strings.Contains(v, "://") || path.IsAbs(v) {
		return
	}
	if !strings.HasSuffix(v, ".txt") && !strings.HasSuffix(v, ".in") {
		return
	}
	v = path.Clean(v)
	if strings.HasPrefix(v, "../") || v == ".." {
		return
	}
	for _, f := range s.files {
		if f == v {
			return
		}
	}
	s.files = append(s.files, v)
}

// resolve returns the literal lists a value stands for, or ok=false.
func (s *setupPyScan) resolve(v pyListValue) ([][]pyStringItem, []map[string][]pyStringItem, bool) {
	if !v.literal {
		return nil, nil, false
	}
	if v.ref == "" {
		if v.extras != nil {
			return nil, []map[string][]pyStringItem{v.extras}, true
		}
		return [][]pyStringItem{v.items}, nil, true
	}
	b := s.bindings[v.ref]
	if b == nil || b.nonLiteral || s.uses[v.ref] > 0 || s.overflow {
		return nil, nil, false
	}
	return b.lists, b.dicts, true
}
