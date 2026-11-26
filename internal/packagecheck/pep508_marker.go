package packagecheck

import (
	"fmt"
	"regexp"
	"strings"
)

// checkPEP508Marker reports whether an environment marker parses under
// the PEP 508 grammar as packaging 25.0 and 26.0 (the versions pip 25.2
// and 26.0 vendor) parse it, which is how pip decides whether a
// requirement line is valid. The marker is never evaluated.
//
//	marker      = marker_atom (BOOLOP marker_atom)*
//	marker_atom = WS? "(" WS? marker WS? ")" WS? | WS? marker_item WS?
//	marker_item = WS? marker_var WS? marker_op WS? marker_var WS?
//	marker_var  = VARIABLE | QUOTED_STRING
//	marker_op   = "in" | "not" WS "in" | OP
//
// WS is spaces and tabs. Token patterns are packaging's: they end at a
// word boundary, so "andos_name" is not "and" followed by a variable.
func checkPEP508Marker(s string) error {
	p := &markerParser{s: s}
	if err := p.marker(0); err != nil {
		return err
	}
	if p.pos != len(p.s) {
		return fmt.Errorf("invalid environment marker: unexpected %q", p.s[p.pos:])
	}
	return nil
}

var (
	markerVariable = regexp.MustCompile(`^(?:python_version|python_full_version|os[._]name|sys[._]platform|platform_(?:release|system)|platform[._](?:version|machine|python_implementation)|python_implementation|implementation_(?:name|version)|extras?|dependency_groups)\b`)
	markerQuoted   = regexp.MustCompile(`^(?:'[^']*'|"[^"]*")`)
	markerOp       = regexp.MustCompile(`^(?:===|==|~=|!=|<=|>=|<|>)`)
	markerBoolOp   = regexp.MustCompile(`^(?:or|and)\b`)
	markerIn       = regexp.MustCompile(`^in\b`)
	markerNot      = regexp.MustCompile(`^not\b`)
)

// maxMarkerDepth bounds parenthesis nesting.
const maxMarkerDepth = 100

type markerParser struct {
	s   string
	pos int
}

func (p *markerParser) ws() bool {
	start := p.pos
	for p.pos < len(p.s) && (p.s[p.pos] == ' ' || p.s[p.pos] == '\t') {
		p.pos++
	}
	return p.pos > start
}

func (p *markerParser) take(re *regexp.Regexp) bool {
	m := re.FindString(p.s[p.pos:])
	if m == "" {
		return false
	}
	p.pos += len(m)
	return true
}

func (p *markerParser) marker(depth int) error {
	if err := p.atom(depth); err != nil {
		return err
	}
	for p.take(markerBoolOp) {
		if err := p.atom(depth); err != nil {
			return err
		}
	}
	return nil
}

func (p *markerParser) atom(depth int) error {
	p.ws()
	if p.pos < len(p.s) && p.s[p.pos] == '(' {
		if depth >= maxMarkerDepth {
			return fmt.Errorf("invalid environment marker: nested too deeply")
		}
		p.pos++
		p.ws()
		if err := p.marker(depth + 1); err != nil {
			return err
		}
		p.ws()
		if p.pos >= len(p.s) || p.s[p.pos] != ')' {
			return fmt.Errorf("invalid environment marker: expected ')'")
		}
		p.pos++
	} else if err := p.item(); err != nil {
		return err
	}
	p.ws()
	return nil
}

func (p *markerParser) item() error {
	p.ws()
	if err := p.variable(); err != nil {
		return err
	}
	p.ws()
	switch {
	case p.take(markerIn):
	case p.take(markerNot):
		if !p.ws() || !p.take(markerIn) {
			return fmt.Errorf("invalid environment marker: expected 'in' after 'not'")
		}
	case p.take(markerOp):
	default:
		return fmt.Errorf("invalid environment marker: expected an operator")
	}
	p.ws()
	if err := p.variable(); err != nil {
		return err
	}
	p.ws()
	return nil
}

func (p *markerParser) variable() error {
	if p.take(markerVariable) || p.take(markerQuoted) {
		return nil
	}
	rest := p.s[p.pos:]
	if i := strings.IndexAny(rest, " \t"); i >= 0 {
		rest = rest[:i]
	}
	return fmt.Errorf("invalid environment marker: expected a marker variable or quoted string, not %q", rest)
}
