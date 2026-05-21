package pattern

import (
	"strings"

	ahocorasick "github.com/petar-dambovaliev/aho-corasick"

	"github.com/garagon/aguara/internal/rules"
)

// minKeywordLen is the shortest literal substring worth indexing.
// 4 chars avoids common 3-letter words ("all", "run", "any", "the", "key")
// that appear in most content and produce poor pre-filter selectivity.
const minKeywordLen = 4

// prefilter uses Aho-Corasick to quickly identify which rules could possibly
// match before running expensive regex evaluation. For each rule it extracts
// literal substrings that must appear in any matching text, indexes them in
// a single AC automaton, and at match time returns only candidate rules
// whose keywords were found.
//
// Keywords are deduplicated: if multiple rules share the same keyword (e.g.
// "ignore"), a single AC pattern maps to all of those rule IDs.
//
// Overlapping matches are required at query time: when one rule extracts
// "bash" as a keyword and another extracts "bashrc", content "bashrc" must
// route to rules keyed by both literals. Non-overlapping iteration would
// report only one of them and silently drop the other rule set from the
// candidate map.
type prefilter struct {
	ac             *ahocorasick.AhoCorasick
	refs           [][]string      // AC pattern index -> list of rule IDs
	noKeywordRules map[string]bool // rules without extractable keywords (always run)
}

// buildPrefilter creates a keyword-based pre-filter from compiled rules.
//
// A pattern that produces zero extractable literals (either because all its
// literals are below minKeywordLen, or because some alternation branch has no
// literal evidence) is treated as "always passes the prefilter". The
// downstream effect depends on the rule's match_mode:
//   - MatchAny: matching via any pattern is enough, so if any pattern has no
//     usable literal evidence the rule must be marked noKeyword (always run).
//     Otherwise the indexed union of all patterns' literals filters the rule
//     correctly.
//   - MatchAll: every pattern must match, so a pattern with no literal
//     evidence does not constrain anything but the remaining patterns'
//     literals still apply (content lacking those literals cannot satisfy
//     match_mode: all). Only when *every* pattern is unfilterable does the
//     rule fall back to noKeyword.
func buildPrefilter(compiled []*rules.CompiledRule) *prefilter {
	// Collect keywords per rule, deduplicating across rules.
	kwToRules := make(map[string]map[string]bool) // keyword -> set of rule IDs
	noKeyword := make(map[string]bool)

	for _, rule := range compiled {
		forceNoKeyword := false
		ruleHasKeyword := false
		for _, pat := range rule.Patterns {
			var kws []string
			switch pat.Type {
			case rules.PatternContains:
				if len(pat.Value) >= minKeywordLen {
					kws = []string{pat.Value} // already lowercased
				}
			case rules.PatternRegex:
				kws = extractKeywords(pat.Value)
			}
			if len(kws) == 0 {
				// Pattern provides no usable literal evidence. Under MatchAny
				// the rule could match via this pattern without any of the
				// other patterns' keywords appearing, so we must give up on
				// filtering it. Under MatchAll the other patterns' keywords
				// remain reliable filters.
				if rule.MatchMode == rules.MatchAny {
					forceNoKeyword = true
					break
				}
				continue
			}
			for _, kw := range kws {
				if kwToRules[kw] == nil {
					kwToRules[kw] = make(map[string]bool)
				}
				kwToRules[kw][rule.ID] = true
				ruleHasKeyword = true
			}
		}
		if forceNoKeyword || !ruleHasKeyword {
			noKeyword[rule.ID] = true
		}
	}

	pf := &prefilter{noKeywordRules: noKeyword}

	if len(kwToRules) > 0 {
		keywords := make([]string, 0, len(kwToRules))
		refs := make([][]string, 0, len(kwToRules))
		for kw, ruleSet := range kwToRules {
			keywords = append(keywords, kw)
			ids := make([]string, 0, len(ruleSet))
			for id := range ruleSet {
				ids = append(ids, id)
			}
			refs = append(refs, ids)
		}
		builder := ahocorasick.NewAhoCorasickBuilder(ahocorasick.Opts{
			AsciiCaseInsensitive: false, // we search pre-lowercased content
			MatchKind:            ahocorasick.StandardMatch,
			DFA:                  true,
		})
		ac := builder.Build(keywords)
		pf.ac = &ac
		pf.refs = refs
	}

	return pf
}

// candidateRules returns the set of rule IDs that could match the content.
// A rule is a candidate if any of its keywords appear in lowerContent, or
// if the rule has no extractable keywords (conservative: always run those).
func (p *prefilter) candidateRules(lowerContent string) map[string]bool {
	if p == nil {
		return nil // nil map: caller treats nil as "all rules are candidates"
	}
	candidates := make(map[string]bool, len(p.noKeywordRules)+16)
	for id := range p.noKeywordRules {
		candidates[id] = true
	}
	if p.ac != nil {
		// IterOverlapping reports every keyword that matches at every position.
		// FindAll would collapse overlapping hits (e.g. "bash" and "bashrc"
		// starting at the same offset) and drop rules keyed only by the longer
		// literal, silently hiding true positives.
		iter := p.ac.IterOverlapping(lowerContent)
		for m := iter.Next(); m != nil; m = iter.Next() {
			for _, id := range p.refs[m.Pattern()] {
				candidates[id] = true
			}
		}
	}
	return candidates
}

// extractKeywords returns lowercase literal substrings from a regex pattern
// that must appear in any matching text. Only runs of alphanumeric/underscore
// characters of minKeywordLen+ length are returned. Content inside character
// classes ([...]) and quantifiers ({...}) is skipped.
//
// Alternations are paren-aware: an alternation group whose branches do not
// all produce a keyword (e.g. `(API[_-]?KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)`
// where the `API[_-]?KEY` branch yields no >=4-char literal after stripping
// the character class) contributes no keywords, because content matching the
// regex via the weak branch would carry none of the longer branches'
// literals. Optional groups (`(...)?`, `(...)*`, `(...){0,n}`) also
// contribute no keywords because the group may match zero times.
// Literals outside such alternations are still extracted and indexed
// normally, so a pattern like `subprocess\.(run|call|Popen)` still filters
// on "subprocess" even though the `run` branch is weak.
func extractKeywords(pattern string) []string {
	p := stripFlags(pattern)
	return extractKeywordsFrom(p)
}

// extractKeywordsFrom walks a pre-stripped regex, accumulating literals as
// keywords and recursing on parenthesized groups. Recursion is required so
// that nested alternations like `((A|B)|cdef)` get their weak inner
// alternations rejected before the outer alternation decides whether to
// contribute literals.
//
// Top-level alternations (e.g. `api|secret`, no enclosing parens) are
// handled before the linear walk: the regex matches via either branch, so
// every branch must produce at least one >=minKeywordLen literal for the
// pattern to be filterable. Without this guard the walker would treat `|`
// as a plain boundary and silently index only the strong branches'
// literals - the exact gap that motivated the alternation-aware fix in
// the parenthesized case.
func extractKeywordsFrom(p string) []string {
	if branches := splitTopLevelAlternation(p); len(branches) > 1 {
		var altKws []string
		for _, branch := range branches {
			bKws := extractKeywordsFrom(branch)
			if len(bKws) == 0 {
				return nil
			}
			altKws = append(altKws, bKws...)
		}
		return altKws
	}

	var keywords []string
	var buf strings.Builder
	inCharClass := false
	inQuantifier := false
	escaped := false

	for i := 0; i < len(p); i++ {
		ch := p[i]

		if escaped {
			escaped = false
			flushKeyword(&buf, &keywords)
			continue
		}
		if ch == '\\' {
			escaped = true
			flushKeyword(&buf, &keywords)
			continue
		}
		if ch == '[' && !inCharClass && !inQuantifier {
			inCharClass = true
			flushKeyword(&buf, &keywords)
			continue
		}
		if ch == ']' && inCharClass {
			inCharClass = false
			continue
		}
		if inCharClass {
			continue
		}
		if ch == '{' && !inQuantifier {
			// `{0,n}` or `{0}` on the preceding character makes that
			// character optional. Trim it from the buffer so the
			// indexed literal only reflects what is actually required.
			trimOptionalTail(&buf, p, i)
			inQuantifier = true
			flushKeyword(&buf, &keywords)
			continue
		}
		if ch == '}' && inQuantifier {
			inQuantifier = false
			continue
		}
		if inQuantifier {
			continue
		}

		if ch == '(' {
			end := findMatchingParen(p, i)
			if end == -1 {
				// Malformed input; treat as a boundary and keep walking so we
				// don't crash on a stray unbalanced paren.
				flushKeyword(&buf, &keywords)
				continue
			}
			inner := stripGroupFlags(p[i+1 : end])
			flushKeyword(&buf, &keywords)

			optional := isOptionalQuantifier(p, end+1)

			branches := splitTopLevelAlternation(inner)
			if len(branches) == 1 {
				// Plain grouping, no alternation. The group's literals are
				// required as long as the group itself is required, so only
				// contribute when not under an optional quantifier.
				if !optional {
					keywords = append(keywords, extractKeywordsFrom(inner)...)
				}
			} else {
				// Alternation. Every branch must produce at least one keyword
				// for the alternation to contribute literals: a branch with
				// no extractable literal could match content carrying none of
				// the other branches' literals, which would falsely filter
				// the rule out. Optional alternations contribute nothing
				// regardless of branch strength.
				if !optional {
					var altKws []string
					allBranchesStrong := true
					for _, branch := range branches {
						bKws := extractKeywordsFrom(branch)
						if len(bKws) == 0 {
							allBranchesStrong = false
							break
						}
						altKws = append(altKws, bKws...)
					}
					if allBranchesStrong {
						keywords = append(keywords, altKws...)
					}
				}
			}
			i = end
			continue
		}

		if ch == ')' {
			// Stray close paren (only reachable if findMatchingParen failed
			// to find a match upstream and we kept walking). Treat as a
			// boundary so any literal in progress is flushed.
			flushKeyword(&buf, &keywords)
			continue
		}

		if isKeywordChar(ch) {
			buf.WriteByte(ch)
		} else {
			// `?` or `*` on the preceding character makes that
			// character optional, so the indexed keyword must only
			// span the required prefix. Without this trim, a regex
			// like `https?` would be indexed on the literal "https"
			// even though "http" alone is enough to match.
			trimOptionalTail(&buf, p, i)
			flushKeyword(&buf, &keywords)
		}
	}
	flushKeyword(&buf, &keywords)

	return keywords
}

// trimOptionalTail removes the last byte from buf when the character at
// position pos in p is an optional quantifier (`?`, `*`, or `{0,...}`).
// The optional quantifier applies to the immediately preceding regex atom;
// when that atom is a literal character, the literal is not required to
// appear in matching content and must be excluded from the prefilter
// keyword.
func trimOptionalTail(buf *strings.Builder, p string, pos int) {
	if !isOptionalQuantifier(p, pos) || buf.Len() == 0 {
		return
	}
	s := buf.String()
	buf.Reset()
	buf.WriteString(s[:len(s)-1])
}

// findMatchingParen returns the index of the ')' that closes the '(' at
// start, or -1 if no match is found. Honors character classes and escaped
// metacharacters so a '(' inside `[(]` or after `\` does not perturb the
// depth count.
func findMatchingParen(p string, start int) int {
	depth := 1
	inCharClass := false
	escaped := false
	for i := start + 1; i < len(p); i++ {
		ch := p[i]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if ch == '[' && !inCharClass {
			inCharClass = true
			continue
		}
		if ch == ']' && inCharClass {
			inCharClass = false
			continue
		}
		if inCharClass {
			continue
		}
		switch ch {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// splitTopLevelAlternation splits inner group content on '|' characters at
// depth 0 (not inside nested parens or character classes). Returns the input
// as a single element when there is no top-level alternation.
func splitTopLevelAlternation(s string) []string {
	var branches []string
	depth := 0
	inCharClass := false
	escaped := false
	start := 0
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if ch == '[' && !inCharClass {
			inCharClass = true
			continue
		}
		if ch == ']' && inCharClass {
			inCharClass = false
			continue
		}
		if inCharClass {
			continue
		}
		switch ch {
		case '(':
			depth++
		case ')':
			depth--
		case '|':
			if depth == 0 {
				branches = append(branches, s[start:i])
				start = i + 1
			}
		}
	}
	branches = append(branches, s[start:])
	return branches
}

// stripGroupFlags removes leading group prefixes inside a (...) group:
//   - non-capturing `?:`
//   - lookahead `?=` and `?!`
//   - lookbehind `?<=` and `?<!` (Go's regexp doesn't support these but the
//     stripper accepts them defensively)
//   - inline flags `?i:`, `?im:`, etc.
//   - named capture `?P<name>`
//
// Returns the input unchanged when no recognized prefix is found.
func stripGroupFlags(s string) string {
	if len(s) < 2 || s[0] != '?' {
		return s
	}
	switch s[1] {
	case ':', '=', '!':
		return s[2:]
	case '<':
		if len(s) >= 3 && (s[2] == '=' || s[2] == '!') {
			return s[3:]
		}
	case 'P':
		if len(s) >= 3 && s[2] == '<' {
			if gt := strings.Index(s, ">"); gt > 0 {
				return s[gt+1:]
			}
		}
	}
	// Inline flag group like `?i:foo` or `?im:foo`.
	if colon := strings.Index(s, ":"); colon > 0 {
		for j := 1; j < colon; j++ {
			ch := s[j]
			if ch != 'i' && ch != 's' && ch != 'm' && ch != 'U' && ch != '-' {
				return s
			}
		}
		return s[colon+1:]
	}
	return s
}

// isOptionalQuantifier reports whether the character at position pos in p is
// a quantifier that allows zero matches (`?`, `*`, `{0,...}`). Used to mark
// a group's literals as non-required.
func isOptionalQuantifier(p string, pos int) bool {
	if pos >= len(p) {
		return false
	}
	switch p[pos] {
	case '?', '*':
		return true
	case '{':
		// Look for `{0,...}` or `{0}` - a quantifier starting with 0.
		end := strings.Index(p[pos:], "}")
		if end == -1 {
			return false
		}
		quant := p[pos+1 : pos+end]
		return strings.HasPrefix(quant, "0,") || quant == "0"
	}
	return false
}

// isKeywordChar returns true for characters that form useful keyword literals.
// Only alphanumeric and underscore; everything else is treated as a boundary.
func isKeywordChar(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
		(ch >= '0' && ch <= '9') || ch == '_'
}

// stripFlags removes a leading flag group like (?i) or (?is) from a pattern.
func stripFlags(p string) string {
	if !strings.HasPrefix(p, "(?") {
		return p
	}
	end := strings.Index(p, ")")
	if end == -1 || end < 3 {
		return p
	}
	flags := p[2:end]
	for _, ch := range flags {
		if ch != 'i' && ch != 's' && ch != 'm' && ch != 'U' {
			return p // not a pure flag group (e.g. (?:...) or (?P<>...))
		}
	}
	return p[end+1:]
}

func flushKeyword(buf *strings.Builder, keywords *[]string) {
	s := buf.String()
	buf.Reset()
	if len(s) >= minKeywordLen {
		*keywords = append(*keywords, strings.ToLower(s))
	}
}
