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
func buildPrefilter(compiled []*rules.CompiledRule) *prefilter {
	// Collect keywords per rule, deduplicating across rules.
	kwToRules := make(map[string]map[string]bool) // keyword -> set of rule IDs
	noKeyword := make(map[string]bool)

	for _, rule := range compiled {
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
			for _, kw := range kws {
				if kwToRules[kw] == nil {
					kwToRules[kw] = make(map[string]bool)
				}
				kwToRules[kw][rule.ID] = true
				ruleHasKeyword = true
			}
		}
		if !ruleHasKeyword {
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
func extractKeywords(pattern string) []string {
	p := stripFlags(pattern)

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

		if isKeywordChar(ch) {
			buf.WriteByte(ch)
		} else {
			flushKeyword(&buf, &keywords)
		}
	}
	flushKeyword(&buf, &keywords)

	return keywords
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
