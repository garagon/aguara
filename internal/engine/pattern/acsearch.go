package pattern

import (
	ahocorasick "github.com/petar-dambovaliev/aho-corasick"

	"github.com/garagon/aguara/internal/rules"
)

// acIndex maps AC automaton pattern indices back to their originating rules.
type acPatternRef struct {
	rule       *rules.CompiledRule
	patternIdx int // index within rule.Patterns
}

// acSearcher wraps an Aho-Corasick automaton built from all contains patterns
// across a set of rules. It enables O(n+m) multi-pattern matching instead of
// O(n*p) sequential substring search where p is the number of patterns.
type acSearcher struct {
	ac   ahocorasick.AhoCorasick
	refs []acPatternRef // pattern index -> (rule, pattern index)
}

// buildACSearcher creates an Aho-Corasick automaton from all contains patterns
// in the given rules. Returns nil if there are no contains patterns.
func buildACSearcher(compiled []*rules.CompiledRule) *acSearcher {
	var patterns []string
	var refs []acPatternRef

	for _, rule := range compiled {
		for pi, pat := range rule.Patterns {
			if pat.Type == rules.PatternContains {
				patterns = append(patterns, pat.Value) // already lowercased
				refs = append(refs, acPatternRef{rule: rule, patternIdx: pi})
			}
		}
	}

	if len(patterns) == 0 {
		return nil
	}

	builder := ahocorasick.NewAhoCorasickBuilder(ahocorasick.Opts{
		AsciiCaseInsensitive: false, // we search against pre-lowercased content
		MatchKind:            ahocorasick.StandardMatch,
		DFA:                  true, // DFA for faster matching at cost of more memory
	})
	ac := builder.Build(patterns)

	return &acSearcher{ac: ac, refs: refs}
}

// acMatch represents a match found by the AC automaton with rule context.
type acMatch struct {
	ruleID     string
	patternIdx int
	start      int
	end        int
}

// findAll runs the AC automaton against lowercased content and returns all matches
// grouped by rule ID for efficient processing.
func (s *acSearcher) findAll(lowerContent string) []acMatch {
	if s == nil {
		return nil
	}
	rawMatches := s.ac.FindAll(lowerContent)
	result := make([]acMatch, 0, len(rawMatches))
	for _, m := range rawMatches {
		ref := s.refs[m.Pattern()]
		result = append(result, acMatch{
			ruleID:     ref.rule.ID,
			patternIdx: ref.patternIdx,
			start:      m.Start(),
			end:        m.End(),
		})
	}
	return result
}
