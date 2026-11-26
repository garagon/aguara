package pattern

import (
	"regexp"
	"strings"
	"testing"

	"github.com/garagon/aguara/internal/rules"
	"github.com/stretchr/testify/require"
)

func TestMatchPatternLinePositions(t *testing.T) {
	for _, tc := range []struct {
		name, content, value string
		kind                 rules.PatternType
		want                 []hitPos
	}{
		{"regex same line", "x x\nx", "x", rules.PatternRegex, []hitPos{{1, 1, "x"}, {1, 1, "x"}, {2, 2, "x"}}},
		{"regex blank lines and CRLF", "\r\nx\r\n\r\nx\n", "x", rules.PatternRegex, []hitPos{{2, 2, "x"}, {4, 4, "x"}}},
		{"regex multiline", "x\ny\nx\ny", "x\ny", rules.PatternRegex, []hitPos{{1, 2, "x\ny"}, {3, 4, "x\ny"}}},
		{"regex empty input", "", "^$", rules.PatternRegex, []hitPos{{1, 1, ""}}},
		{"regex zero width", "x\n\ny\n", "(?m)^", rules.PatternRegex, []hitPos{{1, 1, ""}, {2, 2, ""}, {3, 3, ""}, {4, 4, ""}}},
		{"regex EOF", "x\n", "$", rules.PatternRegex, []hitPos{{2, 2, ""}}},
		{"contains same line", "X x\nx", "x", rules.PatternContains, []hitPos{{1, 1, "X"}, {1, 1, "x"}, {2, 2, "x"}}},
		{"contains multiline", "X\nY\nx\ny", "x\ny", rules.PatternContains, []hitPos{{1, 2, "X\nY"}, {3, 4, "x\ny"}}},
		{"contains blank lines and CRLF", "\r\nX\r\n\r\nx\n", "x", rules.PatternContains, []hitPos{{2, 2, "X"}, {4, 4, "x"}}},
		{"contains unicode contraction", "\u0130\n\n\u0130 \u0130", "i", rules.PatternContains, []hitPos{{1, 1, "\u0130"}, {3, 3, "\u0130"}, {3, 3, "\u0130"}}},
		{"contains unicode expansion", "\u023a\n\u023a \u023a", "\u2c65", rules.PatternContains, []hitPos{{1, 1, "\u023a"}, {2, 2, "\u023a"}, {2, 2, "\u023a"}}},
		{"contains no match", "normal\ntext", "marker", rules.PatternContains, nil},
		{"contains empty pattern", "normal\ntext", "", rules.PatternContains, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pat := rules.CompiledPattern{Type: tc.kind, Value: tc.value}
			if tc.kind == rules.PatternRegex {
				pat.Regex = regexp.MustCompile(tc.value)
			}
			hits := matchPattern(pat, tc.content, newLowercaseContent(tc.content), strings.Split(tc.content, "\n"))
			require.Equal(t, tc.want, positions(hits))
			for _, h := range hits {
				require.Equal(t, h.text, tc.content[h.start:h.end], "hit offsets select the matched text")
			}
		})
	}
}

func TestMatchPatternLineCursorResetsPerPattern(t *testing.T) {
	content := "early\n\nlate"
	lower := newLowercaseContent(content)
	for _, kind := range []rules.PatternType{rules.PatternRegex, rules.PatternContains} {
		for _, tc := range []struct {
			value string
			line  int
		}{{"late", 3}, {"early", 1}, {"late", 3}} {
			pat := rules.CompiledPattern{Type: kind, Value: tc.value}
			if kind == rules.PatternRegex {
				pat.Regex = regexp.MustCompile(tc.value)
			}
			require.Equal(t, []hitPos{{tc.line, tc.line, tc.value}}, positions(matchPattern(pat, content, lower, strings.Split(content, "\n"))))
		}
	}
}

// hitPos is the line span and text of a hit, without its offsets.
type hitPos struct {
	line, endLine int
	text          string
}

func positions(hits []matchHit) []hitPos {
	var out []hitPos
	for _, h := range hits {
		out = append(out, hitPos{h.line, h.endLine, h.text})
	}
	return out
}
