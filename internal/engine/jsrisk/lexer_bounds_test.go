package jsrisk

import (
	"strings"
	"testing"
	"time"
)

// Deep nesting puts the `(` matching each `)` far behind it. The walk that
// classifies the following `/` must stay inside its window instead of
// rescanning the file for every slash.
func TestParenHeaderScanStaysInsideWindow(t *testing.T) {
	n := 4 * maxLexerBackscan
	content := []byte(strings.Repeat("(", n) + strings.Repeat(")!/1", n))
	for i, c := range content {
		if c != ')' {
			continue
		}
		_, _, lowest := scanParenHeader(content, i)
		if i-lowest > maxLexerBackscan+maxKeywordLen+1 {
			t.Fatalf("scan from offset %d examined back to %d (%d bytes), window is %d",
				i, lowest, i-lowest, maxLexerBackscan)
		}
	}
}

// A header longer than the window reads like an unmatched `)`: a following
// `/` is division, and a `!` after it is not taken for a non-null assertion,
// so `!` keeps the regex reading it had before TypeScript support.
func TestParenHeaderBeyondWindowKeepsUnmatchedReading(t *testing.T) {
	long := strings.Repeat("a", maxLexerBackscan)
	cases := []struct {
		src   string
		regex bool
	}{
		{"if (x) /re/.test(s)", true},
		{"if (" + long + ") /re/.test(s)", false},
		{"y = f(x)! / 2", false},
		{"y = f(" + long + ")! / 2", true},
		{"y = " + strings.Repeat("v", 3*maxKeywordLen) + " / 2", false},
	}
	for _, tc := range cases {
		slash := strings.LastIndex(tc.src[:strings.Index(tc.src, "/")+1], "/")
		if got := couldBeRegexStart([]byte(tc.src), slash); got != tc.regex {
			t.Errorf("couldBeRegexStart(%.40q...) = %v, want %v", tc.src, got, tc.regex)
		}
	}
}

// End to end, crafted nesting stays far below the quadratic cost an
// unbounded walk has on the same input. Each shape takes a few seconds under
// the race detector with the bounded walk and well over the limit without it.
func TestCraftedNestingAnalyzesInBoundedTime(t *testing.T) {
	n := 48 * 1024 / 5
	inputs := map[string]string{
		"non-null before slash": strings.Repeat("(", n) + strings.Repeat(")!/1", n),
		"division after paren":  strings.Repeat("(", n) + strings.Repeat(")/1", n),
	}
	for name, body := range inputs {
		start := time.Now()
		analyze(t, "nest.ts", body)
		elapsed := time.Since(start)
		t.Logf("%s: %v", name, elapsed)
		if elapsed > 10*time.Second {
			t.Errorf("%s: analysis took %v", name, elapsed)
		}
	}
}
