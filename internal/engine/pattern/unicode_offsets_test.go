package pattern_test

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/garagon/aguara/internal/engine/pattern"
	"github.com/garagon/aguara/internal/rules"
	"github.com/garagon/aguara/internal/scanner"
	"github.com/stretchr/testify/require"
)

func TestContainsOriginalUnicodeOffsets(t *testing.T) {
	for _, tc := range []struct {
		name, prefix, value, match string
	}{
		{"ascii", "ordinary\n", "marker", "MARKER"},
		{"expansion", strings.Repeat("\u023a", 64) + "\n", "marker", "MARKER"},
		{"contraction", strings.Repeat("\u0130", 64) + "\n", "marker", "MARKER"},
		{"equal_total_length", "\u023a\n", "markeri", "MARKER\u0130"},
		{"unicode_match_expands", "prefix\n", "\u2c65", "\u023a"},
		{"unicode_match_contracts", "header\n", "i", "\u0130"},
		{"invalid_utf8", "\xff\xfe\n", "marker", "MARKER"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, mode := range []string{"any", "all"} {
				t.Run(mode, func(t *testing.T) {
					rule := compileTestRule(t, rules.RawRule{ID: "UNICODE_OFFSET_TEST", Name: "Unicode offset", Severity: "HIGH", Category: "test", MatchMode: mode,
						Patterns: []rules.RawPattern{{Type: rules.PatternContains, Value: tc.value}}})
					matcher := pattern.NewMatcher([]*rules.CompiledRule{rule})
					findings, err := matcher.Analyze(context.Background(), &scanner.Target{RelPath: "test.txt", Content: []byte(tc.prefix + tc.match)})
					require.NoError(t, err)
					require.Len(t, findings, 1)
					require.Equal(t, tc.match, findings[0].MatchedText)
					require.Equal(t, 2, findings[0].Line)
				})
			}
		})
	}
}

func TestContainsUnicodeExclusionsAndCodeBlocks(t *testing.T) {
	rule := compileTestRule(t, rules.RawRule{ID: "UNICODE_CONTEXT_TEST", Name: "Unicode context", Severity: "HIGH", Category: "test",
		Patterns:        []rules.RawPattern{{Type: rules.PatternContains, Value: "marker"}},
		ExcludePatterns: []rules.RawPattern{{Type: rules.PatternContains, Value: "example"}}})
	content := strings.Repeat("\u023a", 64) + "\nexample MARKER\n\n\n\n```text\nMARKER\n```\n"
	findings, err := pattern.NewMatcher([]*rules.CompiledRule{rule}).Analyze(context.Background(), &scanner.Target{RelPath: "test.md", Content: []byte(content)})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	require.Equal(t, 7, findings[0].Line)
	require.Equal(t, "MARKER", findings[0].MatchedText)
	require.True(t, findings[0].InCodeBlock)
	require.Equal(t, "MARKER", findings[0].Context[3].Content)
}

func TestDecodedContainsOriginalUnicodeOffsets(t *testing.T) {
	rule := compileTestRule(t, rules.RawRule{ID: "UNICODE_DECODE_TEST", Name: "Unicode decode", Severity: "HIGH", Category: "test",
		Patterns: []rules.RawPattern{{Type: rules.PatternContains, Value: "marker"}}})
	payload := strings.Repeat("\u023a", 64) + "\nMARKER"
	target := &scanner.Target{RelPath: "test.txt", Content: []byte("header\n" + base64.StdEncoding.EncodeToString([]byte(payload)))}
	findings := pattern.DecodeAndRescan(target, []*rules.CompiledRule{rule}, nil)
	require.Len(t, findings, 1)
	require.Equal(t, "MARKER", findings[0].MatchedText)
	require.Equal(t, 2, findings[0].Line)
}
