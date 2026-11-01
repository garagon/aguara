package pattern

import (
	"context"

	"github.com/garagon/aguara/internal/scanner"
)

const privilegeWordPattern = `(?i)\bsetuid\b|\bsetgid\b|\bcap_setuid\b`

// Only the built-in bare-word predicate receives this view. Command predicates,
// decoded payloads and custom patterns retain their original input. Unknown
// syntax falls back to the legacy detector, never to a clean scan.
func privilegeWordContent(target *scanner.Target, content string) string {
	if string(target.SourceContent()) != content {
		return content
	}
	analysis, err := target.PrivilegeAnalysis(context.Background())
	if err != nil || analysis == nil || len(analysis.MaskedSpans) == 0 {
		return content
	}
	masked := []byte(content)
	for _, span := range analysis.MaskedSpans {
		for i := span.Start; i < span.End; i++ {
			if masked[i] != '\n' && masked[i] != '\r' {
				masked[i] = ' '
			}
		}
	}
	return string(masked)
}
