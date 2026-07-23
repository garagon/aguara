package skillpolicy

import (
	"context"
	"testing"

	"github.com/garagon/aguara/internal/scanner"
)

// SKILL.md frontmatter is untrusted YAML. Arbitrary content must never panic
// the posture analyzer or produce an unidentified finding.
func FuzzAnalyze(f *testing.F) {
	f.Add("---\nname: demo\nallowed-tools: '*'\n---\n# Demo\n")
	f.Add("---\nallowed-tools: Bash(gh:*)\n---\n")
	f.Add("---\nallowed-tools: [\"*\"\n---\n")

	f.Fuzz(func(t *testing.T, src string) {
		findings, err := New().Analyze(context.Background(), &scanner.Target{
			Path:    "SKILL.md",
			RelPath: "SKILL.md",
			Content: []byte(src),
		})
		if err != nil {
			return
		}
		for _, finding := range findings {
			if finding.RuleID == "" {
				t.Error("finding with empty RuleID")
			}
		}
	})
}
