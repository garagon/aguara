package npmpolicy

import (
	"context"
	"testing"

	"github.com/garagon/aguara/internal/scanner"
)

// Both surfaces this analyzer reads ship inside cloned repos: the
// package.json allowScripts policy and the project .npmrc. Run every
// fuzz input through both paths.
func FuzzAnalyze(f *testing.F) {
	f.Add(`{"allowScripts":{"left-pad":true}}`)
	f.Add("dangerously-allow-all-scripts=true\nallow-git = true ; comment\n")
	f.Add("allow-remote=\n#dangerously-allow-all-scripts=true\n")

	a := New()
	f.Fuzz(func(t *testing.T, src string) {
		for _, rel := range []string{"package.json", ".npmrc"} {
			findings, err := a.Analyze(context.Background(), &scanner.Target{
				Path:    rel,
				RelPath: rel,
				Content: []byte(src),
			})
			if err != nil {
				continue
			}
			for _, fd := range findings {
				if fd.RuleID == "" {
					t.Error("finding with empty RuleID")
				}
			}
		}
	})
}
