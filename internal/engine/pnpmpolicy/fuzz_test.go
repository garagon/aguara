package pnpmpolicy

import (
	"context"
	"testing"

	"github.com/garagon/aguara/internal/scanner"
)

// pnpm-workspace.yaml is attacker-controlled in a cloned repo, and the
// analyzer walks raw yaml.Node trees including merge-key expansion
// (bounded by a visited set). The fuzzer hunts for panics and for
// inputs that escape that bound.
func FuzzAnalyze(f *testing.F) {
	f.Add("dangerouslyAllowAllBuilds: true\n")
	f.Add("base: &b\n  trustLockfile: true\nprod:\n  <<: *b\n")
	f.Add("a: &a\n  <<: *a\n")
	f.Add("minimumReleaseAge: 0\nonlyBuiltDependencies: []\n")

	a := New()
	f.Fuzz(func(t *testing.T, src string) {
		findings, err := a.Analyze(context.Background(), &scanner.Target{
			Path:    "pnpm-workspace.yaml",
			RelPath: "pnpm-workspace.yaml",
			Content: []byte(src),
		})
		if err != nil {
			return
		}
		for _, fd := range findings {
			if fd.RuleID == "" {
				t.Error("finding with empty RuleID")
			}
		}
	})
}
