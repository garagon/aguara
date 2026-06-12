package pkgmeta

import (
	"context"
	"testing"

	"github.com/garagon/aguara/internal/scanner"
)

// package.json manifests are untrusted input from scanned repos.
func FuzzAnalyze(f *testing.F) {
	f.Add(`{"scripts":{"postinstall":"node setup.js"},"dependencies":{"x":"git+https://github.com/a/b"}}`)
	f.Add(`{"optionalDependencies":{"y":"github:a/b#commit"}}`)
	f.Add(`{"scripts":[1,2],"dependencies":"nope"}`)

	a := New()
	f.Fuzz(func(t *testing.T, src string) {
		findings, err := a.Analyze(context.Background(), &scanner.Target{
			Path:    "package.json",
			RelPath: "package.json",
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
