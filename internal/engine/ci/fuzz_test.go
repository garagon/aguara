package ci

import (
	"context"
	"testing"

	"github.com/garagon/aguara/internal/scanner"
)

// Workflow YAML in a scanned repo is untrusted; the analyzer parses it
// with yaml.v3 and walks jobs/steps/permissions shapes.
func FuzzAnalyze(f *testing.F) {
	f.Add("on: pull_request_target\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v6\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - run: make test\n")
	f.Add("on: [push]\npermissions:\n  id-token: write\njobs: {}\n")
	f.Add("jobs:\n  x: &a\n    steps: *a\n")

	a := New()
	f.Fuzz(func(t *testing.T, src string) {
		findings, err := a.Analyze(context.Background(), &scanner.Target{
			Path:    ".github/workflows/ci.yml",
			RelPath: ".github/workflows/ci.yml",
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
