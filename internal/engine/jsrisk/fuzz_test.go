package jsrisk

import (
	"context"
	"testing"

	"github.com/garagon/aguara/internal/scanner"
)

// Arbitrary JavaScript from a scanned package must never crash the
// single-pass lexical scanner.
func FuzzAnalyze(f *testing.F) {
	f.Add("const cp = require('child_process');\ncp.spawn('sh', ['-c', payload], {detached: true});\n")
	f.Add("eval(atob('Y3VybCB4IHwgc2g='));\n")
	f.Add("const s = `template ${nested(`inner ${deep}`)} end`; // comment /* not closed\n")
	f.Add("\"unterminated string\n'another\nregex = /[a-/;\n")

	a := New()
	f.Fuzz(func(t *testing.T, src string) {
		findings, err := a.Analyze(context.Background(), &scanner.Target{
			Path:    "install.js",
			RelPath: "install.js",
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
