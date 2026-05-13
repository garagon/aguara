package pkgmeta

import (
	"context"
	"testing"

	"github.com/garagon/aguara/internal/scanner"
)

// BenchmarkPkgMetaAnalyzer measures the per-call cost of analyzing a
// full-chain package.json (lifecycle script, optional git dep, publish
// surface with provenance reference). No threshold is asserted.
func BenchmarkPkgMetaAnalyzer(b *testing.B) {
	pkg := []byte(`{
  "name": "x",
  "version": "1.0.0",
  "publishConfig": {"provenance": true, "access": "public"},
  "scripts": {
    "postinstall": "node ./hook.js",
    "build": "tsc",
    "test": "vitest",
    "release": "npm publish --provenance"
  },
  "dependencies": {
    "left-pad": "^1.3.0",
    "lodash": "^4.17.21"
  },
  "optionalDependencies": {
    "setup": "github:owner/setup",
    "fsevents": "^2.3.0"
  }
}`)
	a := New()
	target := &scanner.Target{
		Path:    "package.json",
		RelPath: "package.json",
		Content: pkg,
	}
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = a.Analyze(ctx, target)
	}
}
