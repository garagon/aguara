package ci

import (
	"context"
	"testing"

	"github.com/garagon/aguara/internal/scanner"
)

// BenchmarkCITrustAnalyzer measures the per-call cost of analyzing a
// realistic-shape pwn-request workflow. No threshold is asserted; the
// number lands in `.bench/` so regressions surface across PRs.
func BenchmarkCITrustAnalyzer(b *testing.B) {
	wf := []byte(`
name: Bundle Size
on: pull_request_target
permissions:
  contents: write
  id-token: write
jobs:
  size:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'pnpm'
      - uses: actions/cache@v4
        with:
          path: ~/.cache
          key: pr-${{ github.event.pull_request.number }}
      - run: pnpm install
      - run: pnpm build
      - run: pnpm publish --provenance
`)
	a := New()
	target := &scanner.Target{
		Path:    ".github/workflows/bundle.yml",
		RelPath: ".github/workflows/bundle.yml",
		Content: wf,
	}
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = a.Analyze(ctx, target)
	}
}
