package commands

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// A "!" pattern is unsupported. Instead of silently doing nothing (or
// matching a file literally named "!..."), every local scan warns with
// its file and line.
func TestScanWarnsAboutNegationPatterns(t *testing.T) {
	clearCIEnv(t)
	dir := projectWith(t, map[string]string{
		".aguaraignore": "*.log\n!keep.log\n",
		".aguara.yml":   "ignore:\n  - \"!other\"\n",
		"keep.log":      injectionPayload,
	})
	stderr := captureStderrBytes(t, func() {
		_, err := runScanJSONWithError(t, dir)
		require.NoError(t, err)
	})
	require.Contains(t, string(stderr), filepath.Join(dir, ".aguaraignore")+`:2: ignore pattern "!keep.log": negation (!) is not supported`)
	require.Contains(t, string(stderr), filepath.Join(dir, ".aguara.yml")+` ignore: ignore pattern "!other"`)

	// Untrusted policy is never read, so it is never warned about.
	stderr = captureStderrBytes(t, func() {
		_, err := runScanJSONWithError(t, dir, "--project-policy", "ignore")
		require.NoError(t, err)
	})
	require.NotContains(t, string(stderr), "negation")
}

// Patterns that matched nothing are listed only with --verbose, so normal
// runs stay quiet, with a hint for a bare name that spells a directory.
func TestScanVerboseListsUnmatchedIgnorePatterns(t *testing.T) {
	clearCIEnv(t)
	dir := projectWith(t, map[string]string{
		".aguaraignore": "dist\nbuild/\n*.log\n",
		"dist/app.md":   "# app\n",
		"debug.log":     "x\n",
	})
	stderr := captureStderrBytes(t, func() {
		_, err := runScanJSONWithError(t, dir)
		require.NoError(t, err)
	})
	require.NotContains(t, string(stderr), "matched nothing")

	stderr = captureStderrBytes(t, func() {
		_, err := runScanJSONWithError(t, dir, "--verbose")
		require.NoError(t, err)
	})
	out := string(stderr)
	require.Contains(t, out, `:1: ignore pattern "dist" matched nothing in this scan; a directory named dist was scanned`)
	require.Contains(t, out, `write dist/ to exclude`)
	require.Contains(t, out, `:2: ignore pattern "build/" matched nothing in this scan`)
	require.NotContains(t, out, `"*.log" matched nothing`)
}
