package scanner_test

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/garagon/aguara/internal/scanner"
)

// writeTree creates every slash-separated file path under dir.
func writeTree(t *testing.T, dir string, files ...string) {
	t.Helper()
	for _, f := range files {
		path := filepath.Join(dir, filepath.FromSlash(f))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte("content\n"), 0o644))
	}
}

// discovered returns the slash-separated RelPath of every target.
func discovered(t *testing.T, td *scanner.TargetDiscovery, dir string) []string {
	t.Helper()
	targets, err := td.Discover(dir)
	require.NoError(t, err)
	var paths []string
	for _, target := range targets {
		paths = append(paths, filepath.ToSlash(target.RelPath))
	}
	sort.Strings(paths)
	return paths
}

// A trailing slash names a directory: it excludes that directory and
// everything under it, at any depth unless the pattern is anchored.
func TestIgnoreTrailingSlashExcludesDirectoryTrees(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir,
		"dist/app.md", "dist/nested/deep.md",
		"packages/web/dist/bundle.md",
		".venv/lib/site.py",
		"build/out.md", "src/build/kept.md",
		"distribution.md", "src/main.md",
	)
	td := &scanner.TargetDiscovery{IgnorePatterns: []string{"dist/", ".venv/", "/build/"}}
	require.Equal(t, []string{"distribution.md", "src/build/kept.md", "src/main.md"}, discovered(t, td, dir))
}

// The same patterns work from the project's .aguaraignore, which is what
// `aguara init` scaffolds.
func TestIgnoreFileTrailingSlashPatterns(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, "vendor/lib/x.md", "node/x.md", "coverage/index.md", "notes.md")
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".aguaraignore"), []byte("# deps\nvendor/\ncoverage/\n"), 0o644))
	td := &scanner.TargetDiscovery{}
	require.Equal(t, []string{".aguaraignore", "node/x.md", "notes.md"}, discovered(t, td, dir))
	require.Equal(t, 2, td.ExcludedByIgnoreFile, "each pruned directory counts once")
}

func TestIgnoreAnchoredPatterns(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, "out", "sub/out", "docs/a.md", "docs/b.txt", "x/docs/c.md", "logs/today/l.md")
	for _, tc := range []struct {
		pattern string
		want    []string
	}{
		// A leading slash anchors a name to the scan root; it covers a
		// file or a directory with that name there.
		{"/out", []string{"docs/a.md", "docs/b.txt", "logs/today/l.md", "sub/out", "x/docs/c.md"}},
		{"/docs", []string{"logs/today/l.md", "out", "sub/out", "x/docs/c.md"}},
		{"./docs/", []string{"logs/today/l.md", "out", "sub/out", "x/docs/c.md"}},
		{"/docs/*.md", []string{"docs/b.txt", "logs/today/l.md", "out", "sub/out", "x/docs/c.md"}},
		{"/logs/*/", []string{"docs/a.md", "docs/b.txt", "out", "sub/out", "x/docs/c.md"}},
	} {
		t.Run(tc.pattern, func(t *testing.T) {
			td := &scanner.TargetDiscovery{IgnorePatterns: []string{tc.pattern}}
			require.Equal(t, tc.want, discovered(t, td, dir))
		})
	}
}

// A literal path with a slash in it is matched from the scan root, as
// before, and now also covers the directory it names.
func TestIgnoreLiteralPathCoversDirectory(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, "docs/internal/a.md", "docs/internal/deep/b.md", "docs/public.md", "x/docs/internal/c.md")
	td := &scanner.TargetDiscovery{IgnorePatterns: []string{"docs/internal"}}
	require.Equal(t, []string{"docs/public.md", "x/docs/internal/c.md"}, discovered(t, td, dir))
}

// "**" alone excludes everything, as "*" already did.
func TestIgnoreDoubleStarAlone(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, "a.md", "b/c.md")
	td := &scanner.TargetDiscovery{IgnorePatterns: []string{"**"}}
	require.Empty(t, discovered(t, td, dir))
}

// "**/" names every directory, so it excludes everything below the root
// but not the files at the root, as in gitignore; "/**" excludes all.
func TestIgnoreDoubleStarDirectoryForms(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, "a.md", "b/c.md", "b/d/e.md")
	td := &scanner.TargetDiscovery{IgnorePatterns: []string{"**/"}}
	require.Equal(t, []string{"a.md"}, discovered(t, td, dir))
	td = &scanner.TargetDiscovery{IgnorePatterns: []string{"/**"}}
	require.Empty(t, discovered(t, td, dir))
}

// A bare name without a slash keeps matching file names only. Treating it
// as a directory too would make an entry such as "aguara" (a build
// output) also exclude source directories such as cmd/aguara/.
func TestIgnoreBareNameStillMatchesFilesOnly(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, "aguara", "cmd/aguara/main.go", "cmd/aguara/aguara")
	td := &scanner.TargetDiscovery{IgnorePatterns: []string{"aguara"}}
	require.Equal(t, []string{"cmd/aguara/main.go"}, discovered(t, td, dir))
}

// gitignore spells a negated character class [!...]; Go's matcher only
// understood [^...]. Both now negate.
func TestIgnoreNegatedCharacterClass(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, "a1.md", "b1.md", "!1.md")
	for _, pattern := range []string{"[!a]1.md", "[^a]1.md"} {
		t.Run(pattern, func(t *testing.T) {
			td := &scanner.TargetDiscovery{IgnorePatterns: []string{pattern}}
			require.Equal(t, []string{"a1.md"}, discovered(t, td, dir))
		})
	}
}

// Negation is not supported. A "!" pattern never matches, not even a file
// whose name starts with "!", and discovery reports it as unsupported so
// the CLI can warn instead of silently treating it as a literal.
func TestIgnoreNegationIsReportedNotApplied(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, "secret.md", "!secret.md")
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".aguaraignore"), []byte("*.md\n!secret.md\n"), 0o644))
	td := &scanner.TargetDiscovery{}
	require.Equal(t, []string{".aguaraignore"}, discovered(t, td, dir))
	uses := td.PatternUses(dir)
	require.Len(t, uses, 2)
	require.Equal(t, "!secret.md", uses[1].Pattern)
	require.Equal(t, 2, uses[1].Line)
	require.NotEmpty(t, uses[1].Unsupported)
	require.Zero(t, uses[1].Matched)
	require.Empty(t, uses[0].Unsupported)
	require.Equal(t, 2, uses[0].Matched)
}

// Patterns that matched nothing are detectable, with a hint when a bare
// name matched no file but names a directory that was scanned.
func TestIgnorePatternUsesReportUnmatchedPatterns(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, "dist/a.md", "notes.log", "keep.md")
	td := &scanner.TargetDiscovery{IgnorePatterns: []string{"*.log", "dist", "missing/"}}
	require.Equal(t, []string{"dist/a.md", "keep.md"}, discovered(t, td, dir))
	uses := td.PatternUses(dir)
	require.Len(t, uses, 3)
	require.Equal(t, 1, uses[0].Matched)
	require.Zero(t, uses[1].Matched)
	require.Contains(t, uses[1].Hint, "dist/")
	require.Zero(t, uses[2].Matched)
	require.Empty(t, uses[2].Hint)
	for _, u := range uses {
		require.Empty(t, u.File, "caller patterns have no file")
	}
}

// An unreadable directory under an excluded directory is never read.
func TestIgnoreDirectoryPatternSkipsUnreadableSubtree(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, "keep.md")
	locked := filepath.Join(dir, "build", "locked")
	require.NoError(t, os.MkdirAll(locked, 0o700))
	require.NoError(t, os.Chmod(locked, 0))
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
	if _, err := os.ReadDir(locked); err == nil {
		t.Skip("permissions not enforced")
	}
	td := &scanner.TargetDiscovery{IgnorePatterns: []string{"build/"}}
	require.Equal(t, []string{"keep.md"}, discovered(t, td, dir))
}
