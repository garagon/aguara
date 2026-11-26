package scanner_test

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/garagon/aguara/internal/scanner"
)

func relPaths(targets []*scanner.Target) []string {
	var out []string
	for _, t := range targets {
		out = append(out, filepath.ToSlash(t.RelPath))
	}
	sort.Strings(out)
	return out
}

func TestDiscoverPathsRelativeToRoot(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, "a/x.md", "a/y.md", "b/z.md", "c.md", "vendor/lib/v.md", "img.png")
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".aguaraignore"), []byte("vendor/\n"), 0o644))
	t.Chdir(dir)

	td := &scanner.TargetDiscovery{}
	targets, err := td.DiscoverPaths(".", []string{"a", "a/x.md", "./c.md", "vendor/lib/v.md", "vendor/lib", "img.png", "c.md"})
	require.NoError(t, err)
	require.Equal(t, []string{"a/x.md", "a/y.md", "c.md"}, relPaths(targets),
		"duplicates collapse; .aguaraignore and binary extensions apply to named paths")
	require.Equal(t, 2, td.ExcludedByIgnoreFile)

	td = &scanner.TargetDiscovery{IgnoreProjectFile: true}
	targets, err = td.DiscoverPaths(".", []string{"vendor/lib/v.md", "b"})
	require.NoError(t, err)
	require.Equal(t, []string{"b/z.md", "vendor/lib/v.md"}, relPaths(targets), "untrusted policy is not read")
}

func TestDiscoverPathsRejectsPathsOutsideRoot(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	writeTree(t, outside, "x.md")
	writeTree(t, root, "in.md")
	if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	td := &scanner.TargetDiscovery{}
	_, err := td.DiscoverPaths(root, []string{filepath.Join(outside, "x.md")})
	require.ErrorContains(t, err, "outside the scan root")
	_, err = td.DiscoverPaths(root, []string{filepath.Join(root, "linked", "x.md")})
	require.ErrorContains(t, err, "outside the scan root", "a linked parent directory cannot reach outside root")

	targets, err := td.DiscoverPaths(root, []string{filepath.Join(root, "in.md"), filepath.Join(root, "linked")})
	require.NoError(t, err)
	require.Equal(t, []string{"in.md"}, relPaths(targets))
	require.Len(t, td.Skipped, 1)
	require.Equal(t, filepath.Join(root, "linked"), td.Skipped[0].Path)
	require.Contains(t, td.Skipped[0].Reason, "symbolic link")

	_, err = td.DiscoverPaths(root, []string{filepath.Join(root, "missing.md")})
	require.ErrorIs(t, err, scanner.ErrIncompleteScan)
}

// Paths inside the directories a walk always skips are skipped when named
// too, so a path list equals a directory scan, and each is reported.
func TestDiscoverPathsSkipsAlwaysSkippedDirectories(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, "a.md", "node_modules/pkg/index.md", ".git/config", ".aguara/state.md", "src/node_modules/x.md")
	t.Chdir(dir)
	td := &scanner.TargetDiscovery{}
	targets, err := td.DiscoverPaths(".", []string{"a.md", "node_modules/pkg/index.md", ".git/config", ".aguara", "src/node_modules", "node_modules"})
	require.NoError(t, err)
	require.Equal(t, []string{"a.md"}, relPaths(targets))
	var skipped []string
	for _, s := range td.Skipped {
		skipped = append(skipped, s.Path)
		require.Contains(t, s.Reason, "directory walks always skip")
	}
	require.Equal(t, []string{"node_modules/pkg/index.md", ".git/config", ".aguara", "src/node_modules", "node_modules"}, skipped)

	whole, err := (&scanner.TargetDiscovery{}).Discover(dir)
	require.NoError(t, err)
	require.Equal(t, relPaths(whole), relPaths(targets), "the same files as a directory scan")
}

// A working directory reached through a symbolic link is still the root.
func TestDiscoverPathsFromLinkedWorkingDirectory(t *testing.T) {
	real := t.TempDir()
	writeTree(t, real, "a.md", "sub/b.md")
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	t.Chdir(link)
	td := &scanner.TargetDiscovery{}
	targets, err := td.DiscoverPaths(".", []string{".", "a.md", "sub"})
	require.NoError(t, err)
	require.Equal(t, []string{"a.md", "sub/b.md"}, relPaths(targets))
}

func TestDiscoverPathsRejectsSpecialFiles(t *testing.T) {
	if _, err := os.Stat(os.DevNull); err != nil {
		t.Skip("no device file")
	}
	td := &scanner.TargetDiscovery{}
	_, err := td.DiscoverPaths(filepath.Dir(os.DevNull), []string{os.DevNull})
	require.ErrorIs(t, err, scanner.ErrIncompleteScan)
	require.ErrorContains(t, err, "not a regular file or directory")
}

func TestDiscoverPathsSizeLimit(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "big.md"), make([]byte, 64), 0o644))
	td := &scanner.TargetDiscovery{MaxFileSize: 32}
	_, err := td.DiscoverPaths(dir, []string{filepath.Join(dir, "big.md")})
	require.ErrorIs(t, err, scanner.ErrIncompleteScan)
	td = &scanner.TargetDiscovery{MaxFileSize: 32, IgnorePatterns: []string{"big.md"}}
	targets, err := td.DiscoverPaths(dir, []string{filepath.Join(dir, "big.md")})
	require.NoError(t, err)
	require.Empty(t, targets, "an exclusion takes precedence over the size limit, as in a walk")
}
