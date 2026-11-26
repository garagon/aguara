package scanner_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/types"
)

// linkFixture builds a tree with content the walk reads and content it
// skips for each reason, plus a links/ directory holding one link to every
// entry. It returns the root and the link targets by link name.
func linkFixture(t *testing.T) (string, map[string]string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	files := map[string]string{
		"README.md":                 "# read\n",
		"docs/guide.md":             "# read\n",
		"docs/image.png":            "binary extension\n",
		"docs/big.md":               strings.Repeat("over the size limit\n", 10),
		"notes/keep.md":             "# read\n",
		"notes/skip.md":             "excluded by a file pattern\n",
		"vendor/lib.md":             "excluded by a subtree pattern\n",
		"vendor/deep/more.md":       "excluded by a subtree pattern\n",
		"node_modules/x/payload.md": "never walked\n",
		".git/notes.md":             "never walked\n",
		".aguara/state.md":          "never walked\n",
		"docs/.git/inner.md":        "never walked\n",
	}
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	}
	require.NoError(t, os.Mkdir(filepath.Join(root, "links"), 0o755))
	targets := map[string]string{}
	add := func(rel string) {
		name := "l" + strings.NewReplacer("/", "_", ".", "_").Replace(rel) + ".md"
		if err := os.Symlink(filepath.Join(root, filepath.FromSlash(rel)), filepath.Join(root, "links", name)); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		targets[name] = rel
	}
	for name := range files {
		add(name)
	}
	for _, dir := range []string{".", "docs", "notes", "vendor", "vendor/deep", "node_modules", "node_modules/x", ".git", ".aguara", "docs/.git"} {
		add(dir)
	}
	// A link to a link resolves to the final target.
	require.NoError(t, os.Symlink(filepath.Join(root, "links", "lREADME_md.md"), filepath.Join(root, "links", "chain.md")))
	targets["chain.md"] = "README.md"
	return root, targets
}

// A link is inside exactly when the walk reads what it reaches: a file
// the walk returns as a target, or a directory the walk enters and reads
// files under. Everything else in the target is excluded.
func TestLinkResolutionMatchesWhatTheWalkReads(t *testing.T) {
	root, linkTargets := linkFixture(t)
	td := &scanner.TargetDiscovery{
		IgnorePatterns: []string{"vendor/**", "notes/skip.md"},
		MaxFileSize:    64,
	}
	found, err := td.Discover(root)
	require.NoError(t, err)
	read := map[string]bool{}
	for _, target := range found {
		read[filepath.ToSlash(target.RelPath)] = true
	}
	require.Equal(t, map[string]bool{"README.md": true, "docs/guide.md": true, "notes/keep.md": true}, read)
	require.Equal(t, 3, td.ExcludedByCallerPatterns, "vendor/lib.md, vendor/deep/more.md and notes/skip.md; resolving links counts none")

	resolves := map[string]string{}
	for _, s := range td.Skipped {
		require.Equal(t, types.SkippedSymlink, s.Kind, s.Path)
		resolves[filepath.Base(s.Path)] = s.Resolves
	}
	require.Len(t, resolves, len(linkTargets))
	for name, rel := range linkTargets {
		info, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel)))
		require.NoError(t, err)
		walked := read[rel]
		if info.IsDir() {
			walked = false
			for path := range read {
				if rel == "." || strings.HasPrefix(path, rel+"/") {
					walked = true
				}
			}
		}
		want := types.LinkExcluded
		if walked {
			want = types.LinkInside
		}
		require.Equal(t, want, resolves[name], "link %s to %s", name, rel)
	}
}

// A changed link is resolved by the same rules.
func TestScanPathsResolvesChangedLinksLikeTheWalk(t *testing.T) {
	root, _ := linkFixture(t)
	s := scanner.New(1)
	r, err := s.ScanPaths(t.Context(), root, []string{"links/lnode_modules_x_payload_md.md", "links/ldocs_guide_md.md", "links/ldocs_image_png.md"}, nil)
	require.NoError(t, err)
	require.Equal(t, []types.SkippedFile{
		{Path: "links/ldocs_guide_md.md", Kind: types.SkippedSymlink, Resolves: types.LinkInside},
		{Path: "links/ldocs_image_png.md", Kind: types.SkippedSymlink, Resolves: types.LinkExcluded},
		{Path: "links/lnode_modules_x_payload_md.md", Kind: types.SkippedSymlink, Resolves: types.LinkExcluded},
	}, r.Skipped)
}
