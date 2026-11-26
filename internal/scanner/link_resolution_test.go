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

// probeName names the probe links linkFixture puts in each directory.
const probeName = "zz-probe"

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
		// A probe link in every directory: a walk lists it exactly when it
		// enters the directory and no pattern covers everything there.
		require.NoError(t, os.Symlink(filepath.Join(root, "README.md"), filepath.Join(root, filepath.FromSlash(dir), probeName)))
	}
	// A link to a link resolves to the final target.
	require.NoError(t, os.Symlink(filepath.Join(root, "links", "lREADME_md.md"), filepath.Join(root, "links", "chain.md")))
	targets["chain.md"] = "README.md"
	return root, targets
}

// A link is inside exactly when the walk reads what it reaches: a file
// the walk returns as a target, or a directory the walk enters and reads
// files under. Everything else in the target is excluded.
//
// It holds for the ignore forms every release accepts ("vendor/**", a path)
// and for the gitignore forms: a directory pattern prunes the walk, an
// anchored pattern matches from the root, "**" spans directories.
func TestLinkResolutionMatchesWhatTheWalkReads(t *testing.T) {
	for name, tc := range map[string]struct {
		patterns []string
		excluded int // what the walk counts; resolving links counts none
	}{
		"recursive glob and path": {[]string{"vendor/**", "notes/skip.md"}, 3},            // vendor/lib.md, vendor/deep/more.md, notes/skip.md
		"directory and anchored":  {[]string{"vendor/", "/notes/skip.md"}, 2},             // vendor/ pruned whole, notes/skip.md
		"double star":             {[]string{"**/deep/", "vendor/*.md", "**/skip.md"}, 3}, // vendor/deep/ pruned, vendor/lib.md, notes/skip.md
	} {
		t.Run(name, func(t *testing.T) { checkLinksMatchWalk(t, tc.patterns, tc.excluded) })
	}
}

func checkLinksMatchWalk(t *testing.T, patterns []string, excluded int) {
	root, linkTargets := linkFixture(t)
	td := &scanner.TargetDiscovery{IgnorePatterns: patterns, MaxFileSize: 64}
	found, err := td.Discover(root)
	require.NoError(t, err)
	read := map[string]bool{}
	for _, target := range found {
		read[filepath.ToSlash(target.RelPath)] = true
	}
	require.Equal(t, map[string]bool{"README.md": true, "docs/guide.md": true, "notes/keep.md": true}, read)
	require.Equal(t, excluded, td.ExcludedByCallerPatterns)

	resolves := map[string]string{}
	entered := map[string]bool{}
	for _, s := range td.Skipped {
		require.Equal(t, types.SkippedSymlink, s.Kind, s.Path)
		if filepath.Base(s.Path) == probeName {
			entered[filepath.ToSlash(filepath.Dir(s.Path))] = true
			continue
		}
		resolves[filepath.Base(s.Path)] = s.Resolves
	}
	require.Len(t, resolves, len(linkTargets))
	for name, rel := range linkTargets {
		info, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel)))
		require.NoError(t, err)
		// A file is reached when the walk reads it; a directory when the
		// walk enters it (its probe is listed).
		walked := read[rel]
		if info.IsDir() {
			walked = entered[rel]
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
	r, err := s.ScanChangedPaths(t.Context(), root, []string{"links/lnode_modules_x_payload_md.md", "links/ldocs_guide_md.md", "links/ldocs_image_png.md"}, nil)
	require.NoError(t, err)
	require.Equal(t, []types.SkippedFile{
		{Path: "links/ldocs_guide_md.md", Kind: types.SkippedSymlink, Resolves: types.LinkInside},
		{Path: "links/ldocs_image_png.md", Kind: types.SkippedSymlink, Resolves: types.LinkExcluded},
		{Path: "links/lnode_modules_x_payload_md.md", Kind: types.SkippedSymlink, Resolves: types.LinkExcluded},
	}, r.Skipped)
}
