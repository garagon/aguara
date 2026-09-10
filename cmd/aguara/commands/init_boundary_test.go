package commands

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInitRejectsLinkedOutputs(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
		run  func(string) error
	}{
		{"config", ".aguara.yml", func(dir string) error { return runInit(nil, []string{dir}) }},
		{"ignore", ".aguaraignore", func(dir string) error { return runInit(nil, []string{dir}) }},
		{"workflow", ".github/workflows/aguara.yml", initCIOnly},
		{"hook", ".git/hooks/pre-commit", initHook},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			outside := filepath.Join(t.TempDir(), "must-not-be-created")
			path := filepath.Join(dir, filepath.FromSlash(tc.path))
			require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
			if err := os.Symlink(outside, path); err != nil {
				t.Skipf("symlink unavailable: %v", err)
			}
			require.Error(t, tc.run(dir))
			_, err := os.Lstat(outside)
			require.True(t, os.IsNotExist(err), "must not write through a dangling link")
		})
	}
}

func TestInitRejectsEscapingOutputParents(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(string) error
	}{
		{".github", initCIOnly},
		{".git", initHook},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, outside := t.TempDir(), t.TempDir()
			if err := os.Symlink(outside, filepath.Join(dir, tc.name)); err != nil {
				t.Skipf("symlink unavailable: %v", err)
			}
			require.Error(t, tc.run(dir))
			entries, err := os.ReadDir(outside)
			require.NoError(t, err)
			require.Empty(t, entries)
		})
	}
}

func TestInitRootedCreatePreservesExistingFiles(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	require.NoError(t, err)
	defer func() { _ = root.Close() }()
	created, err := createScaffoldFile(root, "existing", "original", 0o600)
	require.NoError(t, err)
	require.True(t, created)
	before, err := os.Stat(filepath.Join(dir, "existing"))
	require.NoError(t, err)
	created, err = createScaffoldFile(root, "existing", "replacement", 0o755)
	require.NoError(t, err)
	require.False(t, created)
	data, err := os.ReadFile(filepath.Join(dir, "existing"))
	require.NoError(t, err)
	require.Equal(t, "original", string(data))
	after, err := os.Stat(filepath.Join(dir, "existing"))
	require.NoError(t, err)
	require.Equal(t, before.Mode(), after.Mode())
	if err := os.Symlink("existing", filepath.Join(dir, "linked")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	created, err = createScaffoldFile(root, "linked", "replacement", 0o644)
	require.Error(t, err)
	require.False(t, created)
	data, err = os.ReadFile(filepath.Join(dir, "existing"))
	require.NoError(t, err)
	require.Equal(t, "original", string(data))
}

func TestInitRootedCreateParentLinks(t *testing.T) {
	base := t.TempDir()
	dir, outside := filepath.Join(base, "root"), filepath.Join(base, "outside")
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "inside"), 0o700))
	require.NoError(t, os.Mkdir(outside, 0o700))
	if err := os.Symlink("../outside", filepath.Join(dir, "escape")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	require.NoError(t, os.Symlink("inside", filepath.Join(dir, "linked")))
	root, err := os.OpenRoot(dir)
	require.NoError(t, err)
	defer func() { _ = root.Close() }()
	created, err := createScaffoldFile(root, "escape/nested/file", "fixture", 0o600)
	require.Error(t, err)
	require.False(t, created)
	entries, err := os.ReadDir(outside)
	require.NoError(t, err)
	require.Empty(t, entries)
	created, err = createScaffoldFile(root, "linked/nested/file", "fixture", 0o600)
	require.NoError(t, err)
	require.True(t, created, "relative links remaining inside the selected root are supported")
}

func TestPathHintClaimDoesNotFollowLinks(t *testing.T) {
	home := t.TempDir()
	require.True(t, claimPathHint(home))
	require.False(t, claimPathHint(home))
	for _, parent := range []bool{false, true} {
		home, outside := t.TempDir(), t.TempDir()
		link, dest := filepath.Join(home, ".aguara"), outside
		if !parent {
			require.NoError(t, os.Mkdir(link, 0o700))
			link = filepath.Join(link, ".path-hint-shown")
			dest = filepath.Join(outside, "missing")
		}
		if err := os.Symlink(dest, link); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		require.False(t, claimPathHint(home))
		entries, err := os.ReadDir(outside)
		require.NoError(t, err)
		require.Empty(t, entries)
	}
}
