package scanner_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/garagon/aguara/internal/scanner"
	"github.com/stretchr/testify/require"
)

func TestTargetLoadContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.md")
	require.NoError(t, os.WriteFile(path, []byte("hello\nworld"), 0644))

	target := &scanner.Target{Path: path, RelPath: "test.md"}
	require.NoError(t, target.LoadContent())
	require.Equal(t, "hello\nworld", string(target.Content))

	lines := target.Lines()
	require.Len(t, lines, 2)
	require.Equal(t, "hello", lines[0])
	require.Equal(t, "world", lines[1])
}

func TestTargetDiscovery(t *testing.T) {
	dir := t.TempDir()
	// Create files
	require.NoError(t, os.WriteFile(filepath.Join(dir, "skill.md"), []byte("content"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "helper.py"), []byte("code"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "image.png"), []byte("binary"), 0644))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".git"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".git", "HEAD"), []byte("ref"), 0644))

	td := &scanner.TargetDiscovery{}
	targets, err := td.Discover(dir)
	require.NoError(t, err)

	// Should find skill.md and helper.py, but not image.png or .git/HEAD
	paths := make(map[string]bool)
	for _, target := range targets {
		paths[target.RelPath] = true
	}
	require.True(t, paths["skill.md"])
	require.True(t, paths["helper.py"])
	require.False(t, paths["image.png"])
	require.False(t, paths[".git/HEAD"])
}

func TestAguaraIgnore(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "keep.md"), []byte("keep"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "skip.log"), []byte("skip"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".aguaraignore"), []byte("*.log\n"), 0644))

	td := &scanner.TargetDiscovery{}
	targets, err := td.Discover(dir)
	require.NoError(t, err)

	paths := make(map[string]bool)
	for _, target := range targets {
		paths[target.RelPath] = true
	}
	require.True(t, paths["keep.md"])
	require.False(t, paths["skip.log"])
}
