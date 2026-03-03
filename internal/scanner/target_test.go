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

func TestTargetLoadContentCustomMaxSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.md")

	// Write a file slightly larger than 2 MB
	data := make([]byte, 2<<20+100)
	require.NoError(t, os.WriteFile(path, data, 0644))

	// With a 2 MB limit, this file should be rejected
	target := &scanner.Target{Path: path, RelPath: "big.md", MaxFileSize: 2 << 20}
	err := target.LoadContent()
	require.Error(t, err)
	require.Contains(t, err.Error(), "file too large")

	// With a 3 MB limit, the same file should load fine
	target2 := &scanner.Target{Path: path, RelPath: "big.md", MaxFileSize: 3 << 20}
	require.NoError(t, target2.LoadContent())
	require.Len(t, target2.Content, 2<<20+100)
}

func TestDiscoveryCustomMaxSize(t *testing.T) {
	dir := t.TempDir()

	// Create a small file and a "large" file (> 2 KB)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "small.md"), []byte("hello"), 0644))
	bigData := make([]byte, 3000)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "big.md"), bigData, 0644))

	// With a 2 KB limit, only small.md should be discovered
	td := &scanner.TargetDiscovery{MaxFileSize: 2048}
	targets, err := td.Discover(dir)
	require.NoError(t, err)

	paths := make(map[string]bool)
	for _, target := range targets {
		paths[target.RelPath] = true
	}
	require.True(t, paths["small.md"])
	require.False(t, paths["big.md"])

	// With default (0), both should be discovered
	td2 := &scanner.TargetDiscovery{}
	targets2, err := td2.Discover(dir)
	require.NoError(t, err)

	paths2 := make(map[string]bool)
	for _, target := range targets2 {
		paths2[target.RelPath] = true
	}
	require.True(t, paths2["small.md"])
	require.True(t, paths2["big.md"])
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
