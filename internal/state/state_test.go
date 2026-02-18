package state

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	// Create and populate store
	s := New(path)
	s.Set("file1.md", "abc123")
	s.Set("file2.md", "def456")

	require.NoError(t, s.Save())

	// Load into a new store
	s2 := New(path)
	require.NoError(t, s2.Load())

	e1, ok := s2.Get("file1.md")
	assert.True(t, ok)
	assert.Equal(t, "abc123", e1.Hash)

	e2, ok := s2.Get("file2.md")
	assert.True(t, ok)
	assert.Equal(t, "def456", e2.Hash)

	_, ok = s2.Get("nonexistent")
	assert.False(t, ok)
}

func TestStoreLoadNonexistent(t *testing.T) {
	s := New("/tmp/nonexistent-aguara-test-state.json")
	// Should not error on missing file
	assert.NoError(t, s.Load())
	assert.Empty(t, s.Entries)
}

func TestStoreCreatesDirs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "deep", "state.json")

	s := New(path)
	s.Set("key", "val")
	require.NoError(t, s.Save())

	_, err := os.Stat(path)
	assert.NoError(t, err)
}

func TestDefaultPath(t *testing.T) {
	p := DefaultPath()
	assert.Contains(t, p, "state.json")
	assert.Contains(t, p, ".aguara")
}
