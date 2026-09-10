package state

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStateSaveIgnoresPreexistingTemporarySymlink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	outside := filepath.Join(t.TempDir(), "untouched")
	require.NoError(t, os.WriteFile(outside, []byte("original"), 0o600))
	if err := os.Symlink(outside, path+".tmp"); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	store := New(path)
	store.Set("skill.md", "hash")
	err := store.Save()
	data, readErr := os.ReadFile(outside)
	require.NoError(t, readErr)
	require.Equal(t, "original", string(data))
	require.NoError(t, err)
	require.NoError(t, New(path).Load())
}
