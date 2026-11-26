//go:build unix

package incident

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// The cross-device fallback of quarantine copies the file; a named pipe
// there is an error instead of a read that blocks.
func TestQuarantineCopyRejectsSpecialFiles(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "artifact")
	if err := unix.Mkfifo(src, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	dst := filepath.Join(t.TempDir(), "artifact")
	done := make(chan error, 1)
	go func() { done <- copyThenRemove(src, dst) }()
	select {
	case err := <-done:
		require.Error(t, err)
		_, statErr := os.Lstat(src)
		require.NoError(t, statErr, "the source stays in place when it cannot be copied")
	case <-time.After(10 * time.Second):
		t.Fatal("quarantine copy blocked on a named pipe")
	}

	regular := filepath.Join(dir, "regular")
	require.NoError(t, os.WriteFile(regular, []byte("payload"), 0o600))
	require.NoError(t, copyThenRemove(regular, dst))
	data, err := os.ReadFile(dst)
	require.NoError(t, err)
	require.Equal(t, "payload", string(data))
	_, err = os.Lstat(regular)
	require.True(t, os.IsNotExist(err))
}
