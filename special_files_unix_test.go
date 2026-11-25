//go:build unix

package aguara_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/garagon/aguara"
)

func TestScanSkipsSpecialFilesPublicAPI(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.md"), []byte("# a\n"), 0o600))
	if err := unix.Mkfifo(filepath.Join(dir, "SKILL.md"), 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	type outcome struct {
		r   *aguara.ScanResult
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		r, err := aguara.Scan(ctx, dir, aguara.WithWorkers(1))
		done <- outcome{r, err}
	}()
	select {
	case o := <-done:
		require.NoError(t, o.err)
		require.Equal(t, 1, o.r.FilesScanned)
		require.Equal(t, []aguara.SkippedFile{{Path: "SKILL.md", Kind: aguara.SkippedNamedPipe}}, o.r.Skipped)
	case <-time.After(15 * time.Second):
		t.Fatal("Scan blocked on a named pipe")
	}
}
