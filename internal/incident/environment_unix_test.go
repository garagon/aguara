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

// A FIFO planted as METADATA or as a .pth file in a committed virtual
// environment must not hang the check.
func TestInstalledReadsDoNotBlockOnSpecialFiles(t *testing.T) {
	site := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(site, "fifo-1.0.dist-info"), 0o755))
	if err := unix.Mkfifo(filepath.Join(site, "fifo-1.0.dist-info", "METADATA"), 0o644); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	require.NoError(t, unix.Mkfifo(filepath.Join(site, "trap.pth"), 0o644))
	writeDistInfo(t, site, "ok-1.0.dist-info", "Name: ok\nVersion: 1.0\n")

	type outcome struct {
		res        *CheckResult
		err        error
		pthFinding []Finding
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := CheckEnvironment(CheckOptions{Path: site, Intel: environmentOverride()})
		done <- outcome{res, err, checkPthFile(filepath.Join(site, "trap.pth"))}
	}()
	select {
	case o := <-done:
		require.NoError(t, o.err)
		require.Equal(t, 1, o.res.PackagesRead, "the FIFO dist-info is unreadable, the regular one is read")
		require.Empty(t, o.pthFinding)
	case <-time.After(10 * time.Second):
		t.Fatal("installed-file read blocked on a FIFO")
	}
}
