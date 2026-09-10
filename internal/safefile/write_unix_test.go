//go:build unix

package safefile

import (
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestWriteRejectsFIFO(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, put); err == nil {
		t.Fatal("FIFO accepted")
	}
	assertEntries(t, dir, 1)
}
