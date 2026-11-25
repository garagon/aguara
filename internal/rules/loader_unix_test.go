//go:build unix

package rules

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// A rule file that is a named pipe, or a link to an endless device, is a
// skipped (invalid) rule file, never a read that blocks or does not end.
func TestLoadFromDirRejectsSpecialRuleFiles(t *testing.T) {
	dir := t.TempDir()
	writeLimitRule(t, dir, "LIM_OK")
	fifo := filepath.Join(dir, "pipe.yaml")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	zero := filepath.Join(dir, "zero.yaml")
	if err := os.Symlink("/dev/zero", zero); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	type outcome struct {
		raws    []RawRule
		skipped []SkippedFile
		err     error
	}
	done := make(chan outcome, 1)
	go func() {
		raws, skipped, err := LoadFromDir(dir)
		done <- outcome{raws, skipped, err}
	}()
	var o outcome
	select {
	case o = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("LoadFromDir blocked on a special rule file")
	}
	if o.err != nil {
		t.Fatal(o.err)
	}
	if len(o.raws) != 1 || o.raws[0].ID != "LIM_OK" {
		t.Fatalf("loaded %+v", o.raws)
	}
	requireSkipped(t, o.skipped, fifo, "named pipe, not a regular file")
	if _, err := os.Stat("/dev/zero"); err == nil {
		requireSkipped(t, o.skipped, zero, "device, not a regular file")
	}
}
