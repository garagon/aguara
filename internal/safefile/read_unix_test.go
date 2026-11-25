//go:build unix

package safefile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// withDeadline fails the test instead of hanging when fn blocks. A blocked
// read is abandoned in its goroutine; the test binary still exits.
func withDeadline(t *testing.T, fn func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("read blocked on a special file")
		return nil
	}
}

func TestReadRegularRejectsSpecialFilesWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	zeroLink := filepath.Join(dir, "zero")
	if err := os.Symlink("/dev/zero", zeroLink); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	cases := []struct {
		path   string
		follow bool
	}{
		{fifo, false},
		{fifo, true},
		{zeroLink, true},
		{zeroLink, false},
	}
	if _, err := os.Stat("/dev/zero"); err == nil {
		cases = append(cases, struct {
			path   string
			follow bool
		}{"/dev/zero", true})
	}
	for _, c := range cases {
		err := withDeadline(t, func() error {
			_, err := ReadRegular(c.path, c.follow, 1<<20)
			return err
		})
		if !errors.Is(err, ErrNotRegular) {
			t.Fatalf("%s (follow=%v): %v", c.path, c.follow, err)
		}
	}
}

// A file replaced after the type check is caught on the opened descriptor:
// the open does not block on the named pipe and the read is refused.
func TestOpenRegularRejectsReplacementAfterInspection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	err = withDeadline(t, func() error {
		f, err := os.OpenFile(path, os.O_RDONLY|openNonBlock|openNoFollow, 0)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		opened, err := f.Stat()
		if err != nil {
			return err
		}
		if opened.Mode().IsRegular() || os.SameFile(info, opened) {
			t.Fatalf("replacement not detected: %v", opened.Mode())
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
