// Package safefile writes private artifacts without following destination links.
package safefile

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Write renders into a unique sibling temporary file, then replaces path.
// Destinations must be absent or regular files. Files use mode 0600, subject
// to umask; callers must provide an existing parent directory.
//
// Replacement changes the inode rather than modifying existing hard links.
// Rename is atomic on Unix, but not guaranteed atomic on every platform.
// This does not provide ancestor confinement or a filesystem snapshot.
func Write(path string, render func(io.Writer) error) error {
	if err := checkDestination(path); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".aguara-output-*")
	if err != nil {
		return err
	}
	name := f.Name()
	closed := false
	defer func() {
		if !closed {
			_ = f.Close()
		}
		_ = os.Remove(name)
	}()

	w := &checkedWriter{writer: f}
	if err := render(w); err != nil {
		return err
	}
	if w.err != nil {
		return w.err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	err = f.Close()
	closed = true
	if err != nil {
		return err
	}
	if err := checkDestination(path); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func checkDestination(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("output destination must be a regular file, not a symlink or special file: %q", path)
	}
	return nil
}

// Some text formatters discard individual fmt write errors. Retain the first
// failure so a callback returning nil cannot publish an incomplete artifact.
type checkedWriter struct {
	writer io.Writer
	err    error
}

func (w *checkedWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	n, err := w.writer.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	w.err = err
	return n, err
}
