package safefile

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func put(w io.Writer) error {
	_, err := io.WriteString(w, "complete")
	return err
}

func TestWriteReplacesRegularFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report")
	for range 2 {
		if err := Write(path, put); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil || string(data) != "complete" {
			t.Fatalf("result=%q err=%v", data, err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("output exposed to group/others: %v", info.Mode())
		}
	}
	assertEntries(t, dir, 1)
}

func TestWriteFailurePreservesDestination(t *testing.T) {
	for _, exists := range []bool{false, true} {
		dir := t.TempDir()
		path := filepath.Join(dir, "report")
		if exists {
			if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		want := errors.New("render failed")
		err := Write(path, func(w io.Writer) error {
			_, _ = io.WriteString(w, "partial")
			return want
		})
		if !errors.Is(err, want) {
			t.Fatalf("error=%v", err)
		}
		data, err := os.ReadFile(path)
		if exists {
			if err != nil || string(data) != "original" {
				t.Fatalf("destination changed: %q %v", data, err)
			}
			assertEntries(t, dir, 1)
		} else {
			if !os.IsNotExist(err) {
				t.Fatalf("failed output created: %v", err)
			}
			assertEntries(t, dir, 0)
		}
	}
}

func TestWriteRejectsLinkedAndDirectoryDestinations(t *testing.T) {
	for _, kind := range []string{"symlink", "dangling", "directory"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "report")
			outside := filepath.Join(t.TempDir(), "other")
			if kind == "directory" {
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			} else {
				if kind == "symlink" {
					if err := os.WriteFile(outside, []byte("original"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Symlink(outside, path); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
			}
			called := false
			err := Write(path, func(w io.Writer) error { called = true; return put(w) })
			if err == nil || called {
				t.Fatalf("unsafe destination rendered: called=%v err=%v", called, err)
			}
			assertEntries(t, dir, 1)
			switch kind {
			case "symlink":
				data, err := os.ReadFile(outside)
				if err != nil || string(data) != "original" {
					t.Fatalf("symlink target changed: %q %v", data, err)
				}
			case "dangling":
				if _, err := os.Stat(outside); !os.IsNotExist(err) {
					t.Fatalf("dangling target created: %v", err)
				}
			}
		})
	}
}

func TestWriteRechecksDestinationBeforePublishing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report")
	outside := filepath.Join(t.TempDir(), "other")
	if err := os.WriteFile(outside, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Verify symlink support before entering the callback.
	probe := filepath.Join(dir, "probe")
	if err := os.Symlink(outside, probe); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := os.Remove(probe); err != nil {
		t.Fatal(err)
	}
	err := Write(path, func(w io.Writer) error {
		if err := put(w); err != nil {
			return err
		}
		return os.Symlink(outside, path)
	})
	if err == nil {
		t.Fatal("published over a newly introduced symlink")
	}
	data, err := os.ReadFile(outside)
	if err != nil || string(data) != "original" {
		t.Fatalf("outside changed: %q %v", data, err)
	}
	assertEntries(t, dir, 1)
}

func TestWriteCapturesIgnoredWriteAndCloseErrors(t *testing.T) {
	for _, writeAfterClose := range []bool{false, true} {
		dir := t.TempDir()
		path := filepath.Join(dir, "report")
		err := Write(path, func(w io.Writer) error {
			f := w.(*checkedWriter).writer.(*os.File)
			if err := f.Close(); err != nil {
				return err
			}
			if writeAfterClose {
				_, _ = io.WriteString(w, "ignored error")
			}
			return nil
		})
		if err == nil {
			t.Fatal("closed output published")
		}
		assertEntries(t, dir, 0)
	}
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

func TestCheckedWriterRejectsShortWrite(t *testing.T) {
	w := &checkedWriter{writer: shortWriter{}}
	if _, err := w.Write([]byte("data")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write: %v", err)
	}
	if n, err := w.Write([]byte("again")); n != 0 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("lost first write error: %d %v", n, err)
	}
}

func assertEntries(t *testing.T, dir string, want int) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != want {
		t.Fatalf("unexpected entries: %v err=%v", entries, err)
	}
}
