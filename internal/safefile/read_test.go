package safefile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadRegularReadsAndBoundsRegularFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := os.WriteFile(path, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, follow := range []bool{false, true} {
		data, err := ReadRegular(path, follow, 5)
		if err != nil || string(data) != "12345" {
			t.Fatalf("follow=%v: %q %v", follow, data, err)
		}
		if _, err := ReadRegular(path, follow, 4); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("follow=%v: limit not enforced: %v", follow, err)
		}
	}
	if _, err := ReadRegular(filepath.Join(dir, "missing"), true, 5); !os.IsNotExist(err) {
		t.Fatalf("missing file: %v", err)
	}
	if _, err := ReadRegular(dir, true, 5); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("directory accepted: %v", err)
	}
}

// The limit holds even when the reported size is smaller than the stream.
func TestReadLimitedIgnoresReportedSize(t *testing.T) {
	if _, err := ReadLimited(strings.NewReader("123456"), "stream", 5); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("stream over the limit accepted: %v", err)
	}
	data, err := ReadLimited(strings.NewReader("12345"), "stream", 5)
	if err != nil || string(data) != "12345" {
		t.Fatalf("%q %v", data, err)
	}
}

func TestOpenRegularSymlinkPolicy(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := ReadRegular(link, false, 10); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("link followed without followSymlink: %v", err)
	}
	if data, err := ReadRegular(link, true, 10); err != nil || string(data) != "x" {
		t.Fatalf("link not followed: %q %v", data, err)
	}
}
