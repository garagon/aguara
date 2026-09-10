package baseline

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBaselineRejectsSymlinkOutput(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "untouched")
	if err := os.WriteFile(outside, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.Symlink(outside, path); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	_, _, err := Write(path, nil, "test")
	data, readErr := os.ReadFile(outside)
	if readErr != nil || string(data) != "original" || err == nil {
		t.Fatalf("linked output: target=%q read=%v write=%v", data, readErr, err)
	}
}
