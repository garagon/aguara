//go:build unix

package incident_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/garagon/aguara/internal/incident"
)

// An installed package.json that is a named pipe, or a package directory
// that cannot be listed, used to be left out without a word, so check
// reported a clean tree it had not read. Each is now a WARNING finding.
func TestCheckNPM_ReportsUnreadManifests(t *testing.T) {
	nm := filepath.Join(t.TempDir(), "node_modules")
	writeNPMPackage(t, nm, "left-pad", "1.3.0")
	if err := os.MkdirAll(filepath.Join(nm, "pipe"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(nm, "pipe", "package.json"), 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	result, err := incident.CheckNPM(incident.CheckOptions{Path: nm})
	if err != nil {
		t.Fatal(err)
	}
	if result.PackagesRead != 1 {
		t.Fatalf("packages read: %d", result.PackagesRead)
	}
	if len(result.Findings) != 1 || result.Findings[0].Severity != incident.SevWarning ||
		!strings.Contains(result.Findings[0].Title, "named pipe") || result.Findings[0].Path != filepath.Join(nm, "pipe") {
		t.Fatalf("unread manifest not reported: %+v", result.Findings)
	}

	locked := filepath.Join(nm, "locked")
	writeNPMPackage(t, nm, "locked", "1.0.0")
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
	if _, err := os.ReadDir(locked); err == nil {
		return // permissions not enforced (running as root)
	}
	result, err = incident.CheckNPM(incident.CheckOptions{Path: nm})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range result.Findings {
		if f.Path == locked && f.Severity == incident.SevWarning && strings.Contains(f.Title, "could not be listed") {
			found = true
		}
	}
	if !found {
		t.Fatalf("unlistable package directory not reported: %+v", result.Findings)
	}
}
