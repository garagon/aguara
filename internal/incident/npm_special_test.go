package incident_test

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/garagon/aguara/internal/incident"
)

// Padding an installed package.json past the read limit must not hide the
// package: the check fails instead of leaving it out.
func TestCheckNPM_OversizedManifestFails(t *testing.T) {
	nm := filepath.Join(t.TempDir(), "node_modules")
	writeNPMPackage(t, nm, "event-stream", "3.3.6")
	f, err := os.OpenFile(filepath.Join(nm, "event-stream", "package.json"), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Sparse padding after the JSON object: still one valid document to a
	// lenient reader, but over the 50 MiB manifest limit.
	truncErr := f.Truncate(50<<20 + 1)
	closeErr := f.Close()
	if truncErr != nil || closeErr != nil {
		t.Fatal(truncErr, closeErr)
	}
	_, err = incident.CheckNPM(incident.CheckOptions{Path: nm})
	if err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("oversized manifest accepted: %v", err)
	}
}

// Padding with millions of keys under the size limit fails the same way.
func TestCheckNPM_ManifestOverStructureBudgetFails(t *testing.T) {
	nm := filepath.Join(t.TempDir(), "node_modules")
	writeNPMPackage(t, nm, "event-stream", "3.3.6")
	var b strings.Builder
	b.WriteString(`{"name":"event-stream","version":"3.3.6"`)
	for i := range 2_000_001 {
		b.WriteString(`,"`)
		b.WriteString(strconv.Itoa(i))
		b.WriteString(`":0`)
	}
	b.WriteString("}")
	if err := os.WriteFile(filepath.Join(nm, "event-stream", "package.json"), []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := incident.CheckNPM(incident.CheckOptions{Path: nm})
	// Rejected by the structure budget: the node or the member limit.
	if err == nil || (!strings.Contains(err.Error(), "node limit") && !strings.Contains(err.Error(), "members")) {
		t.Fatalf("padded manifest accepted: %v", err)
	}
}
