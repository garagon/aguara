package incident_test

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/garagon/aguara/internal/incident"
	"github.com/garagon/aguara/internal/intel"
)

// Package findings name their class and the package they are about, so
// reports can identify them without parsing titles.
func TestPackageFindingsCarryKindAndIdentity(t *testing.T) {
	dir := t.TempDir()
	nm := filepath.Join(dir, "node_modules")
	writeNPMPackage(t, nm, "event-stream", "3.3.6")

	result, err := incident.CheckNPM(incident.CheckOptions{Path: nm})
	if err != nil {
		t.Fatalf("CheckNPM: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %+v", result.Findings)
	}
	f := result.Findings[0]
	if f.Kind != incident.KindCompromisedPackage || f.Ecosystem != intel.EcosystemNPM ||
		f.Package != "event-stream" || f.Version != "3.3.6" {
		t.Fatalf("identity = %q %q %q %q", f.Kind, f.Ecosystem, f.Package, f.Version)
	}
	if len(f.AdvisoryIDs) == 0 || !strings.Contains(f.Title, f.AdvisoryIDs[0]) {
		t.Fatalf("advisory_ids %v must include the advisory the title names (%s)", f.AdvisoryIDs, f.Title)
	}

	data, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"kind":"compromised_package"`, `"ecosystem":"npm"`, `"package":"event-stream"`, `"version":"3.3.6"`} {
		if !strings.Contains(string(data), key) {
			t.Errorf("JSON lacks %s: %s", key, data)
		}
	}

	// Findings that are not about one package omit the identity fields.
	data, err = json.Marshal(incident.Finding{Severity: incident.SevWarning, Kind: incident.KindPersistenceArtifact, Title: "x"})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"ecosystem"`, `"package"`, `"version"`} {
		if strings.Contains(string(data), key) {
			t.Errorf("JSON has %s for a non-package finding: %s", key, data)
		}
	}
}
