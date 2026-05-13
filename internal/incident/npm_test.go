package incident_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/garagon/aguara/internal/incident"
)

func writeNPMPackage(t *testing.T, root, importPath, version string) {
	t.Helper()
	dir := filepath.Join(root, filepath.FromSlash(importPath))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	body := `{"name":` + jsonString(importPath) + `,"version":` + jsonString(version) + `}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(body), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
}

func jsonString(s string) string {
	// Minimal JSON string escaping for the few cases the test writes.
	return `"` + s + `"`
}

func TestIsCompromisedIn_NPMHit(t *testing.T) {
	cp := incident.IsCompromisedIn(incident.EcosystemNPM, "event-stream", "3.3.6")
	if cp == nil {
		t.Fatalf("expected event-stream 3.3.6 to be compromised, got nil")
	}
	if cp.Ecosystem != incident.EcosystemNPM {
		t.Errorf("expected ecosystem npm, got %q", cp.Ecosystem)
	}
}

func TestIsCompromisedIn_NPMMiss(t *testing.T) {
	// event-stream is in the npm list; checking pypi for the same name
	// must return nil, otherwise a Python package sharing a name with
	// an npm incident would falsely chain.
	if cp := incident.IsCompromisedIn(incident.EcosystemPyPI, "event-stream", "3.3.6"); cp != nil {
		t.Errorf("expected ecosystem filter to exclude pypi lookup, got: %+v", cp)
	}
}

func TestIsCompromised_LegacyTwoArg_StillMatchesAcrossEcosystems(t *testing.T) {
	// The legacy IsCompromised(name, version) signature must continue
	// to match npm entries; existing callers (the Python checker)
	// only ever inspected PyPI packages so the cross-ecosystem match
	// is benign there.
	if cp := incident.IsCompromised("event-stream", "3.3.6"); cp == nil {
		t.Errorf("legacy IsCompromised should still find npm event-stream 3.3.6")
	}
}

func TestCheckNPM_RequiresPath(t *testing.T) {
	if _, err := incident.CheckNPM(incident.CheckOptions{}); err == nil {
		t.Errorf("expected error when path is empty")
	}
}

func TestCheckNPM_DetectsCompromisedPackage(t *testing.T) {
	dir := t.TempDir()
	nm := filepath.Join(dir, "node_modules")
	writeNPMPackage(t, nm, "event-stream", "3.3.6")
	writeNPMPackage(t, nm, "express", "4.18.2")

	result, err := incident.CheckNPM(incident.CheckOptions{Path: nm})
	if err != nil {
		t.Fatalf("CheckNPM returned error: %v", err)
	}
	if result.PackagesRead != 2 {
		t.Errorf("expected 2 packages read, got %d", result.PackagesRead)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(result.Findings), result.Findings)
	}
	if result.Findings[0].Severity != incident.SevCritical {
		t.Errorf("expected CRITICAL severity, got %q", result.Findings[0].Severity)
	}
}

func TestCheckNPM_ScopedPackages(t *testing.T) {
	dir := t.TempDir()
	nm := filepath.Join(dir, "node_modules")
	writeNPMPackage(t, nm, "@scope/legit", "1.0.0")
	writeNPMPackage(t, nm, "ua-parser-js", "0.7.29")

	result, err := incident.CheckNPM(incident.CheckOptions{Path: nm})
	if err != nil {
		t.Fatalf("CheckNPM returned error: %v", err)
	}
	if result.PackagesRead != 2 {
		t.Errorf("expected 2 packages read, got %d", result.PackagesRead)
	}
	if len(result.Findings) != 1 || result.Findings[0].Path == "" {
		t.Fatalf("expected one ua-parser-js finding with a path, got: %+v", result.Findings)
	}
}

func TestCheckNPM_NestedNodeModules(t *testing.T) {
	// A nested copy at node_modules/foo/node_modules/event-stream
	// must still be detected (npm legitimately ships nested deps
	// when a dep's version constraint cannot be hoisted).
	dir := t.TempDir()
	nm := filepath.Join(dir, "node_modules")
	writeNPMPackage(t, nm, "foo", "1.0.0")
	writeNPMPackage(t, filepath.Join(nm, "foo", "node_modules"), "event-stream", "3.3.6")

	result, err := incident.CheckNPM(incident.CheckOptions{Path: nm})
	if err != nil {
		t.Fatalf("CheckNPM returned error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding for nested compromised dep, got %d: %+v", len(result.Findings), result.Findings)
	}
}

func TestCheckNPM_CleanTree(t *testing.T) {
	dir := t.TempDir()
	nm := filepath.Join(dir, "node_modules")
	writeNPMPackage(t, nm, "react", "18.3.1")
	writeNPMPackage(t, nm, "@scope/utils", "2.1.0")

	result, err := incident.CheckNPM(incident.CheckOptions{Path: nm})
	if err != nil {
		t.Fatalf("CheckNPM returned error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("clean tree must produce no findings, got: %+v", result.Findings)
	}
}

func TestCheckNPM_NonExistentPath(t *testing.T) {
	if _, err := incident.CheckNPM(incident.CheckOptions{Path: "/nonexistent/path"}); err == nil {
		t.Errorf("expected error for nonexistent path")
	}
}
