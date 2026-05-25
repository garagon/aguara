package incident_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/garagon/aguara/internal/incident"
	"github.com/garagon/aguara/internal/intel"
	"github.com/garagon/aguara/internal/packagecheck"
)

// trapdoorPnpmLock returns a minimal pnpm-lock.yaml (v9 shape)
// declaring a single name@version, mirroring the structure pnpm
// writes. Kept inline rather than a committed fixture to match the
// incident package's temp-dir test convention.
func trapdoorPnpmLock(name, version string) string {
	return "lockfileVersion: '9.0'\n\n" +
		"importers:\n" +
		"  .:\n" +
		"    dependencies:\n" +
		"      " + name + ":\n" +
		"        specifier: " + version + "\n" +
		"        version: " + version + "\n\n" +
		"packages:\n" +
		"  " + name + "@" + version + ":\n" +
		"    resolution: {integrity: sha512-FAKE_FIXTURE_DO_NOT_VERIFY==}\n\n" +
		"snapshots:\n" +
		"  " + name + "@" + version + ": {}\n"
}

// TestTrapDoor_PnpmLockfileDetectedViaEmbeddedIntel exercises the
// third exposure surface: a TrapDoor npm package declared in a
// pnpm-lock.yaml. It builds the matcher from the REAL embedded
// snapshots, so the manual SOCKET entry is matched end to end through
// the actual pnpm parser and packagecheck runner.
func TestTrapDoor_PnpmLockfileDetectedViaEmbeddedIntel(t *testing.T) {
	dir := t.TempDir()
	lock := trapdoorPnpmLock("dev-env-bootstrapper", "1.0.12")
	if err := os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), []byte(lock), 0o644); err != nil {
		t.Fatalf("write pnpm-lock.yaml: %v", err)
	}

	matcher := intel.NewMatcher(incident.EmbeddedSnapshots()...)
	targets, err := packagecheck.Discover(dir, []string{intel.EcosystemNPM})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	runner := &packagecheck.Runner{Matcher: matcher}
	res, err := runner.Run(targets)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(res.Hits) != 1 {
		t.Fatalf("expected 1 pnpm hit, got %d: %+v", len(res.Hits), res.Hits)
	}
	if res.Hits[0].Ref.Name != "dev-env-bootstrapper" {
		t.Errorf("hit name = %q, want dev-env-bootstrapper", res.Hits[0].Ref.Name)
	}
	if res.Hits[0].Record.ID != "SOCKET-2026-05-24-trapdoor" {
		t.Errorf("hit advisory = %q, want SOCKET-2026-05-24-trapdoor", res.Hits[0].Record.ID)
	}
	if len(res.Ecosystems) != 1 || res.Ecosystems[0].Source != "pnpm-lock.yaml" {
		t.Errorf("ecosystem summary = %+v, want one pnpm-lock.yaml entry", res.Ecosystems)
	}
}

// TestTrapDoor_PnpmRangeOnlyPackageNotListed confirms the scope cut
// holds through the pnpm path too: a campaign package OSV carries
// range-only (not added to manual intel) must not hit, even though
// it appears in the lockfile.
func TestTrapDoor_PnpmRangeOnlyPackageNotListed(t *testing.T) {
	dir := t.TempDir()
	lock := trapdoorPnpmLock("async-pipeline-builder", "1.0.12")
	if err := os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), []byte(lock), 0o644); err != nil {
		t.Fatalf("write pnpm-lock.yaml: %v", err)
	}

	matcher := intel.NewMatcher(incident.EmbeddedSnapshots()...)
	targets, err := packagecheck.Discover(dir, []string{intel.EcosystemNPM})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	res, err := (&packagecheck.Runner{Matcher: matcher}).Run(targets)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Hits) != 0 {
		t.Fatalf("range-only campaign package must not be in manual intel, got hits: %+v", res.Hits)
	}
}
