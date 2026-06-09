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

// TestTrapDoor_PnpmWholePackageRangeFlagged confirms the range-only
// TrapDoor entry is caught through the pnpm path too: a whole-package
// (introduced:0) campaign package in a lockfile flags at any version
// via the real embedded snapshot + the range-capable matcher.
func TestTrapDoor_PnpmWholePackageRangeFlagged(t *testing.T) {
	dir := t.TempDir()
	lock := trapdoorPnpmLock("async-pipeline-builder", "2.5.0") // any version matches introduced:0
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
	if len(res.Hits) != 1 {
		t.Fatalf("expected 1 pnpm hit for the whole-package range, got %d: %+v", len(res.Hits), res.Hits)
	}
	if res.Hits[0].Record.ID != "SOCKET-2026-05-24-trapdoor" {
		t.Errorf("hit advisory = %q, want SOCKET-2026-05-24-trapdoor", res.Hits[0].Record.ID)
	}
}

// TestTrapDoor_PnpmNpmAliasResolvedViaEmbeddedIntel proves the npm:
// alias path end to end against the REAL embedded snapshots: the
// compromised TrapDoor package is installed under an innocent local
// alias ("safe-bootstrap"), but the lockfile key encodes the real
// registry target, so the parser resolves it to dev-env-bootstrapper
// and the advisory still fires. Without alias resolution this scans
// clean -- the exact false negative PR2 closes.
func TestTrapDoor_PnpmNpmAliasResolvedViaEmbeddedIntel(t *testing.T) {
	dir := t.TempDir()
	lock := "lockfileVersion: '9.0'\n\n" +
		"importers:\n" +
		"  .:\n" +
		"    dependencies:\n" +
		"      safe-bootstrap:\n" +
		"        specifier: npm:dev-env-bootstrapper@1.0.12\n" +
		"        version: dev-env-bootstrapper@1.0.12\n\n" +
		"packages:\n" +
		"  safe-bootstrap@npm:dev-env-bootstrapper@1.0.12:\n" +
		"    resolution: {integrity: sha512-FAKE_FIXTURE_DO_NOT_VERIFY==}\n\n" +
		"snapshots:\n" +
		"  safe-bootstrap@npm:dev-env-bootstrapper@1.0.12: {}\n"
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
	if len(res.Hits) != 1 {
		t.Fatalf("expected 1 pnpm hit via alias, got %d: %+v", len(res.Hits), res.Hits)
	}
	if res.Hits[0].Ref.Name != "dev-env-bootstrapper" {
		t.Errorf("hit name = %q, want dev-env-bootstrapper (alias must not leak as safe-bootstrap)", res.Hits[0].Ref.Name)
	}
	if res.Hits[0].Record.ID != "SOCKET-2026-05-24-trapdoor" {
		t.Errorf("hit advisory = %q, want SOCKET-2026-05-24-trapdoor", res.Hits[0].Record.ID)
	}
	if len(res.Ecosystems) != 1 || res.Ecosystems[0].Source != "pnpm-lock.yaml" {
		t.Errorf("ecosystem summary = %+v, want one pnpm-lock.yaml entry", res.Ecosystems)
	}
}
