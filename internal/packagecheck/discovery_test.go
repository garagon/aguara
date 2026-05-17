package packagecheck

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/garagon/aguara/internal/intel"
)

func TestDiscover_MonorepoFindsBothGoTargets(t *testing.T) {
	root := filepath.Join("testdata", "go-monorepo")
	targets, err := Discover(root, []string{intel.EcosystemGo})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	// Sort for stability across walk-order differences across
	// platforms. WalkDir is documented to be lexical but we lock
	// the assertion shape via explicit sort.
	sort.Slice(targets, func(i, j int) bool { return targets[i].Path < targets[j].Path })

	if got, want := len(targets), 2; got != want {
		t.Fatalf("targets = %d, want %d (targets=%+v)", got, want, targets)
	}
	for _, target := range targets {
		if target.Source != "go.sum" {
			t.Errorf("target %s: source = %q, want go.sum", target.Path, target.Source)
		}
		if target.Ecosystem != intel.EcosystemGo {
			t.Errorf("target %s: ecosystem = %q, want Go", target.Path, target.Ecosystem)
		}
	}
	// Both expected paths must show up; the vendor/ and
	// node_modules/ go.sum entries must NOT.
	gotPaths := map[string]bool{}
	for _, t := range targets {
		gotPaths[t.Path] = true
	}
	for _, want := range []string{
		filepath.Join(root, "services", "api", "go.sum"),
		filepath.Join(root, "workers", "scraper", "go.sum"),
	} {
		if !gotPaths[want] {
			t.Errorf("missing expected target %q (got %v)", want, gotPaths)
		}
	}
	for _, skipped := range []string{
		filepath.Join(root, "vendor", "notmine", "go.sum"),
		filepath.Join(root, "node_modules", "notmine", "go.sum"),
	} {
		if gotPaths[skipped] {
			t.Errorf("Discover walked into a skipped directory: %q", skipped)
		}
	}
}

func TestDiscover_PrefersGoSumOverGoMod(t *testing.T) {
	tmp := t.TempDir()
	writeFile(t, filepath.Join(tmp, "go.sum"), "example.com/mod v1.0.0 h1:hash=\n")
	writeFile(t, filepath.Join(tmp, "go.mod"), "module example.com/x\n\nrequire example.com/mod v1.0.0\n")

	targets, err := Discover(tmp, []string{intel.EcosystemGo})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(targets) != 1 || targets[0].Source != "go.sum" {
		t.Errorf("targets = %+v, want one go.sum target", targets)
	}
}

func TestDiscover_FallsBackToGoModWhenNoGoSum(t *testing.T) {
	root := filepath.Join("testdata", "go-mod-only")
	targets, err := Discover(root, []string{intel.EcosystemGo})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(targets) != 1 || targets[0].Source != "go.mod" {
		t.Errorf("targets = %+v, want one go.mod target", targets)
	}
}

func TestDiscover_NoGoFilesReturnsEmpty(t *testing.T) {
	tmp := t.TempDir()
	writeFile(t, filepath.Join(tmp, "README.md"), "# nothing\n")

	targets, err := Discover(tmp, []string{intel.EcosystemGo})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(targets) != 0 {
		t.Errorf("targets = %+v, want empty", targets)
	}
}

func TestDiscover_DefaultsToAllSupportedWhenEcosystemsNil(t *testing.T) {
	// PR #2: nil means "scan every ecosystem packagecheck knows
	// about". Today that's Go only; future PRs flow additively
	// without callers having to update their slice.
	root := filepath.Join("testdata", "go-clean")
	targets, err := Discover(root, nil)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(targets) != 1 || targets[0].Ecosystem != intel.EcosystemGo {
		t.Errorf("targets = %+v, want one Go target", targets)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestDiscover_MultiEcosystemMonorepo(t *testing.T) {
	// Each services/* subdir carries a different lockfile. Discovery
	// asked for all three ecosystems should emit one Target per
	// (subdir, ecosystem) pair, and skip the vendor/ + node_modules/
	// children that exist only to verify the skip rules still hold.
	root := filepath.Join("testdata", "multi-ecosystem")
	targets, err := Discover(root, []string{
		intel.EcosystemCargo,
		intel.EcosystemPackagist,
		intel.EcosystemRubyGems,
	})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].Path < targets[j].Path })

	if got, want := len(targets), 3; got != want {
		t.Fatalf("targets = %d, want %d (targets=%+v)", got, want, targets)
	}
	wantByEco := map[string]string{
		intel.EcosystemCargo:     filepath.Join(root, "services", "cargo-svc", "Cargo.lock"),
		intel.EcosystemPackagist: filepath.Join(root, "services", "composer-svc", "composer.lock"),
		intel.EcosystemRubyGems:  filepath.Join(root, "services", "ruby-svc", "Gemfile.lock"),
	}
	got := map[string]string{}
	for _, target := range targets {
		got[target.Ecosystem] = target.Path
	}
	for eco, wantPath := range wantByEco {
		if got[eco] != wantPath {
			t.Errorf("ecosystem %s: got %q, want %q", eco, got[eco], wantPath)
		}
	}
	// vendor/ and node_modules/ contain lockfiles solely to
	// exercise the skip rules; they must not appear in targets.
	for _, target := range targets {
		if strings.Contains(target.Path, "/vendor/") || strings.Contains(target.Path, "/node_modules/") {
			t.Errorf("Discover walked a skipped directory: %q", target.Path)
		}
	}
}

func TestDiscover_DefaultNilCoversAllPackagecheckEcosystems(t *testing.T) {
	// PR #3 widens the default scan from Go-only to every
	// ecosystem packagecheck knows. Caller passing nil must see
	// all four lockfile types in the multi-ecosystem fixture.
	root := filepath.Join("testdata", "multi-ecosystem")
	targets, err := Discover(root, nil)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	seen := map[string]bool{}
	for _, target := range targets {
		seen[target.Ecosystem] = true
	}
	for _, eco := range []string{intel.EcosystemCargo, intel.EcosystemPackagist, intel.EcosystemRubyGems} {
		if !seen[eco] {
			t.Errorf("default Discover missed ecosystem %s (targets=%+v)", eco, targets)
		}
	}
}

func TestDiscover_MavenAndNuGetMonorepoSkipsBuildDirs(t *testing.T) {
	// Monorepo fixture has:
	//   api/pom.xml             (Maven)
	//   web/Web.csproj          (NuGet)
	//   vendor/should-skip.csproj   (skipped: vendor/)
	//   target/skip/pom.xml         (skipped: target/)
	//   .gradle/skip/gradle.lockfile (skipped: .gradle/)
	//   web/bin/Skip.csproj         (skipped: bin/)
	//   web/obj/Skip.csproj         (skipped: obj/)
	root := filepath.Join("testdata", "multi-mvn-nuget")
	targets, err := Discover(root, []string{intel.EcosystemMaven, intel.EcosystemNuGet})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if got, want := len(targets), 2; got != want {
		t.Fatalf("targets = %d, want %d (targets=%+v)", got, want, targets)
	}
	var sawMaven, sawNuGet bool
	for _, target := range targets {
		switch target.Ecosystem {
		case intel.EcosystemMaven:
			sawMaven = true
			if target.Source != "pom.xml" {
				t.Errorf("Maven source = %q, want pom.xml", target.Source)
			}
			if !strings.Contains(target.Path, "/api/") {
				t.Errorf("Maven path %q not under api/", target.Path)
			}
		case intel.EcosystemNuGet:
			sawNuGet = true
			if target.Source != "csproj" {
				t.Errorf("NuGet source = %q, want csproj", target.Source)
			}
		}
	}
	if !sawMaven || !sawNuGet {
		t.Errorf("expected both Maven + NuGet targets, got %+v", targets)
	}
	for _, target := range targets {
		for _, skipDir := range []string{"/vendor/", "/target/", "/.gradle/", "/bin/", "/obj/"} {
			if strings.Contains(target.Path, skipDir) {
				t.Errorf("Discover walked into %s: %q", skipDir, target.Path)
			}
		}
	}
}

func TestDiscover_GradleDependencyLocksDirectoryEmitsPerFileTarget(t *testing.T) {
	// gradle/dependency-locks/*.lockfile must emit one Target
	// per file, NOT one per directory. The maven-gradle fixture
	// has compileClasspath.lockfile + runtimeClasspath.lockfile
	// under gradle/dependency-locks/ AND a root-level
	// gradle.lockfile, so total = 3 Maven targets in the
	// directory tree.
	root := filepath.Join("testdata", "maven-gradle")
	targets, err := Discover(root, []string{intel.EcosystemMaven})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(targets) != 3 {
		t.Fatalf("targets = %d, want 3 (gradle.lockfile + 2 dependency-locks files); got %+v", len(targets), targets)
	}
	for _, target := range targets {
		if target.Ecosystem != intel.EcosystemMaven {
			t.Errorf("ecosystem = %q, want Maven", target.Ecosystem)
		}
		if target.Source != "gradle.lockfile" {
			t.Errorf("source = %q, want gradle.lockfile", target.Source)
		}
	}
}

func TestDiscover_NuGetMultipleProjectFilesPerDirectory(t *testing.T) {
	// A directory with both a packages.lock.json AND a .csproj
	// emits both targets (different parser source-of-truth: the
	// lockfile carries resolved versions, the .csproj carries
	// the declared version that may differ).
	root := filepath.Join("testdata", "nuget-compromised")
	targets, err := Discover(root, []string{intel.EcosystemNuGet})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("targets = %d, want 2 (packages.lock.json + MyApp.csproj); got %+v", len(targets), targets)
	}
	sources := map[string]bool{}
	for _, target := range targets {
		sources[target.Source] = true
	}
	for _, want := range []string{"packages.lock.json", "csproj"} {
		if !sources[want] {
			t.Errorf("missing source %q in %+v", want, sources)
		}
	}
}
