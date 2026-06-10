package packagecheck

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/garagon/aguara/internal/intel"
)

func TestRunner_RunReportsHitsAndEcosystemSummary(t *testing.T) {
	// Build a matcher that knows about example.com/malicious-mod
	// v1.2.3 in the Go ecosystem. The compromised fixture's go.sum
	// declares that exact (module, version) so the runner must
	// emit one Hit + a per-target EcosystemResult with
	// FindingsCount == 1.
	snap := intel.Snapshot{
		SchemaVersion: intel.CurrentSchemaVersion,
		GeneratedAt:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Records: []intel.Record{{
			ID:        "MAL-TEST-Go-1",
			Ecosystem: intel.EcosystemGo,
			Name:      "example.com/malicious-mod",
			Kind:      intel.KindMalicious,
			Versions:  []string{"v1.2.3"},
		}},
	}
	matcher := intel.NewMatcher(snap)
	runner := &Runner{Matcher: matcher}

	targets, err := Discover(filepath.Join("testdata", "go-compromised"), []string{intel.EcosystemGo})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	res, err := runner.Run(targets)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if got, want := len(res.Ecosystems), 1; got != want {
		t.Fatalf("ecosystems = %d, want %d", got, want)
	}
	er := res.Ecosystems[0]
	if er.Ecosystem != intel.EcosystemGo {
		t.Errorf("ecosystem = %q, want Go", er.Ecosystem)
	}
	if er.Source != "go.sum" {
		t.Errorf("source = %q, want go.sum", er.Source)
	}
	if er.PackagesRead != 2 {
		t.Errorf("packages_read = %d, want 2 (testify + malicious-mod)", er.PackagesRead)
	}
	if er.FindingsCount != 1 {
		t.Errorf("findings_count = %d, want 1", er.FindingsCount)
	}
	if len(res.Hits) != 1 {
		t.Fatalf("hits = %d, want 1 (hits=%+v)", len(res.Hits), res.Hits)
	}
	if res.Hits[0].Ref.Name != "example.com/malicious-mod" {
		t.Errorf("hit ref name = %q, want example.com/malicious-mod", res.Hits[0].Ref.Name)
	}
	if res.Hits[0].Record.ID != "MAL-TEST-Go-1" {
		t.Errorf("hit record ID = %q, want MAL-TEST-Go-1", res.Hits[0].Record.ID)
	}
}

func TestRunner_ResolvesNpmAliasToRealCompromisedPackage(t *testing.T) {
	// The fixture installs node-ipc@9.2.3 under the local alias
	// "safe-ipc". The matcher knows only the REAL package node-ipc@9.2.3.
	// The runner must still report a hit, proving the alias was resolved
	// to the real registry package rather than the innocent local name.
	snap := intel.Snapshot{
		SchemaVersion: intel.CurrentSchemaVersion,
		GeneratedAt:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Records: []intel.Record{{
			ID:        "MAL-TEST-NPM-node-ipc",
			Ecosystem: intel.EcosystemNPM,
			Name:      "node-ipc",
			Kind:      intel.KindMalicious,
			Versions:  []string{"9.2.3"},
		}},
	}
	runner := &Runner{Matcher: intel.NewMatcher(snap)}

	targets, err := Discover(filepath.Join("testdata", "pnpm-alias-compromised"), []string{intel.EcosystemNPM})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	res, err := runner.Run(targets)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(res.Hits) != 1 {
		t.Fatalf("hits = %d, want 1 (hits=%+v)", len(res.Hits), res.Hits)
	}
	if got := res.Hits[0].Ref.Name; got != "node-ipc" {
		t.Errorf("hit ref name = %q, want node-ipc (the alias must NOT leak as safe-ipc)", got)
	}
	if got := res.Hits[0].Ref.Version; got != "9.2.3" {
		t.Errorf("hit ref version = %q, want 9.2.3", got)
	}
	if got := res.Hits[0].Ref.Source; got != "pnpm-lock.yaml" {
		t.Errorf("hit ref source = %q, want pnpm-lock.yaml", got)
	}
	if er := res.Ecosystems[0]; er.PackagesRead != 2 {
		t.Errorf("packages_read = %d, want 2 (node-ipc via alias + lodash)", er.PackagesRead)
	}
}

// TestRunner_BunLockAliasResolvesToReal: a bun.lock alias (safe-ipc ->
// node-ipc@9.2.3) is matched against the real package, not the alias.
func TestRunner_BunLockAliasResolvesToReal(t *testing.T) {
	snap := intel.Snapshot{
		SchemaVersion: intel.CurrentSchemaVersion,
		GeneratedAt:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Records: []intel.Record{{
			ID: "MAL-TEST-NPM-node-ipc", Ecosystem: intel.EcosystemNPM,
			Name: "node-ipc", Kind: intel.KindMalicious, Versions: []string{"9.2.3"},
		}},
	}
	runner := &Runner{Matcher: intel.NewMatcher(snap)}
	targets, err := Discover(filepath.Join("testdata", "bun-alias-compromised"), []string{intel.EcosystemNPM})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	res, err := runner.Run(targets)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Hits) != 1 {
		t.Fatalf("hits = %d, want 1 (hits=%+v)", len(res.Hits), res.Hits)
	}
	if got := res.Hits[0].Ref.Name; got != "node-ipc" {
		t.Errorf("hit ref name = %q, want node-ipc (alias must not leak as safe-ipc)", got)
	}
	if res.Ecosystems[0].Source != "bun.lock" {
		t.Errorf("source = %q, want bun.lock", res.Ecosystems[0].Source)
	}
}

// TestRunner_YarnBerryAliasResolvesToReal: a yarn Berry alias descriptor
// resolves (via resolution:) to the real node-ipc@9.2.3 and matches.
func TestRunner_YarnBerryAliasResolvesToReal(t *testing.T) {
	snap := intel.Snapshot{
		SchemaVersion: intel.CurrentSchemaVersion,
		GeneratedAt:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Records: []intel.Record{{
			ID: "MAL-TEST-NPM-node-ipc", Ecosystem: intel.EcosystemNPM,
			Name: "node-ipc", Kind: intel.KindMalicious, Versions: []string{"9.2.3"},
		}},
	}
	runner := &Runner{Matcher: intel.NewMatcher(snap)}
	targets, err := Discover(filepath.Join("testdata", "yarn-berry-alias-compromised"), []string{intel.EcosystemNPM})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	res, err := runner.Run(targets)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Hits) != 1 {
		t.Fatalf("hits = %d, want 1 (hits=%+v)", len(res.Hits), res.Hits)
	}
	if got := res.Hits[0].Ref.Name; got != "node-ipc" {
		t.Errorf("hit ref name = %q, want node-ipc (Berry alias must resolve to real)", got)
	}
	if res.Ecosystems[0].Source != "yarn.lock" {
		t.Errorf("source = %q, want yarn.lock", res.Ecosystems[0].Source)
	}
}

func TestRunner_CleanProjectReturnsZeroFindings(t *testing.T) {
	// The matcher knows about a malicious package the fixture does
	// NOT carry. Expect zero hits, one EcosystemResult with
	// FindingsCount == 0.
	snap := intel.Snapshot{
		SchemaVersion: intel.CurrentSchemaVersion,
		Records: []intel.Record{{
			ID:        "MAL-Go-NOT-USED",
			Ecosystem: intel.EcosystemGo,
			Name:      "example.com/never-imported",
			Kind:      intel.KindMalicious,
			Versions:  []string{"v0.0.1"},
		}},
	}
	runner := &Runner{Matcher: intel.NewMatcher(snap)}
	targets, _ := Discover(filepath.Join("testdata", "go-clean"), []string{intel.EcosystemGo})
	res, err := runner.Run(targets)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Hits) != 0 {
		t.Errorf("hits = %d, want 0 (hits=%+v)", len(res.Hits), res.Hits)
	}
	if len(res.Ecosystems) != 1 || res.Ecosystems[0].FindingsCount != 0 {
		t.Errorf("expected 1 ecosystem with 0 findings, got %+v", res.Ecosystems)
	}
}

func TestRunner_EmptyTargetsReturnsEmptyResult(t *testing.T) {
	// `aguara check --ecosystem go` on a non-Go repo must not
	// error; it returns clean Ecosystems []. The JSON-shape
	// contract is `"ecosystems": []` not `null`.
	runner := &Runner{Matcher: intel.NewMatcher(intel.Snapshot{})}
	res, err := runner.Run(nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Ecosystems == nil {
		t.Error("Ecosystems is nil; want empty non-nil slice for stable JSON shape")
	}
	if res.Hits == nil {
		t.Error("Hits is nil; want empty non-nil slice")
	}
}

func TestRunner_MonorepoOneEntryPerLockfile(t *testing.T) {
	snap := intel.Snapshot{
		SchemaVersion: intel.CurrentSchemaVersion,
		Records: []intel.Record{{
			ID:        "MAL-MONO",
			Ecosystem: intel.EcosystemGo,
			Name:      "example.com/malicious-mod",
			Kind:      intel.KindMalicious,
			Versions:  []string{"v1.2.3"},
		}},
	}
	runner := &Runner{Matcher: intel.NewMatcher(snap)}
	targets, _ := Discover(filepath.Join("testdata", "go-monorepo"), []string{intel.EcosystemGo})
	res, err := runner.Run(targets)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Ecosystems) != 2 {
		t.Fatalf("ecosystems = %d, want 2 (services/api + workers/scraper)", len(res.Ecosystems))
	}
	// One ecosystem entry should report a hit (services/api with
	// the malicious module); the other should be clean. The flat
	// Hits slice has one entry total.
	if len(res.Hits) != 1 {
		t.Errorf("hits = %d, want 1", len(res.Hits))
	}
	var compromised, clean int
	for _, e := range res.Ecosystems {
		if e.FindingsCount > 0 {
			compromised++
		} else {
			clean++
		}
	}
	if compromised != 1 || clean != 1 {
		t.Errorf("expected exactly one compromised + one clean target, got %+v", res.Ecosystems)
	}
}

func TestRunner_RequiresMatcher(t *testing.T) {
	r := &Runner{}
	_, err := r.Run(nil)
	if err == nil {
		t.Fatal("expected error when Matcher is nil")
	}
}

func TestRunner_MultiEcosystemSyntheticSnapshotHitsEach(t *testing.T) {
	// One synthetic intel record per ecosystem; the multi-eco
	// fixture has one matching package each. The runner must
	// emit three Ecosystems[] entries with FindingsCount=1 each
	// and three Hits total.
	snap := intel.Snapshot{
		SchemaVersion: intel.CurrentSchemaVersion,
		Records: []intel.Record{
			{ID: "MAL-CARGO", Ecosystem: intel.EcosystemCargo, Name: "serde", Kind: intel.KindMalicious, Versions: []string{"1.0.197"}},
			{ID: "MAL-PACKAGIST", Ecosystem: intel.EcosystemPackagist, Name: "symfony/console", Kind: intel.KindMalicious, Versions: []string{"7.0.4"}},
			{ID: "MAL-RUBYGEMS", Ecosystem: intel.EcosystemRubyGems, Name: "rake", Kind: intel.KindMalicious, Versions: []string{"13.2.0"}},
		},
	}
	runner := &Runner{Matcher: intel.NewMatcher(snap)}
	targets, err := Discover(filepath.Join("testdata", "multi-ecosystem"), []string{
		intel.EcosystemCargo, intel.EcosystemPackagist, intel.EcosystemRubyGems,
	})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	res, err := runner.Run(targets)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Ecosystems) != 3 {
		t.Fatalf("ecosystems = %d, want 3", len(res.Ecosystems))
	}
	if len(res.Hits) != 3 {
		t.Fatalf("hits = %d, want 3 (hits=%+v)", len(res.Hits), res.Hits)
	}
	for _, e := range res.Ecosystems {
		if e.FindingsCount != 1 {
			t.Errorf("%s/%s: findings_count = %d, want 1", e.Ecosystem, e.Source, e.FindingsCount)
		}
	}
}

func TestRunner_ComposerVPrefixAliasMatchesBareOSVVersion(t *testing.T) {
	// composer.lock ships "v3.5.0"; the OSV record carries
	// "3.5.0". The runner's versionAliases helper queries both
	// forms so the match still fires. Locking the contract here
	// catches a regression that would drop the alias path.
	snap := intel.Snapshot{
		SchemaVersion: intel.CurrentSchemaVersion,
		Records: []intel.Record{{
			ID:        "MAL-COMPOSER-ALIAS",
			Ecosystem: intel.EcosystemPackagist,
			Name:      "monolog/monolog",
			Kind:      intel.KindMalicious,
			Versions:  []string{"3.5.0"}, // bare form, no "v"
		}},
	}
	runner := &Runner{Matcher: intel.NewMatcher(snap)}
	targets, _ := Discover(filepath.Join("testdata", "composer-compromised"), []string{intel.EcosystemPackagist})
	res, err := runner.Run(targets)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Hits) != 1 {
		t.Fatalf("hits = %d, want 1 (alias path broke; hits=%+v)", len(res.Hits), res.Hits)
	}
	if res.Hits[0].Ref.Version != "v3.5.0" {
		t.Errorf("hit ref version = %q, want v3.5.0 (lockfile raw value preserved)", res.Hits[0].Ref.Version)
	}
}

func TestRunner_ComposerAliasDoesNotDoubleCountFinding(t *testing.T) {
	// If the OSV record carries BOTH "v3.5.0" and "3.5.0" the
	// alias-and-raw query path would naively fire twice. The
	// runner's per-ref dedup keys on advisory ID so we emit
	// exactly one Hit / FindingsCount=1 per (ref, advisory).
	snap := intel.Snapshot{
		SchemaVersion: intel.CurrentSchemaVersion,
		Records: []intel.Record{{
			ID:        "MAL-COMPOSER-DUP",
			Ecosystem: intel.EcosystemPackagist,
			Name:      "monolog/monolog",
			Kind:      intel.KindMalicious,
			Versions:  []string{"v3.5.0", "3.5.0"},
		}},
	}
	runner := &Runner{Matcher: intel.NewMatcher(snap)}
	targets, _ := Discover(filepath.Join("testdata", "composer-compromised"), []string{intel.EcosystemPackagist})
	res, _ := runner.Run(targets)
	if len(res.Hits) != 1 {
		t.Errorf("hits = %d, want 1 (alias dedup broke)", len(res.Hits))
	}
	if res.Ecosystems[0].FindingsCount != 1 {
		t.Errorf("findings_count = %d, want 1", res.Ecosystems[0].FindingsCount)
	}
}

func TestRunnerCollapsesMultipleIntelRecordsPerPackageRef(t *testing.T) {
	// When two snapshots cover the same (ecosystem, name, version)
	// tuple - the typical manual + OSV overlap that lands once OSV
	// catches up to a hand-curated advisory - the runner must emit
	// ONE Hit, not one per advisory. The matcher keeps returning
	// every record for correlation; this is a runner-output-layer
	// collapse that keeps user-facing counts stable across
	// `aguara check` and `aguara check --fresh`.
	//
	// The first snapshot's record wins (manual before OSV), so the
	// surfaced advisory ID stays the curated one.
	manualSnap := intel.Snapshot{
		SchemaVersion: intel.CurrentSchemaVersion,
		Sources:       []intel.SourceMeta{{Kind: intel.SourceManual}},
		Records: []intel.Record{{
			ID:        "SOCKET-2026-05-19-mini-shai-hulud-antv",
			Ecosystem: intel.EcosystemNPM,
			Name:      "@antv/g2",
			Kind:      intel.KindMalicious,
			Versions:  []string{"5.6.8"},
		}},
	}
	osvSnap := intel.Snapshot{
		SchemaVersion: intel.CurrentSchemaVersion,
		Sources:       []intel.SourceMeta{{Kind: intel.SourceOSV}},
		Records: []intel.Record{{
			ID:        "MAL-2026-3973",
			Ecosystem: intel.EcosystemNPM,
			Name:      "@antv/g2",
			Kind:      intel.KindMalicious,
			Versions:  []string{"5.6.8"},
		}},
	}
	runner := &Runner{Matcher: intel.NewMatcher(manualSnap, osvSnap)}
	targets, err := Discover(filepath.Join("testdata", "pnpm-mini-shai-hulud-antv"), []string{intel.EcosystemNPM})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	res, err := runner.Run(targets)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Ecosystems) != 1 {
		t.Fatalf("ecosystems = %d, want 1", len(res.Ecosystems))
	}
	// The fixture lockfile pins @antv/g2 5.6.8 + echarts-for-react 3.2.7
	// + lodash 4.17.21. Only @antv/g2 has both snapshots covering it.
	// echarts-for-react has no synthetic match here, so the total Hit
	// count is exactly 1 even though MatchPackage returns two records
	// per the matcher's correlation contract.
	if got := len(res.Hits); got != 1 {
		t.Fatalf("hits = %d, want 1 (manual+OSV duplicate must collapse to one); got=%+v", got, res.Hits)
	}
	if got := res.Ecosystems[0].FindingsCount; got != 1 {
		t.Errorf("ecosystems[0].findings_count = %d, want 1", got)
	}
	if got := res.Hits[0].Record.ID; got != "SOCKET-2026-05-19-mini-shai-hulud-antv" {
		t.Errorf("manual record must win; got record id %q", got)
	}
}

func TestRunner_MavenSyntheticHit(t *testing.T) {
	snap := intel.Snapshot{
		SchemaVersion: intel.CurrentSchemaVersion,
		Records: []intel.Record{{
			ID:        "MAL-MAVEN",
			Ecosystem: intel.EcosystemMaven,
			Name:      "com.fasterxml.jackson.core:jackson-databind",
			Kind:      intel.KindMalicious,
			Versions:  []string{"2.16.1"},
		}},
	}
	runner := &Runner{Matcher: intel.NewMatcher(snap)}
	targets, _ := Discover(filepath.Join("testdata", "maven-compromised"), []string{intel.EcosystemMaven})
	res, err := runner.Run(targets)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Hits) != 1 {
		t.Fatalf("hits = %d, want 1 (hits=%+v)", len(res.Hits), res.Hits)
	}
	if res.Hits[0].Ref.Name != "com.fasterxml.jackson.core:jackson-databind" {
		t.Errorf("hit ref name = %q, want com.fasterxml.jackson.core:jackson-databind", res.Hits[0].Ref.Name)
	}
	if res.Ecosystems[0].FindingsCount != 1 {
		t.Errorf("findings_count = %d, want 1", res.Ecosystems[0].FindingsCount)
	}
}

func TestRunner_PNPMLockHitsCompromisedNPMRecord(t *testing.T) {
	// pnpm-lock.yaml support routes through the npm ecosystem path
	// (pnpm installs from npm registry). The fixture declares
	// node-ipc@9.2.3, which is in the May 2026 compromised list.
	// Build a synthetic snapshot containing that exact record so
	// the test does not depend on the embedded snapshot's contents.
	snap := intel.Snapshot{
		SchemaVersion: intel.CurrentSchemaVersion,
		GeneratedAt:   time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
		Records: []intel.Record{{
			ID:        "MAL-TEST-NPM-NODE-IPC-9.2.3",
			Ecosystem: intel.EcosystemNPM,
			Name:      "node-ipc",
			Kind:      intel.KindMalicious,
			Versions:  []string{"9.2.3"},
		}},
	}
	runner := &Runner{Matcher: intel.NewMatcher(snap)}

	targets, err := Discover(filepath.Join("testdata", "pnpm-compromised"), []string{intel.EcosystemNPM})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected one pnpm-lock.yaml target, got %d: %+v", len(targets), targets)
	}
	if targets[0].Source != "pnpm-lock.yaml" {
		t.Errorf("source = %q, want pnpm-lock.yaml", targets[0].Source)
	}
	if targets[0].Ecosystem != intel.EcosystemNPM {
		t.Errorf("ecosystem = %q, want npm", targets[0].Ecosystem)
	}

	res, err := runner.Run(targets)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got, want := len(res.Ecosystems), 1; got != want {
		t.Fatalf("ecosystems = %d, want %d", got, want)
	}
	er := res.Ecosystems[0]
	if er.Ecosystem != intel.EcosystemNPM {
		t.Errorf("ecosystem = %q, want npm", er.Ecosystem)
	}
	if er.Source != "pnpm-lock.yaml" {
		t.Errorf("source = %q, want pnpm-lock.yaml", er.Source)
	}
	if er.PackagesRead != 2 {
		t.Errorf("packages_read = %d, want 2 (node-ipc + lodash)", er.PackagesRead)
	}
	if er.FindingsCount != 1 {
		t.Errorf("findings_count = %d, want 1 (node-ipc 9.2.3)", er.FindingsCount)
	}
	if len(res.Hits) != 1 {
		t.Fatalf("hits = %d, want 1", len(res.Hits))
	}
	if res.Hits[0].Ref.Name != "node-ipc" {
		t.Errorf("hit ref name = %q, want node-ipc", res.Hits[0].Ref.Name)
	}
	if res.Hits[0].Ref.Version != "9.2.3" {
		t.Errorf("hit ref version = %q, want 9.2.3", res.Hits[0].Ref.Version)
	}
}

func TestRunner_PNPMCleanFixtureProducesZeroFindings(t *testing.T) {
	// pnpm-clean fixture has lodash + @types/node, neither in any
	// compromised list. The runner must still emit one
	// EcosystemResult so consumers see "pipeline ran, scanned N
	// packages, zero findings" rather than silence.
	snap := intel.Snapshot{
		SchemaVersion: intel.CurrentSchemaVersion,
		GeneratedAt:   time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
	}
	runner := &Runner{Matcher: intel.NewMatcher(snap)}

	targets, err := Discover(filepath.Join("testdata", "pnpm-clean"), []string{intel.EcosystemNPM})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	res, err := runner.Run(targets)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got, want := len(res.Ecosystems), 1; got != want {
		t.Fatalf("ecosystems = %d, want %d", got, want)
	}
	if res.Ecosystems[0].PackagesRead != 2 {
		t.Errorf("packages_read = %d, want 2 (lodash + @types/node)", res.Ecosystems[0].PackagesRead)
	}
	if res.Ecosystems[0].FindingsCount != 0 {
		t.Errorf("findings_count = %d, want 0 (clean fixture)", res.Ecosystems[0].FindingsCount)
	}
	if len(res.Hits) != 0 {
		t.Errorf("hits = %d, want 0 (clean fixture)", len(res.Hits))
	}
}

func TestRunner_NuGetSyntheticHit(t *testing.T) {
	snap := intel.Snapshot{
		SchemaVersion: intel.CurrentSchemaVersion,
		Records: []intel.Record{{
			ID:        "MAL-NUGET",
			Ecosystem: intel.EcosystemNuGet,
			Name:      "newtonsoft.json", // case-folded by intel.normalizeName
			Kind:      intel.KindMalicious,
			Versions:  []string{"13.0.3"},
		}},
	}
	runner := &Runner{Matcher: intel.NewMatcher(snap)}
	targets, _ := Discover(filepath.Join("testdata", "nuget-compromised"), []string{intel.EcosystemNuGet})
	res, err := runner.Run(targets)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Hits) == 0 {
		t.Fatal("expected at least one hit (Newtonsoft.Json 13.0.3 in lockfile + csproj)")
	}
	// Both packages.lock.json and the .csproj declare
	// Newtonsoft.Json 13.0.3; the per-(ref, advisory) dedup is
	// per-target, so each lockfile gets one hit. With two
	// targets that means up to 2 hits — but the lockfile and
	// the csproj produce different PackageRef paths.
	for _, h := range res.Hits {
		if h.Record.ID != "MAL-NUGET" {
			t.Errorf("hit record ID = %q, want MAL-NUGET", h.Record.ID)
		}
	}
}
