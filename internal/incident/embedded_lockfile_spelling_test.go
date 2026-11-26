package incident

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/garagon/aguara/internal/intel"
	"github.com/garagon/aguara/internal/packagecheck"
)

// These tests take every live exact-version record of the embedded
// snapshots, write the affected versions into a lockfile spelled the way
// that ecosystem's own tooling writes it, and require the check to report
// each one. They guard the class of bug where the intelligence spells a
// version one way (OSV Go records use "0.69.4") and lockfiles another
// (go.sum writes "v0.69.4"): a future intel refresh that changes how a
// source spells versions fails here instead of silently matching nothing.

// exactTuple is one (name, version) an advisory lists exactly.
type exactTuple struct {
	name, version, id string
}

// liveExactTuples returns the exact-version tuples the default matcher
// can match for one ecosystem: records that are not withdrawn and whose
// advisory ID is not retracted by a tombstone in any embedded snapshot,
// sorted for a deterministic lockfile.
func liveExactTuples(t *testing.T, ecosystem string) []exactTuple {
	t.Helper()
	snaps := EmbeddedSnapshots()
	dead := map[string]bool{}
	for _, s := range snaps {
		for _, r := range s.Records {
			if r.Withdrawn {
				dead[r.Ecosystem+"\x00"+r.Name+"\x00"+r.ID] = true
			}
		}
	}
	seen := map[string]bool{}
	var out []exactTuple
	for _, s := range snaps {
		for _, r := range s.Records {
			if r.Withdrawn || r.Ecosystem != ecosystem || dead[r.Ecosystem+"\x00"+r.Name+"\x00"+r.ID] {
				continue
			}
			for _, v := range r.Versions {
				key := r.Name + "\x00" + v
				if v == "" || seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, exactTuple{name: r.Name, version: v, id: r.ID})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].name != out[j].name {
			return out[i].name < out[j].name
		}
		return out[i].version < out[j].version
	})
	return out
}

// runSpelling writes content as one lockfile, runs the package check over
// it and returns the hits keyed by "name\x00version" as the lockfile
// spelled them.
func runSpelling(t *testing.T, ecosystem, source, content string) map[string]bool {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, source)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &packagecheck.Runner{Matcher: defaultIntelMatcher()}
	res, err := runner.Run([]packagecheck.Target{{Ecosystem: ecosystem, Path: path, Source: source, Root: dir}})
	if err != nil {
		t.Fatalf("%s: %v", source, err)
	}
	hits := map[string]bool{}
	for _, h := range res.Hits {
		hits[h.Ref.Name+"\x00"+h.Ref.Version] = true
	}
	return hits
}

// requireAllReported fails for every tuple whose lockfile spelling was
// not reported, naming a few of them.
func requireAllReported(t *testing.T, label string, tuples []exactTuple, spelled func(exactTuple) (name, version string), hits map[string]bool) {
	t.Helper()
	var missed []string
	for _, tp := range tuples {
		name, version := spelled(tp)
		if !hits[name+"\x00"+version] {
			missed = append(missed, fmt.Sprintf("%s %s (%s)", name, version, tp.id))
		}
	}
	t.Logf("%s: %d of %d exact-version entries reported", label, len(tuples)-len(missed), len(tuples))
	if len(missed) > 0 {
		if len(missed) > 10 {
			missed = append(missed[:10], fmt.Sprintf("and %d more", len(missed)-10))
		}
		t.Errorf("%s: %d exact-version entries spelled as the lockfile writes them were not reported: %s",
			label, len(missed), strings.Join(missed, "; "))
	}
}

func identitySpelling(tp exactTuple) (string, string) { return tp.name, tp.version }

// goSumVersion spells an advisory version the way go.sum and go.mod write
// it: a leading "v", and "+incompatible" for a major version of 2 or more
// published from a module path without the matching /vN suffix (Go
// Modules Reference, "Compatibility with non-module repositories").
func goSumVersion(module, version string) string {
	v := version
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	if strings.HasSuffix(v, "+incompatible") {
		return v
	}
	major, err := strconv.Atoi(strings.SplitN(strings.TrimPrefix(v, "v"), ".", 2)[0])
	if err != nil || major < 2 || strings.HasPrefix(module, "gopkg.in/") {
		return v
	}
	if strings.HasSuffix(module, "/v"+strconv.Itoa(major)) {
		return v
	}
	return v + "+incompatible"
}

func TestEmbeddedGoRecordsMatchGoSumSpelling(t *testing.T) {
	tuples := liveExactTuples(t, intel.EcosystemGo)
	if len(tuples) == 0 {
		t.Skip("the embedded snapshot has no live exact-version Go records")
	}
	var sum, mod strings.Builder
	mod.WriteString("module example.com/fixture\n\ngo 1.22\n\nrequire (\n")
	for _, tp := range tuples {
		v := goSumVersion(tp.name, tp.version)
		fmt.Fprintf(&sum, "%s %s h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n", tp.name, v)
		fmt.Fprintf(&sum, "%s %s/go.mod h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n", tp.name, v)
		fmt.Fprintf(&mod, "\t%s %s\n", tp.name, v)
	}
	mod.WriteString(")\n")
	spelled := func(tp exactTuple) (string, string) { return tp.name, goSumVersion(tp.name, tp.version) }
	requireAllReported(t, "Go go.sum", tuples, spelled, runSpelling(t, intel.EcosystemGo, "go.sum", sum.String()))
	requireAllReported(t, "Go go.mod", tuples, spelled, runSpelling(t, intel.EcosystemGo, "go.mod", mod.String()))
}

func TestEmbeddedNPMRecordsMatchLockfileSpelling(t *testing.T) {
	tuples := liveExactTuples(t, intel.EcosystemNPM)
	if len(tuples) == 0 {
		t.Fatal("the embedded snapshot has no live exact-version npm records")
	}
	// package-lock.json v3: every entry gets its own install path so two
	// versions of one package can coexist, as npm nests them.
	packages := map[string]any{"": map[string]string{"name": "fixture"}}
	for i, tp := range tuples {
		packages[fmt.Sprintf("node_modules/h%d/node_modules/%s", i, tp.name)] = map[string]string{"version": tp.version}
	}
	lock, err := json.Marshal(map[string]any{"lockfileVersion": 3, "packages": packages})
	if err != nil {
		t.Fatal(err)
	}
	requireAllReported(t, "npm package-lock.json", tuples, identitySpelling,
		runSpelling(t, intel.EcosystemNPM, "package-lock.json", string(lock)))

	// pnpm-lock.yaml v9, yarn.lock classic and bun.lock spell the same
	// semver; a fifth of the entries keeps the suite fast.
	sample := everyNth(tuples, 5)
	var pnpm, yarn, bun strings.Builder
	pnpm.WriteString("lockfileVersion: '9.0'\npackages:\n")
	yarn.WriteString("# yarn lockfile v1\n\n")
	bun.WriteString("{\n  \"lockfileVersion\": 1,\n  \"packages\": {\n")
	for i, tp := range sample {
		fmt.Fprintf(&pnpm, "  '%s@%s':\n    resolution: {integrity: sha512-AAAA}\n", tp.name, tp.version)
		fmt.Fprintf(&yarn, "\"%s@%s\":\n  version \"%s\"\n  resolved \"https://registry.yarnpkg.com/%s/-/x-%s.tgz\"\n\n", tp.name, tp.version, tp.version, tp.name, tp.version)
		fmt.Fprintf(&bun, "    \"h%d/%s\": [\"%s@%s\", \"\", {}, \"sha512-AAAA\"],\n", i, tp.name, tp.name, tp.version)
	}
	bun.WriteString("  }\n}\n")
	requireAllReported(t, "npm pnpm-lock.yaml", sample, identitySpelling, runSpelling(t, intel.EcosystemNPM, "pnpm-lock.yaml", pnpm.String()))
	requireAllReported(t, "npm yarn.lock", sample, identitySpelling, runSpelling(t, intel.EcosystemNPM, "yarn.lock", yarn.String()))
	requireAllReported(t, "npm bun.lock", sample, identitySpelling, runSpelling(t, intel.EcosystemNPM, "bun.lock", bun.String()))
}

func TestEmbeddedPyPIRecordsMatchRequirementsSpelling(t *testing.T) {
	all := liveExactTuples(t, intel.EcosystemPyPI)
	if len(all) == 0 {
		t.Fatal("the embedded snapshot has no live exact-version PyPI records")
	}
	// pip accepts `==` only with a valid PEP 440 version; a version that
	// is not one cannot be installed by a current pip from any spelling.
	var tuples []exactTuple
	for _, tp := range all {
		if _, ok := intel.PEP440Canonical(tp.version); ok {
			tuples = append(tuples, tp)
		}
	}
	t.Logf("PyPI: %d of %d exact-version entries are valid PEP 440 versions", len(tuples), len(all))
	var req, uv, poetry strings.Builder
	uv.WriteString("version = 1\nrequires-python = \">=3.8\"\n\n")
	for _, tp := range tuples {
		fmt.Fprintf(&req, "%s==%s\n", tp.name, tp.version)
		fmt.Fprintf(&uv, "[[package]]\nname = %q\nversion = %q\nsource = { registry = \"https://pypi.org/simple\" }\n\n", tp.name, tp.version)
		fmt.Fprintf(&poetry, "[[package]]\nname = %q\nversion = %q\ndescription = \"\"\noptional = false\npython-versions = \"*\"\nfiles = []\n\n", tp.name, tp.version)
	}
	poetry.WriteString("[metadata]\nlock-version = \"2.1\"\npython-versions = \"*\"\ncontent-hash = \"0\"\n")
	requireAllReported(t, "PyPI requirements.txt", tuples, identitySpelling,
		runSpelling(t, intel.EcosystemPyPI, "requirements.txt", req.String()))
	requireAllReported(t, "PyPI uv.lock", tuples, identitySpelling, runSpelling(t, intel.EcosystemPyPI, "uv.lock", uv.String()))
	requireAllReported(t, "PyPI poetry.lock", tuples, identitySpelling, runSpelling(t, intel.EcosystemPyPI, "poetry.lock", poetry.String()))
}

// Every live advisory version must be one the ecosystem's own lockfiles
// can contain. An importer that emits a spelling the tool never writes
// (a Go version with build metadata, an npm version with a "v", a PyPI
// version that is not PEP 440) fails here instead of matching nothing.
func TestEmbeddedAdvisoryVersionsAreValidLockfileVersions(t *testing.T) {
	semver := regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
	gem := regexp.MustCompile(`^[0-9]+(?:\.[0-9A-Za-z]+)*$`)
	// Known exceptions already in the snapshot: a malicious upload whose
	// version no current installer accepts. Add an entry only after
	// checking the advisory.
	known := map[string]bool{"PyPI\x00news-ascii-artss\x00v_05": true}
	valid := func(eco, name, v string) bool {
		if known[eco+"\x00"+name+"\x00"+v] {
			return true
		}
		switch eco {
		case intel.EcosystemNPM, intel.EcosystemCargo:
			return semver.MatchString(v)
		case intel.EcosystemRubyGems:
			return gem.MatchString(v)
		case intel.EcosystemMaven:
			return v != "" && !strings.ContainsAny(v, " \t:/\\")
		default:
			_, ok := intel.CanonicalVersion(eco, v)
			return ok
		}
	}
	for _, eco := range intel.SupportedEcosystems() {
		var bad []string
		for _, tp := range liveExactTuples(t, eco) {
			if !valid(eco, tp.name, tp.version) {
				bad = append(bad, fmt.Sprintf("%s %q (%s)", tp.name, tp.version, tp.id))
			}
		}
		if len(bad) > 0 {
			if len(bad) > 10 {
				bad = append(bad[:10], fmt.Sprintf("and %d more", len(bad)-10))
			}
			t.Errorf("%s: %d advisory versions are not valid lockfile versions: %s", eco, len(bad), strings.Join(bad, "; "))
		}
	}
}

func TestEmbeddedCratesRecordsMatchCargoLockSpelling(t *testing.T) {
	tuples := liveExactTuples(t, intel.EcosystemCargo)
	if len(tuples) == 0 {
		t.Skip("the embedded snapshot has no live exact-version crates.io records")
	}
	var lock strings.Builder
	lock.WriteString("version = 4\n\n")
	for _, tp := range tuples {
		fmt.Fprintf(&lock, "[[package]]\nname = %q\nversion = %q\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n", tp.name, tp.version)
	}
	requireAllReported(t, "crates.io Cargo.lock", tuples, identitySpelling,
		runSpelling(t, intel.EcosystemCargo, "Cargo.lock", lock.String()))
}

// toggleV returns the other tag spelling of a Composer version: Composer's
// VersionParser treats "v1.2.3" and "1.2.3" as the same version, and a
// package's tags may use either form.
func toggleV(v string) string {
	if strings.HasPrefix(v, "v") || strings.HasPrefix(v, "V") {
		return v[1:]
	}
	return "v" + v
}

func TestEmbeddedPackagistRecordsMatchComposerLockSpelling(t *testing.T) {
	tuples := liveExactTuples(t, intel.EcosystemPackagist)
	if len(tuples) == 0 {
		t.Skip("the embedded snapshot has no live exact-version Packagist records")
	}
	for _, variant := range []struct {
		label string
		spell func(exactTuple) (string, string)
	}{
		{"as listed", identitySpelling},
		{"other tag prefix", func(tp exactTuple) (string, string) { return tp.name, toggleV(tp.version) }},
	} {
		var pkgs []map[string]string
		for _, tp := range tuples {
			name, version := variant.spell(tp)
			pkgs = append(pkgs, map[string]string{"name": name, "version": version})
		}
		lock, err := json.Marshal(map[string]any{"packages": pkgs, "packages-dev": []any{}})
		if err != nil {
			t.Fatal(err)
		}
		requireAllReported(t, "Packagist composer.lock ("+variant.label+")", tuples, variant.spell,
			runSpelling(t, intel.EcosystemPackagist, "composer.lock", string(lock)))
	}
}

func TestEmbeddedRubyGemsRecordsMatchGemfileLockSpelling(t *testing.T) {
	tuples := liveExactTuples(t, intel.EcosystemRubyGems)
	if len(tuples) == 0 {
		t.Fatal("the embedded snapshot has no live exact-version RubyGems records")
	}
	for _, platform := range []string{"", "-x86_64-linux"} {
		var lock strings.Builder
		lock.WriteString("GEM\n  remote: https://rubygems.org/\n  specs:\n")
		for _, tp := range tuples {
			fmt.Fprintf(&lock, "    %s (%s%s)\n", tp.name, tp.version, platform)
		}
		lock.WriteString("\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n\nBUNDLED WITH\n   2.5.0\n")
		label := "RubyGems Gemfile.lock"
		if platform != "" {
			label += " (platform gems)"
		}
		hits := runSpelling(t, intel.EcosystemRubyGems, "Gemfile.lock", lock.String())
		requireAllReported(t, label, tuples, func(tp exactTuple) (string, string) {
			return strings.ToLower(tp.name), tp.version
		}, hits)
	}
}

func TestEmbeddedMavenRecordsMatchGradleAndPomSpelling(t *testing.T) {
	tuples := liveExactTuples(t, intel.EcosystemMaven)
	if len(tuples) == 0 {
		t.Skip("the embedded snapshot has no live exact-version Maven records")
	}
	var gradle, pom strings.Builder
	pom.WriteString("<project><dependencies>\n")
	for _, tp := range tuples {
		group, artifact, ok := strings.Cut(tp.name, ":")
		if !ok {
			t.Fatalf("Maven record %s names %q, not groupId:artifactId", tp.id, tp.name)
		}
		fmt.Fprintf(&gradle, "%s:%s:%s=runtimeClasspath\n", group, artifact, tp.version)
		fmt.Fprintf(&pom, "<dependency><groupId>%s</groupId><artifactId>%s</artifactId><version>%s</version></dependency>\n", group, artifact, tp.version)
	}
	pom.WriteString("</dependencies></project>\n")
	requireAllReported(t, "Maven gradle.lockfile", tuples, identitySpelling, runSpelling(t, intel.EcosystemMaven, "gradle.lockfile", gradle.String()))
	requireAllReported(t, "Maven pom.xml", tuples, identitySpelling, runSpelling(t, intel.EcosystemMaven, "pom.xml", pom.String()))
}

// nugetNormalized spells a version the way NuGet writes it in
// packages.lock.json (NuGet "Normalized version numbers"): leading zeros
// dropped, a zero fourth part omitted, build metadata removed.
func nugetNormalized(v string) string {
	v, _, _ = strings.Cut(v, "+")
	release, label, hasLabel := strings.Cut(v, "-")
	parts := strings.Split(release, ".")
	for i, p := range parts {
		if n, err := strconv.Atoi(p); err == nil {
			parts[i] = strconv.Itoa(n)
		}
	}
	for len(parts) < 3 {
		parts = append(parts, "0")
	}
	if len(parts) == 4 && parts[3] == "0" {
		parts = parts[:3]
	}
	out := strings.Join(parts, ".")
	if hasLabel {
		out += "-" + label
	}
	return out
}

func TestEmbeddedNuGetRecordsMatchLockAndProjectSpelling(t *testing.T) {
	tuples := liveExactTuples(t, intel.EcosystemNuGet)
	if len(tuples) == 0 {
		t.Fatal("the embedded snapshot has no live exact-version NuGet records")
	}
	// One target framework per entry so two versions of one package can
	// both be listed.
	deps := map[string]any{}
	var proj strings.Builder
	proj.WriteString("<Project Sdk=\"Microsoft.NET.Sdk\"><ItemGroup>\n")
	for i, tp := range tuples {
		deps[fmt.Sprintf("net8.0/h%d", i)] = map[string]any{tp.name: map[string]string{"type": "Direct", "resolved": nugetNormalized(tp.version)}}
		fmt.Fprintf(&proj, "<PackageReference Include=%q Version=%q />\n", tp.name, tp.version)
	}
	proj.WriteString("</ItemGroup></Project>\n")
	lock, err := json.Marshal(map[string]any{"version": 1, "dependencies": deps})
	if err != nil {
		t.Fatal(err)
	}
	requireAllReported(t, "NuGet packages.lock.json", tuples, func(tp exactTuple) (string, string) {
		return tp.name, nugetNormalized(tp.version)
	}, runSpelling(t, intel.EcosystemNuGet, "packages.lock.json", string(lock)))
	requireAllReported(t, "NuGet csproj", tuples, identitySpelling, runSpelling(t, intel.EcosystemNuGet, "csproj", proj.String()))

	// Project files are hand-written: NuGet resolves an exact-match
	// range ("[1.2.3]"), a pre-release label in another letter case and a
	// zero fourth part to the same package version.
	for _, variant := range []struct {
		label string
		spell func(string) string
	}{
		{"exact range", func(v string) string { return "[" + v + "]" }},
		{"lower-case label", strings.ToLower},
		{"four parts", func(v string) string {
			release, label, hasLabel := strings.Cut(v, "-")
			if strings.Count(release, ".") != 2 {
				return v
			}
			if hasLabel {
				return release + ".0-" + label
			}
			return release + ".0"
		}},
	} {
		var b strings.Builder
		b.WriteString("<Project Sdk=\"Microsoft.NET.Sdk\"><ItemGroup>\n")
		for _, tp := range tuples {
			fmt.Fprintf(&b, "<PackageReference Include=%q Version=%q />\n", tp.name, variant.spell(tp.version))
		}
		b.WriteString("</ItemGroup></Project>\n")
		hits := runSpelling(t, intel.EcosystemNuGet, "csproj", b.String())
		spell := variant.spell
		if variant.label == "exact range" {
			spell = func(v string) string { return v }
		}
		requireAllReported(t, "NuGet csproj ("+variant.label+")", tuples, func(tp exactTuple) (string, string) {
			return tp.name, spell(tp.version)
		}, hits)
	}
}

// mainBranchMatched is how the matcher and runner compared an advisory
// version with a lockfile version before per-ecosystem version equality:
// literal equality, PEP 440 equality for PyPI, and for Packagist the
// runner's second lookup with one leading "v" stripped from the lockfile
// version.
func mainBranchMatched(ecosystem, advisory, lockfile string) bool {
	if advisory == lockfile {
		return true
	}
	switch ecosystem {
	case intel.EcosystemPyPI:
		return intel.PEP440Equal(advisory, lockfile)
	case intel.EcosystemPackagist:
		return strings.TrimPrefix(lockfile, "v") == advisory && strings.HasPrefix(lockfile, "v")
	}
	return false
}

// Every (advisory version, lockfile version) pair that matched before the
// matcher compared versions per ecosystem must still match. The corpus is
// every distinct version spelling per ecosystem in the embedded snapshots,
// withdrawn records included, plus Composer date versions, which the
// snapshot does not currently list; each is tried against the lockfile
// spellings the old rules accepted.
func TestPairsThatMatchedBeforeStillMatch(t *testing.T) {
	type pair struct{ ecosystem, advisory string }
	seen := map[pair]bool{}
	var pairs []pair
	add := func(eco, v string) {
		p := pair{eco, v}
		if v != "" && !seen[p] {
			seen[p] = true
			pairs = append(pairs, p)
		}
	}
	for _, s := range EmbeddedSnapshots() {
		for _, r := range s.Records {
			for _, v := range r.Versions {
				add(r.Ecosystem, v)
			}
		}
	}
	for _, v := range []string{"20200101", "123456", "2020.01.01", "2020-01-01", "20200101-beta1", "v20200101"} {
		add(intel.EcosystemPackagist, v)
	}
	checked, lost := 0, []string{}
	for _, p := range pairs {
		if p.ecosystem == intel.EcosystemRubyGems && strings.Contains(p.advisory, "-") {
			// Gemfile.lock now reads `name (1.0-x86_64-linux)` as version
			// 1.0; an advisory spelled with a platform would no longer be
			// matched by that line.
			t.Errorf("RubyGems advisory version %q has a platform-like suffix", p.advisory)
		}
		for _, l := range []string{p.advisory, "v" + p.advisory, strings.TrimPrefix(p.advisory, "v"), strings.ToUpper(p.advisory), " " + p.advisory} {
			if !mainBranchMatched(p.ecosystem, p.advisory, l) {
				continue
			}
			checked++
			if !intel.VersionsEqual(p.ecosystem, p.advisory, l) {
				lost = append(lost, fmt.Sprintf("%s advisory %q lockfile %q", p.ecosystem, p.advisory, l))
			}
		}
	}
	t.Logf("%d advisory/lockfile spelling pairs that matched before were checked", checked)
	if len(lost) > 0 {
		if len(lost) > 10 {
			lost = append(lost[:10], fmt.Sprintf("and %d more", len(lost)-10))
		}
		t.Errorf("%d pairs no longer match: %s", len(lost), strings.Join(lost, "; "))
	}
}

func everyNth(in []exactTuple, n int) []exactTuple {
	var out []exactTuple
	for i := 0; i < len(in); i += n {
		out = append(out, in[i])
	}
	return out
}
