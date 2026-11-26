package intel_test

import (
	"testing"

	"github.com/garagon/aguara/internal/intel"
)

// versionCase is one lookup against a record that lists recordVersion.
type versionCase struct {
	recordVersion, lockfileVersion string
	want                           bool
}

func runVersionCases(t *testing.T, ecosystem, name string, cases []versionCase) {
	t.Helper()
	for _, tc := range cases {
		m := buildMatcher(t, intel.Record{
			ID: "MAL-TEST", Ecosystem: ecosystem, Name: name,
			Kind: intel.KindMalicious, Versions: []string{tc.recordVersion},
		})
		got := len(m.MatchPackage(intel.MatchInput{Ecosystem: ecosystem, Name: name, Version: tc.lockfileVersion})) > 0
		if got != tc.want {
			t.Errorf("%s record %q, lockfile %q: matched = %v, want %v", ecosystem, tc.recordVersion, tc.lockfileVersion, got, tc.want)
		}
	}
}

// OSV Go records list versions without the leading "v" that go.sum and
// go.mod always write. Both spellings must match in both directions, and
// nothing looser than the Go module version rules may match.
func TestGoVersionEquality(t *testing.T) {
	runVersionCases(t, intel.EcosystemGo, "github.com/example/mod", []versionCase{
		{"0.69.4", "v0.69.4", true},
		{"v0.69.4", "v0.69.4", true},
		{"v0.69.4", "0.69.4", true},
		{"0.69.4", "0.69.4", true},
		// +incompatible names the same tag for a v2+ module without /vN.
		{"2.27.0", "v2.27.0+incompatible", true},
		{"2.27.0+incompatible", "v2.27.0+incompatible", true},
		{"v2.27.0+incompatible", "2.27.0", true},
		// +incompatible is only valid from major version 2.
		{"1.2.3+incompatible", "1.2.3", false},
		{"1.2.3+incompatible", "v1.2.3", false},
		{"1.2.3", "v1.2.3+incompatible", false},
		{"0.9.0+incompatible", "v0.9.0", false},
		{"10.0.0+incompatible", "v10.0.0+incompatible", true},
		// Pre-releases and pseudo-versions must be equal exactly.
		{"1.0.0-rc.1", "v1.0.0-rc.1", true},
		{"0.0.0-20210510213326-e313ffa8abf6", "v0.0.0-20210510213326-e313ffa8abf6", true},
		{"1.2.3", "v1.2.4-0.20210510213326-e313ffa8abf6", false},
		{"0.0.0-20210510213326-e313ffa8abf6", "v0.0.0", false},
		{"1.0.0-RC.1", "v1.0.0-rc.1", false},
		// No prefix matching, no zero padding, no shorthand.
		{"1.2.3", "v1.2.30", false},
		{"1.2.30", "v1.2.3", false},
		{"1.2", "v1.2.0", false},
		{"1.2.0", "v1.2", false},
		{"01.2.3", "v1.2.3", false},
		{"1.2.3", "vv1.2.3", false},
		// Build metadata other than +incompatible is not a Go version.
		{"1.2.3", "v1.2.3+meta", false},
		{"1.2.3+meta", "v1.2.3", false},
		{"", "v1.2.3", false},
	})
}

// Composer's VersionParser::normalize decides version equality for
// Packagist: a tag spelled with or without "v", padded to four parts, and
// stability suffixes in their several spellings.
func TestPackagistVersionEquality(t *testing.T) {
	runVersionCases(t, intel.EcosystemPackagist, "vendor/pkg", []versionCase{
		{"3.5.0", "v3.5.0", true},
		{"v3.5.0", "3.5.0", true},
		{"3.5", "3.5.0.0", true},
		{"1.0.0-RC1", "v1.0.0-rc1", true},
		{"1.8.0-beta.9", "1.8.0-beta9", true},
		{"1.0.0-b2", "1.0.0-beta2", true},
		{"1.0.0+build", "1.0.0", true},
		{"1.0.0-dev", "1.0.0.0-dev", true},
		{"3.5.0", "3.5.1", false},
		{"3.5.0", "3.50", false},
		{"1.0.0-beta1", "1.0.0-beta10", false},
		{"1.0.0-beta1", "1.0.0", false},
		{"1.02.0", "1.2.0", false},
		{"dev-main", "dev-main", true},
		{"dev-main", "DEV-main", true},
		{"dev-main", "dev-Main", false},
		{"dev-main", "dev-master", false},
		{"2.x-dev", "2.0.0-dev", false},
		// Date versions take Composer's date(time) branch: separators
		// become ".", the leading "v" is dropped, modifiers apply.
		{"20200101", "v20200101", true},
		{"123456", "v123456", true},
		{"2020.01.01", "v2020.01.01", true},
		// Composer reads 2020.01.01 as a classical version (2020.01.01.0)
		// and 2020-01-01 as a date (2020.01.01), so they differ.
		{"2020-01-01", "2020.01.01", false},
		{"2020-01-01", "v2020-01-01", true},
		// The runner's former lookup with one leading "v" stripped is kept.
		{"v4.0.0-alpha.3", "vv4.0.0-alpha.3", true},
		{"2020-01-01 10:20", "2020.01.01", false},
		{"20200101-beta1", "v20200101b1", true},
		{"20200101", "20200101-dev", false},
		{"20200101", "2020.01.01", false},
		{"20200101", "20200102", false},
		{"20200101", "v202001010", false},
		{"123456", "v1234567", false},
	})
}

// NuGet treats 1, 1.0, 1.0.0 and 1.0.0.0 as one version, drops leading
// zeros and build metadata, and compares pre-release labels case
// insensitively.
func TestNuGetVersionEquality(t *testing.T) {
	runVersionCases(t, intel.EcosystemNuGet, "Some.Package", []versionCase{
		{"1.0.0", "1.0", true},
		{"1.0.0", "1.0.0.0", true},
		{"1.0.0.0", "1.0.0", true},
		{"1.01.1", "1.1.1", true},
		{"1.0.7", "1.0.7+r3456", true},
		{"4.4.1-contentFiles", "4.4.1-contentfiles", true},
		{"1.2.3.4", "1.2.3.4", true},
		{"1.2.3.4", "1.2.3", false},
		{"1.2.3", "1.2.30", false},
		{"1.0.0-beta", "1.0.0", false},
		{"1.0.0-beta.1", "1.0.0-beta1", false},
		{"1.0.0", "[1.0.0]", false},
	})
}

// npm, crates.io, RubyGems and Maven lockfiles record the registry's own
// version string, so only literal equality matches.
func TestLiteralVersionEcosystems(t *testing.T) {
	for _, eco := range []string{intel.EcosystemNPM, intel.EcosystemCargo, intel.EcosystemRubyGems, intel.EcosystemMaven} {
		runVersionCases(t, eco, "pkg", []versionCase{
			{"1.2.3", "1.2.3", true},
			{"1.2.3", "v1.2.3", false},
			{"1.2.3", "1.2.3.0", false},
			{"1.0.0-rc.1", "1.0.0-RC.1", false},
		})
	}
}
