package intel

import (
	"strings"
	"testing"
)

func TestCanonicaliseEcosystem_AllEightCanonicalIDs(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{"npm", EcosystemNPM},
		{"PyPI", EcosystemPyPI},
		{"Go", EcosystemGo},
		{"crates.io", EcosystemCargo},
		{"Packagist", EcosystemPackagist},
		{"RubyGems", EcosystemRubyGems},
		{"Maven", EcosystemMaven},
		{"NuGet", EcosystemNuGet},
	}
	for _, tc := range tests {
		t.Run(tc.raw, func(t *testing.T) {
			if got := CanonicaliseEcosystem(tc.raw); got != tc.want {
				t.Errorf("CanonicaliseEcosystem(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestCanonicaliseEcosystem_Aliases(t *testing.T) {
	// Every alias listed in the v0.17.0 spec must resolve. Includes
	// the case-folding contract: lower / upper / mixed case all
	// resolve to the same canonical ID.
	tests := []struct {
		alias string
		want  string
	}{
		{"python", EcosystemPyPI},
		{"PYTHON", EcosystemPyPI},
		{"pypi", EcosystemPyPI},
		{"PYPI", EcosystemPyPI},
		{"golang", EcosystemGo},
		{"go", EcosystemGo},
		{"GO", EcosystemGo},
		{"rust", EcosystemCargo},
		{"cargo", EcosystemCargo},
		{"CRATES.IO", EcosystemCargo},
		{"php", EcosystemPackagist},
		{"composer", EcosystemPackagist},
		{"packagist", EcosystemPackagist},
		{"ruby", EcosystemRubyGems},
		{"gem", EcosystemRubyGems},
		{"rubygems", EcosystemRubyGems},
		{"java", EcosystemMaven},
		{"maven", EcosystemMaven},
		{"MAVEN", EcosystemMaven},
		{"dotnet", EcosystemNuGet},
		{"csharp", EcosystemNuGet},
		{"nuget", EcosystemNuGet},
	}
	for _, tc := range tests {
		t.Run(tc.alias, func(t *testing.T) {
			if got := CanonicaliseEcosystem(tc.alias); got != tc.want {
				t.Errorf("CanonicaliseEcosystem(%q) = %q, want %q", tc.alias, got, tc.want)
			}
		})
	}
}

func TestCanonicaliseEcosystem_TrimsWhitespace(t *testing.T) {
	// A user copy-pasting `--ecosystem ` with a trailing space
	// should still resolve. Otherwise the failure mode is a 404
	// against a bucket called "python ".
	if got := CanonicaliseEcosystem(" python "); got != EcosystemPyPI {
		t.Errorf("expected whitespace trim, got %q", got)
	}
	if got := CanonicaliseEcosystem("\tpypi\n"); got != EcosystemPyPI {
		t.Errorf("expected tab/newline trim, got %q", got)
	}
}

func TestCanonicaliseEcosystem_UnknownReturnsEmpty(t *testing.T) {
	// Caller distinguishes "" from a known ID to fail loud on
	// unsupported input rather than 404 against a wrongly-cased URL.
	tests := []string{
		"",
		"   ",
		"npmm",            // typo
		"perl",            // ecosystem we have not added
		"github.com/user", // module path, not an ecosystem
		"PyPi ",           // trailing space + wrong case in canonical
	}
	// "PyPi " — case-insensitive trim makes this resolve to PyPI;
	// adjust the test to use something genuinely unknown.
	tests[5] = "swift"

	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			if got := CanonicaliseEcosystem(raw); got != "" {
				t.Errorf("CanonicaliseEcosystem(%q) = %q, want \"\" (unknown)", raw, got)
			}
		})
	}
}

func TestSupportedEcosystems_AllEightInRegistryOrder(t *testing.T) {
	got := SupportedEcosystems()
	want := []string{
		EcosystemNPM, EcosystemPyPI, EcosystemGo, EcosystemCargo,
		EcosystemPackagist, EcosystemRubyGems, EcosystemMaven, EcosystemNuGet,
	}
	if len(got) != len(want) {
		t.Fatalf("SupportedEcosystems len = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("SupportedEcosystems[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestSupportedEcosystemsHint_ListsCanonicalAndAliases(t *testing.T) {
	hint := SupportedEcosystemsHint()
	// Every canonical ID must appear so the error message lists
	// each option the user can pick.
	for _, id := range SupportedEcosystems() {
		if !strings.Contains(hint, id) {
			t.Errorf("hint missing canonical ID %q: %s", id, hint)
		}
	}
	// Spot-check a few non-trivial aliases. The hint surfaces them
	// in parentheses so users discover the shorter / human-friendly
	// spellings without reading the source.
	aliases := []string{"python", "golang", "cargo", "rust", "php", "composer", "ruby", "gem", "java", "dotnet", "csharp"}
	for _, a := range aliases {
		if !strings.Contains(hint, a) {
			t.Errorf("hint missing alias %q: %s", a, hint)
		}
	}
	// npm has no non-trivial aliases; it must NOT appear as
	// `npm (npm)`.
	if strings.Contains(hint, "npm (npm") {
		t.Errorf("hint should not duplicate npm as its own alias: %s", hint)
	}
}

func TestNormalizePackageName_PerEcosystem(t *testing.T) {
	// Each spec's name normalizer matches the convention of the
	// ecosystem's registry. The matcher relies on this so OSV
	// records and check-time package refs hash to the same key.
	tests := []struct {
		ecosystem string
		raw       string
		want      string
	}{
		// npm: case-preserving trim. npm scopes (`@scope/name`)
		// matter; preserving case keeps `@Scope/Name` discoverable
		// the way OSV publishes it.
		{EcosystemNPM, "  Lodash  ", "Lodash"},
		{EcosystemNPM, "@types/Node", "@types/Node"},

		// PyPI: PEP 503 -- lower + collapse [-_.] runs.
		{EcosystemPyPI, "Django_REST.Framework", "django-rest-framework"},
		{EcosystemPyPI, "  Some_Pkg  ", "some-pkg"},

		// Go: case-preserving trim because module paths are
		// case-sensitive at the proxy.
		{EcosystemGo, "  github.com/PuerkitoBio/goquery  ", "github.com/PuerkitoBio/goquery"},

		// crates.io: lower + trim (the registry treats hyphen /
		// underscore separately, but OSV records use the literal
		// crate name; a casefold suffices for our matcher).
		{EcosystemCargo, "  Tokio  ", "tokio"},

		// Packagist: lower + trim (`vendor/Package` == `vendor/package`).
		{EcosystemPackagist, "Symfony/Console", "symfony/console"},

		// RubyGems: lower + trim. Most gems are already lowercase
		// in the registry, but normalising anyway covers stray
		// upper-case in user fixtures.
		{EcosystemRubyGems, "  Rails  ", "rails"},

		// Maven: case-preserving trim. groupId:artifactId is
		// case-sensitive in Maven Central.
		{EcosystemMaven, "  org.apache.commons:commons-lang3  ", "org.apache.commons:commons-lang3"},
		{EcosystemMaven, "com.Example:Library", "com.Example:Library"},

		// NuGet: lower + trim (NuGet IDs are case-insensitive).
		{EcosystemNuGet, "Newtonsoft.Json", "newtonsoft.json"},
	}
	for _, tc := range tests {
		t.Run(tc.ecosystem+"/"+tc.raw, func(t *testing.T) {
			got := normalizeName(tc.ecosystem, tc.raw)
			if got != tc.want {
				t.Errorf("normalizeName(%q, %q) = %q, want %q", tc.ecosystem, tc.raw, got, tc.want)
			}
		})
	}
}

func TestNormalizeName_UnknownEcosystemFallsBackToLowerTrim(t *testing.T) {
	// Ecosystems the registry does not know about default to
	// lower+trim. This keeps the matcher functional for snapshots
	// that ship records for a future ecosystem before the registry
	// is updated, and is the same safe-default the previous
	// switch-based implementation provided.
	if got := normalizeName("Conan", "  Foo  "); got != "foo" {
		t.Errorf("unknown ecosystem fallback: got %q, want %q", got, "foo")
	}
}

func TestNormalizeEcosystem_PreservesUnknown(t *testing.T) {
	// Matcher's normalizeEcosystem keeps unknown values around
	// (lower-cased) so future snapshots wire in additively. Locking
	// this behaviour in a test prevents an over-eager refactor from
	// silently dropping unrecognised ecosystems.
	if got := normalizeEcosystem("Conan"); got != "conan" {
		t.Errorf("unknown ecosystem fallback: got %q, want %q", got, "conan")
	}
	if got := normalizeEcosystem("python"); got != EcosystemPyPI {
		t.Errorf("known alias should resolve: got %q, want %q", got, EcosystemPyPI)
	}
}
