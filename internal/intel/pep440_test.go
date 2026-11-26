package intel_test

import (
	"strings"
	"testing"

	"github.com/garagon/aguara/internal/intel"
	"github.com/stretchr/testify/require"
)

func TestPEP440Canonical(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"1.0", "1"},
		{"1.0.0", "1"},
		{"1", "1"},
		{"0", "0"},
		{"0.0.0", "0"},
		{"1.0.1", "1.0.1"},
		{"01.002.0003", "1.2.3"},
		{"v1.2", "1.2"},
		{"V1.2", "1.2"},
		{" 1.2 ", "1.2"},
		{"0!1.2", "1.2"},
		{"2!1.2.0", "2!1.2"},
		{"1.0a1", "1a1"},
		{"1.0alpha1", "1a1"},
		{"1.0-ALPHA-1", "1a1"},
		{"1.0b", "1b0"},
		{"1.0beta2", "1b2"},
		{"1.0c1", "1rc1"},
		{"1.0pre1", "1rc1"},
		{"1.0preview1", "1rc1"},
		{"1.0RC1", "1rc1"},
		{"1.0-rc.1", "1rc1"},
		{"1.0.post1", "1.post1"},
		{"1.0-1", "1.post1"},
		{"1.0post", "1.post0"},
		{"1.0rev2", "1.post2"},
		{"1.0r3", "1.post3"},
		{"1.0.dev", "1.dev0"},
		{"1.0dev01", "1.dev1"},
		{"1.0a1.post2.dev3", "1a1.post2.dev3"},
		{"1.0+Local-Build_7", "1+local.build.7"},
		{"1.0+abc.007", "1+abc.7"},
	} {
		got, ok := intel.PEP440Canonical(tc.in)
		require.Truef(t, ok, "PEP440Canonical(%q) rejected a valid version", tc.in)
		require.Equalf(t, tc.want, got, "PEP440Canonical(%q)", tc.in)
	}
	for _, bad := range []string{"", "latest", "1.0-", "1..0", "1.0+", "1.0+a..b", "=1.0", "1.0 2", "1.0.*", strings.Repeat("1.", 200) + "1"} {
		_, ok := intel.PEP440Canonical(bad)
		require.Falsef(t, ok, "PEP440Canonical(%q) accepted an invalid version", bad)
	}
}

func TestPEP440Equal(t *testing.T) {
	require.True(t, intel.PEP440Equal("1.0", "1.0.0"))
	require.True(t, intel.PEP440Equal("1.0.0", "1"))
	require.True(t, intel.PEP440Equal("1.0RC1", "1.0rc1"))
	require.True(t, intel.PEP440Equal("not-a-version", "not-a-version"), "literal equality still holds")
	require.False(t, intel.PEP440Equal("", ""))
	require.False(t, intel.PEP440Equal("1.0", "1.0.1"))
	require.False(t, intel.PEP440Equal("1.0", "1.0.post1"))
	require.False(t, intel.PEP440Equal("1.0", "1.0+local"), "a local label is a different build, not the PyPI release")
	require.False(t, intel.PEP440Equal("1.0", "1.0a1"))
	require.False(t, intel.PEP440Equal("1!1.0", "1.0"))
}

func TestMatcherPyPIVersionsUsePEP440Equality(t *testing.T) {
	m := buildMatcher(t, intel.Record{
		ID:        "MAL-PYPI-FIXTURE",
		Ecosystem: intel.EcosystemPyPI,
		Name:      "Foo_Bar",
		Kind:      intel.KindMalicious,
		Versions:  []string{"1.0.0", "2.0rc1"},
	})
	for _, name := range []string{"Foo_Bar", "foo-bar", "foo.bar", "FOO.BAR"} {
		for _, v := range []string{"1.0.0", "1.0", "1", "v1.0", "2.0.0rc1", "2.0-RC-1"} {
			hits := m.MatchPackage(intel.MatchInput{Ecosystem: intel.EcosystemPyPI, Name: name, Version: v})
			require.Lenf(t, hits, 1, "%s %s must match the advisory", name, v)
		}
	}
	for _, v := range []string{"", "1.0.1", "1.0+local", "1.0.post1", "2.0", "garbage"} {
		hits := m.MatchPackage(intel.MatchInput{Ecosystem: intel.EcosystemPyPI, Name: "foo-bar", Version: v})
		require.Emptyf(t, hits, "version %q must not match", v)
	}
}

func TestMatcherPEP440EqualityIsPyPIOnly(t *testing.T) {
	m := buildMatcher(t, intel.Record{
		ID:        "MAL-NPM-FIXTURE",
		Ecosystem: intel.EcosystemNPM,
		Name:      "pkg",
		Kind:      intel.KindMalicious,
		Versions:  []string{"1.0.0"},
	})
	require.Empty(t, m.MatchPackage(intel.MatchInput{Ecosystem: intel.EcosystemNPM, Name: "pkg", Version: "1.0"}),
		"other ecosystems keep literal version equality")
	require.Len(t, m.MatchPackage(intel.MatchInput{Ecosystem: intel.EcosystemNPM, Name: "pkg", Version: "1.0.0"}), 1)
}

// PEP440String must produce str(Version(v)) as the packaging library
// does; these pairs were checked against packaging 25.0 (pip 25.2).
func TestPEP440StringMatchesPackagingStr(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"1.0", "1.0"},
		{"1.0.0", "1.0.0"},
		{"01.0", "1.0"},
		{"1.0-RC1", "1.0rc1"},
		{"v1.0", "1.0"},
		{"0!1.0", "1.0"},
		{"1.0.post0", "1.0.post0"},
		{"1.0-1", "1.0.post1"},
		{"1.0+ABC.01", "1.0+abc.1"},
		{"1.0.dev", "1.0.dev0"},
		{"1.0a", "1.0a0"},
		{"1.0c1", "1.0rc1"},
		{"1.0_RC_1", "1.0rc1"},
	} {
		got, ok := intel.PEP440String(tc.in)
		require.True(t, ok, tc.in)
		require.Equal(t, tc.want, got, tc.in)
	}
	_, ok := intel.PEP440String("1.0-custom")
	require.False(t, ok)
}

// `===` is arbitrary equality: pip compares the requirement, ignoring
// case, with str(Version(candidate)). These outcomes were checked against
// SpecifierSet(spec).contains(Version(candidate)) in packaging 25.0.
func TestMatcherArbitraryEqualityFollowsPip(t *testing.T) {
	for _, tc := range []struct {
		recordVersion, spec string
		want                bool
	}{
		{"1.0", "1.0", true},
		{"1.0.0", "1.0", false},
		{"1.0", "1.0.0", false},
		{"1.0rc1", "1.0-RC1", false},
		{"1.0-RC1", "1.0rc1", true},
		{"1.0rc1", "1.0RC1", true},
		{"1.0", "V1.0", false},
		{"1.0", "01.0", false},
		{"1.0-custom", "1.0-CUSTOM", true},
	} {
		m := intel.NewMatcher(intel.Snapshot{Records: []intel.Record{{
			ID: "MAL-ARB", Ecosystem: intel.EcosystemPyPI, Name: "pkg", Kind: intel.KindMalicious, Versions: []string{tc.recordVersion},
		}}})
		got := len(m.MatchPackage(intel.MatchInput{Ecosystem: intel.EcosystemPyPI, Name: "pkg", Version: tc.spec, ArbitraryEquality: true})) > 0
		require.Equal(t, tc.want, got, "record %q, ===%s", tc.recordVersion, tc.spec)
	}
	// An all-versions entry still matches: every release is malicious.
	m := intel.NewMatcher(intel.Snapshot{AllVersions: []intel.AllVersionsEntry{{ID: "MAL-ALL", Ecosystem: intel.EcosystemPyPI, Name: "pkg"}}})
	require.Len(t, m.MatchPackage(intel.MatchInput{Ecosystem: intel.EcosystemPyPI, Name: "pkg", Version: "9.9", ArbitraryEquality: true}), 1)
}

func TestMatcherEmptyVersionMatchesOnlyAllVersionsEntries(t *testing.T) {
	m := intel.NewMatcher(intel.Snapshot{
		Records:     []intel.Record{{ID: "MAL-EXACT", Ecosystem: intel.EcosystemPyPI, Name: "exact", Kind: intel.KindMalicious, Versions: []string{"1.0"}}},
		AllVersions: []intel.AllVersionsEntry{{ID: "MAL-ALL", Ecosystem: intel.EcosystemPyPI, Name: "every_version"}},
	})
	require.Empty(t, m.MatchPackage(intel.MatchInput{Ecosystem: intel.EcosystemPyPI, Name: "exact"}))
	hits := m.MatchPackage(intel.MatchInput{Ecosystem: intel.EcosystemPyPI, Name: "Every.Version"})
	require.Len(t, hits, 1)
	require.Equal(t, "MAL-ALL", hits[0].Record.ID)
}
