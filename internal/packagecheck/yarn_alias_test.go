package packagecheck

import (
	"fmt"
	"testing"

	"github.com/garagon/aguara/internal/intel"
	"github.com/stretchr/testify/require"
)

func TestYarnClassicAliasIdentity(t *testing.T) {
	for _, tc := range []struct{ header, name string }{
		{`"safe@npm:real@^1.0.0"`, "real"},
		{`"@local/safe@npm:real@next"`, "real"},
		{`"safe@npm:@scope/real@*"`, "@scope/real"},
		{`"@local/safe@npm:@scope/real@1"`, "@scope/real"},
		{`"safe@npm:real"`, "real"},
		{`"safe@npm:real@"`, "real"},
		{`"safe@npm:@scope/real"`, "@scope/real"},
		{`"a@npm:real@^1", "b@npm:real@~1", real@1.2.3`, "real"},
		{`real@1.2.3, "a@npm:real@^1"`, "real"},
		{`"@local/_safe@npm:real@^1"`, "real"},
		{`"a@npm:@scope/_real@^1"`, "@scope/_real"},
		{`"@scope/_real@^1"`, "@scope/_real"},
		{`"real@>=1.0.0\t<2.0.0", "a@npm:real@^1"`, "real"},
	} {
		refs, err := ParseYarnLock(writeYarn(t, yarnHeader+tc.header+":\n  version \"1.2.3\"\n"))
		require.NoError(t, err)
		require.Equal(t, []string{tc.name + "@1.2.3"}, refSet(refs), tc.header)
	}
}

func TestYarnClassicAliasRejectsAmbiguity(t *testing.T) {
	for _, header := range []string{
		`"a@npm:real@1", "b@npm:other@1"`,
		`"b@npm:other@1", "a@npm:real@1"`,
		`real@1, other@1`, `"a@npm:real@1", real@https://example.test/x`,
		`"a@file:vendor@npm:real@1"`, `"a@npm:real@file:../x"`,
		`"a@npm:real@jsr:thing"`, `"a@npm:real@npm:other@1"`,
		`"a@npm:real@user/repo"`, `"a@npm:real@custom:thing"`,
		`"a@npm:real@https://example.test/x"`, `"a@npm:"`,
		`"a@npm:@scope"`, `"a@npm:@scope/"`, `"a@npm:real/extra@1"`,
		`"a@npm:real@1",`, `"a@npm:real@1`, `""a@npm:real@1""`,
		`"bad name@npm:real@1"`, `"a@npm:bad name@1"`,
		`"a@npm:real@1", "b@npm:Real@1"`,
	} {
		refs, err := ParseYarnLock(writeYarn(t, yarnHeader+header+":\n  version \"1.2.3\"\n"))
		require.NoError(t, err)
		require.Empty(t, refs, header)
	}
}

func TestYarnClassicAliasUsesBodyVersion(t *testing.T) {
	for _, version := range []string{"latest", "1", "1.2", "1.2.x", "^1.2.3", "npm:real@1.2.3", "1.2.3+..", "1.2.3+a+b", "01.2.3", "1.2.3-01"} {
		refs, err := ParseYarnLock(writeYarn(t, fmt.Sprintf("\"a@npm:real@1.2.3\":\n  version %q\n", version)))
		require.NoError(t, err)
		require.Empty(t, refs)
	}
	refs, err := ParseYarnLock(writeYarn(t, "\"a@npm:real@1.0.0\":\n  version \"2.0.0\"\n\nreal@2:\n  version \"2.0.0\"\n"))
	require.NoError(t, err)
	require.Equal(t, []string{"real@2.0.0"}, refSet(refs))
}

func TestYarnClassicAliasResolutionSource(t *testing.T) {
	for _, resolved := range []string{"git+https://example.test/other.git#abc", "git://example.test/other", "file:../local", "ssh://example.test/project", "custom:other"} {
		refs, err := ParseYarnLock(writeYarn(t, fmt.Sprintf("\"a@npm:real@^1\":\n  version \"1.2.3\"\n  resolved %q\n", resolved)))
		require.NoError(t, err)
		require.Empty(t, refs, resolved)
	}
	refs, err := ParseYarnLock(writeYarn(t, "\"a@npm:real@^1\":\n  version \"1.2.3\"\n  resolved \"https://registry.yarnpkg.com/real/-/real-1.2.3.tgz#abc\"\n"))
	require.NoError(t, err)
	require.Equal(t, []string{"real@1.2.3"}, refSet(refs))
}

func TestYarnClassicAliasRunnerFindsRealPackage(t *testing.T) {
	target := writeYarn(t, "\"safe@npm:fixture-malicious@^1\":\n  version \"1.2.3\"\n")
	runner := Runner{Matcher: intel.NewMatcher(intel.Snapshot{Records: []intel.Record{{ID: "MAL-YARN-ALIAS-FIXTURE", Ecosystem: intel.EcosystemNPM, Name: "fixture-malicious", Kind: intel.KindMalicious, Versions: []string{"1.2.3"}}}})}
	result, err := runner.Run([]Target{target})
	require.NoError(t, err)
	require.Len(t, result.Hits, 1)
	require.Equal(t, "fixture-malicious", result.Hits[0].Record.Name)
	require.Equal(t, 1, result.Ecosystems[0].PackagesRead)
}
