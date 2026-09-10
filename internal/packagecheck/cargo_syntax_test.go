package packagecheck

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/garagon/aguara/internal/intel"
	"github.com/stretchr/testify/require"
)

func TestCargoEquivalentTOMLSyntax(t *testing.T) {
	for _, content := range []string{
		"[[package]] # comment\nname = \"sample\" # name\nversion = \"1.2.3\" # version\nsource = \"sparse+https://index.crates.io/\" # source\n",
		"[[ 'package' ]]\n'name' = 'sample'\n\"version\" = \"1.2.3\"\nsource = 'sparse+https://index.crates.io/'",
		"[[package]]\nname = \"sam\\u0070le\"\nversion = \"1.2.3\"\nsource = \"sparse+https://index.crates.io/\"\n",
	} {
		path := filepath.Join(t.TempDir(), "Cargo.lock")
		writeFile(t, path, content)
		refs, err := ParseCargo(Target{Path: path})
		require.NoError(t, err)
		require.Equal(t, []PackageRef{{Ecosystem: intel.EcosystemCargo, Name: "sample", Version: "1.2.3", Path: path, Source: "Cargo.lock"}}, refs)
	}
}

func TestCargoUnknownTablesAndMultilineData(t *testing.T) {
	content := `version = 4
notes = '''
[[package]]
name = "phantom"
version = "9.9.9"
source = "sparse+https://index.crates.io/"
'''
[[package]]
name = "sample"
version = "1.2.3"
source = "sparse+https://index.crates.io/"
[package.metadata]
name = "not-the-package"
version = "9.9.9"
[[package]]
name = "sample"
version = "1.2.3"
source = "registry+https://private.example/index"
[[Package]]
name = "wrong-case"
version = "1.2.3"
source = "sparse+https://index.crates.io/"
`
	path := filepath.Join(t.TempDir(), "Cargo.lock")
	writeFile(t, path, content)
	refs, err := ParseCargo(Target{Path: path})
	require.NoError(t, err)
	require.Len(t, refs, 1)
	require.Equal(t, "sample", refs[0].Name)
	require.Equal(t, "1.2.3", refs[0].Version)
}

func TestCargoInvalidDocumentReturnsNoPartialPackages(t *testing.T) {
	valid := "[[package]]\nname='sample'\nversion='1.2.3'\nsource='sparse+https://index.crates.io/'\n"
	for _, suffix := range []string{"name='duplicate'", "garbage = \"unterminated", "[[package]]\nname=123", "[[package]]\nsource=false", "[[package]]\nversion={ value='1.0.0' }"} {
		path := filepath.Join(t.TempDir(), "Cargo.lock")
		writeFile(t, path, valid+suffix)
		refs, err := ParseCargo(Target{Path: path})
		require.Error(t, err)
		require.Nil(t, refs)
	}
}

func TestCargoRunnerEquivalentSyntaxPreservesHit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Cargo.lock")
	writeFile(t, path, "[[package]] # valid comment\nname='sample'\nversion='1.2.3'\nsource='sparse+https://index.crates.io/'\n")
	runner := Runner{Matcher: intel.NewMatcher(intel.Snapshot{Records: []intel.Record{{ID: "MAL-CARGO-FIXTURE", Ecosystem: intel.EcosystemCargo, Name: "sample", Kind: intel.KindMalicious, Versions: []string{"1.2.3"}}}})}
	target := Target{Ecosystem: intel.EcosystemCargo, Path: path, Source: "Cargo.lock"}
	result, err := runner.Run([]Target{target})
	require.NoError(t, err)
	require.Len(t, result.Hits, 1)
	require.Equal(t, 1, result.Ecosystems[0].PackagesRead)
	require.Equal(t, "MAL-CARGO-FIXTURE", result.Hits[0].Record.ID)
	bad := filepath.Join(t.TempDir(), "Cargo.lock")
	writeFile(t, bad, "name = \"unterminated")
	result, err = runner.Run([]Target{target, {Ecosystem: intel.EcosystemCargo, Path: bad, Source: "Cargo.lock"}})
	require.Error(t, err)
	require.Nil(t, result)
}

func TestCargoInputBoundaries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Cargo.lock")
	f, err := os.Create(path)
	require.NoError(t, err)
	require.NoError(t, f.Truncate(maxManifestBytes+1))
	require.NoError(t, f.Close())
	refs, err := ParseCargo(Target{Path: path})
	require.ErrorContains(t, err, "limit")
	require.Nil(t, refs)
	for _, n := range []int{15, 16, 17} {
		r := strings.NewReader(strings.Repeat(" ", n))
		b, err := readBoundedManifestBytes(r, 16, "Cargo.lock")
		if n > 16 {
			require.Error(t, err)
			require.Nil(t, b)
		} else {
			require.NoError(t, err)
			require.Len(t, b, n)
		}
	}
	want := errors.New("interrupted")
	b, err := readBoundedManifestBytes(io.MultiReader(strings.NewReader("# comment"), nugetFailingReader{err: want}), 32, "Cargo.lock")
	require.ErrorIs(t, err, want)
	require.Nil(t, b)
}

func TestCargoMetadataDoesNotChangeIdentity(t *testing.T) {
	// Small compatibility fixture, not a load test: arbitrary metadata must not
	// enter the package identity map or require whole-document decoding.
	var input strings.Builder
	input.WriteString("version=4\n[metadata]\n")
	for i := 0; i < 64; i++ {
		fmt.Fprintf(&input, "key%d='ignored'\n", i)
	}
	input.WriteString("[[package]]\nname='sample'\nversion='1.2.3'\nsource='sparse+https://index.crates.io/'\n")
	refs, err := parseCargoBytes([]byte(input.String()), "Cargo.lock")
	require.NoError(t, err)
	require.Len(t, refs, 1)
	require.Equal(t, "sample", refs[0].Name)
}

func TestCargoInvalidIdentityShapesFailLoudly(t *testing.T) {
	for _, content := range []string{
		"package = [{ name='sample' }]", // Cargo uses [[package]] tables.
		"[package]\nname='sample'",
		"[[package]]\nname.value='sample'",
		"[[package]]\nname='sample'\nversion='1.2.3'\nsource='sparse+https://index.crates.io/'\n[package.name]\nvalue='other'",
	} {
		refs, err := parseCargoBytes([]byte(content), "Cargo.lock")
		require.Error(t, err)
		require.Nil(t, refs)
	}
}

func TestCargoSyntaxErrorDoesNotEchoInput(t *testing.T) {
	refs, err := parseCargoBytes([]byte("[[package]]\nname = secretFixtureTOKEN"), "Cargo.lock")
	require.Nil(t, refs)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "secretFixtureTOKEN")
}
