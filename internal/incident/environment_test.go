package incident

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/garagon/aguara/internal/intel"
	"github.com/stretchr/testify/require"
)

func writeDistInfo(t *testing.T, site, dir, metadata string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Join(site, dir), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(site, dir, "METADATA"), []byte(metadata), 0o644))
}

func environmentOverride() *IntelOverride {
	return &IntelOverride{Snapshots: []intel.Snapshot{{
		SchemaVersion: intel.CurrentSchemaVersion,
		Records: []intel.Record{
			{ID: "MAL-ENV-1", Ecosystem: intel.EcosystemPyPI, Name: "evil-pkg", Kind: intel.KindMalicious, Versions: []string{"1.0"}},
			{ID: "GHSA-env-alias", Ecosystem: intel.EcosystemPyPI, Name: "evil_pkg", Kind: intel.KindMalicious, Versions: []string{"1.0.0"}},
		},
	}}}
}

func TestCheckEnvironmentMatchesWithoutHostState(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".config", "sysmon"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(home, ".config", "sysmon", "sysmon.py"), []byte("x"), 0o644))

	site := t.TempDir()
	writeDistInfo(t, site, "Evil_Pkg-1.0.0.dist-info", "Metadata-Version: 2.1\nName: Evil_Pkg\nVersion: 1.0.0\n\nbody\n")
	writeDistInfo(t, site, "six-1.16.0.dist-info", "Metadata-Version: 2.1\nName: six\nVersion: 1.16.0\n")
	require.NoError(t, os.WriteFile(filepath.Join(site, "payload.pth"), []byte("import os; os.system('x')\n"), 0o644))

	res, err := CheckEnvironment(CheckOptions{Path: site, Intel: environmentOverride()})
	require.NoError(t, err)
	require.Equal(t, 2, res.PackagesRead)
	require.Zero(t, res.PthScanned, "the .pth heuristic stays in the installed-environment check")
	require.Len(t, res.Ecosystems, 1)
	require.Equal(t, "site-packages", res.Ecosystems[0].Source)
	require.Equal(t, 1, res.Ecosystems[0].FindingsCount)
	require.Empty(t, res.Credentials, "credential files are host state, not environment evidence")
	require.Len(t, res.Findings, 1, "package evidence only: no persistence, cache or .pth findings")
	require.Contains(t, res.Findings[0].Title, "evil_pkg 1.0.0 is a known compromised package (MAL-ENV-1, GHSA-env-alias)",
		"PEP 503 name and PEP 440 version matching, every matching advisory ID listed")

	// The installed-environment check keeps reading host state and .pth
	// files, and lists every advisory ID the same way.
	legacy, err := Check(CheckOptions{Path: site, Intel: environmentOverride()})
	require.NoError(t, err)
	var titles []string
	for _, f := range legacy.Findings {
		titles = append(titles, f.Title)
	}
	require.Contains(t, titles, res.Findings[0].Title)
	require.Contains(t, strings.Join(titles, "\n"), "Persistence artifact")
	require.Contains(t, strings.Join(titles, "\n"), "payload.pth contains executable code")
}

func TestCheckEnvironmentErrors(t *testing.T) {
	_, err := CheckEnvironment(CheckOptions{})
	require.Error(t, err)
	_, err = CheckEnvironment(CheckOptions{Path: filepath.Join(t.TempDir(), "missing")})
	require.Error(t, err)

	site := t.TempDir()
	for _, d := range []string{"a-1.dist-info", "b-1.dist-info", "c-1.dist-info"} {
		writeDistInfo(t, site, d, "Name: x\nVersion: 1\n")
	}
	_, err = readInstalledPackagesLimit(site, 2)
	require.ErrorContains(t, err, "more than 2")
	pkgs, err := readInstalledPackagesLimit(site, 3)
	require.NoError(t, err)
	require.Len(t, pkgs, 3)
}

func TestInstalledReadsAreBounded(t *testing.T) {
	site := t.TempDir()
	// Name and Version are found in the bounded header prefix even when
	// the file is far larger than the read limit.
	writeDistInfo(t, site, "big-1.0.dist-info", "Name: big\nVersion: 1.0\n\n"+strings.Repeat("x", maxMetadataBytes+10))
	pkg := parseMetadata(filepath.Join(site, "big-1.0.dist-info", "METADATA"))
	require.Equal(t, "big", pkg.Name)
	require.Equal(t, "1.0", pkg.Version)

	// An oversized .pth with no executable content in the inspected
	// prefix is reported, not passed as clean.
	big := filepath.Join(site, "huge.pth")
	require.NoError(t, os.WriteFile(big, []byte(strings.Repeat("/some/dir\n", maxPthBytes/10+10)), 0o644))
	findings := checkPthFile(big)
	require.Len(t, findings, 1)
	require.Equal(t, SevWarning, findings[0].Severity)
	require.Contains(t, findings[0].Title, "inspection limit")

	small := filepath.Join(site, "paths.pth")
	require.NoError(t, os.WriteFile(small, []byte("/some/dir\n"), 0o644))
	require.Empty(t, checkPthFile(small))
}
