package packagecheck

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/garagon/aguara/internal/intel"
	"github.com/stretchr/testify/require"
)

const cpmProps = `<Project>
<PropertyGroup><ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally></PropertyGroup>
<ItemGroup><PackageVersion Include="Newtonsoft.Json" Version="13.0.1" /></ItemGroup></Project>`

func cpmProject(t *testing.T, root string, n int) []Target {
	t.Helper()
	targets := make([]Target, 0, n)
	for i := 0; i < n; i++ {
		path := filepath.Join(root, "src", fmt.Sprintf("P%d", i), fmt.Sprintf("P%d.csproj", i))
		writeFile(t, path, `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Newtonsoft.Json" /></ItemGroup></Project>`)
		targets = append(targets, Target{Ecosystem: intel.EcosystemNuGet, Path: path, Source: "csproj", Root: root})
	}
	return targets
}

// One Directory.Packages.props applies to every project below it; a run
// reads and parses it once.
func TestNuGetCentralVersionsAreParsedOncePerRun(t *testing.T) {
	root := t.TempDir()
	props := filepath.Join(root, "Directory.Packages.props")
	writeFile(t, props, cpmProps)
	targets := cpmProject(t, root, 3)

	cache := newRunCache()
	first, err := parseTargetDetail(targets[0], cache)
	require.NoError(t, err)
	require.Equal(t, []string{"Newtonsoft.Json 13.0.1"}, refSummary(first.refs))

	// Later projects take the parsed file from the run's cache: a change
	// to the file after the first read is not seen.
	require.NoError(t, os.WriteFile(props, []byte(strings.Replace(cpmProps, "13.0.1", "9.9.9", 1)), 0o600))
	for _, target := range targets[1:] {
		next, err := parseTargetDetail(target, cache)
		require.NoError(t, err)
		require.Equal(t, []string{"Newtonsoft.Json 13.0.1"}, refSummary(next.refs))
	}
	require.Len(t, cache.nugetProps, 1)
}

// A Directory.Packages.props is read under the dependency-manifest size
// limit, not the lockfile one.
func TestNuGetCentralVersionsSizeLimit(t *testing.T) {
	root := t.TempDir()
	entry := `<PackageVersion Include="Pkg.%d" Version="1.0.0" />` + "\n"
	var b strings.Builder
	b.WriteString("<Project><ItemGroup>\n")
	for i := 0; int64(b.Len()) <= maxNuGetPropsBytes; i++ {
		fmt.Fprintf(&b, entry, i)
	}
	b.WriteString("</ItemGroup></Project>\n")
	writeFile(t, filepath.Join(root, "Directory.Packages.props"), b.String())
	targets := cpmProject(t, root, 1)
	_, err := (&Runner{Matcher: intel.NewMatcher(intel.Snapshot{})}).Run(targets)
	require.ErrorContains(t, err, "Directory.Packages.props")
}
