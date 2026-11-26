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

func nugetRefs(t *testing.T, files map[string]string, project string) []string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		writeFile(t, filepath.Join(root, filepath.FromSlash(name)), content)
	}
	refs, err := ParseNuGet(Target{Ecosystem: intel.EcosystemNuGet, Path: filepath.Join(root, filepath.FromSlash(project)), Source: "csproj", Root: root})
	require.NoError(t, err)
	return refSummary(refs)
}

// A version MSBuild takes from a property the project file does not
// define (one set in Directory.Build.props or on the command line) is not
// known here, so the reference counts as unpinned instead of vanishing.
func TestNuGetUndefinedPropertyVersionIsUnpinned(t *testing.T) {
	got := nugetRefs(t, map[string]string{
		"App.csproj": `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><Known>1.2.3</Known></PropertyGroup><ItemGroup>
<PackageReference Include="Uses.Known" Version="$(Known)" />
<PackageReference Include="Uses.Undefined" Version="$(Undefined)" />
</ItemGroup></Project>`,
	}, "App.csproj")
	require.Equal(t, []string{"Uses.Known 1.2.3", "Uses.Undefined ($(Undefined))"}, got)
}

// Conditional PackageVersion items can declare several versions for one
// package; each is checked, and each is a pin.
func TestNuGetEveryCentralVersionOfAPackageIsRead(t *testing.T) {
	got := nugetRefs(t, map[string]string{
		"Directory.Packages.props": `<Project><ItemGroup>
<PackageVersion Include="Newtonsoft.Json" Version="12.0.1" Condition="'$(TargetFramework)' == 'net48'" />
<PackageVersion Include="Newtonsoft.Json" Version="13.0.1" Condition="'$(TargetFramework)' != 'net48'" />
<PackageVersion Include="newtonsoft.json" Version="13.0.1" />
</ItemGroup></Project>`,
		"src/App/App.csproj": `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Newtonsoft.Json" /></ItemGroup></Project>`,
	}, "src/App/App.csproj")
	require.Equal(t, []string{"Newtonsoft.Json 12.0.1", "Newtonsoft.Json 13.0.1"}, got)
}

// ManagePackageVersionsCentrally set to false turns central versions
// off: the project file's value wins over the props file's, as MSBuild
// evaluates the project after the props it imports.
func TestNuGetCentralManagementTurnedOff(t *testing.T) {
	props := func(manage string) string {
		group := ""
		if manage != "" {
			group = "<PropertyGroup><ManagePackageVersionsCentrally>" + manage + "</ManagePackageVersionsCentrally></PropertyGroup>"
		}
		return `<Project>` + group + `<ItemGroup><PackageVersion Include="Pkg" Version="2.0.0" /><GlobalPackageReference Include="Global.Pkg" Version="1.0.0" /></ItemGroup></Project>`
	}
	project := func(manage string) string {
		group := ""
		if manage != "" {
			group = "<PropertyGroup><ManagePackageVersionsCentrally>" + manage + "</ManagePackageVersionsCentrally></PropertyGroup>"
		}
		return `<Project Sdk="Microsoft.NET.Sdk">` + group + `<ItemGroup><PackageReference Include="Pkg" VersionOverride="3.0.0" /><PackageReference Include="Other" /></ItemGroup></Project>`
	}
	on := []string{"Global.Pkg 1.0.0", "Other ()", "Pkg 3.0.0"}
	off := []string{"Other ()", "Pkg ()"}
	for _, tc := range []struct {
		props, project string
		want           []string
	}{
		{"", "", on},
		{"true", "", on},
		{"false", "", off},
		{" False ", "", off},
		{"true", "false", off},
		{"false", "true", on},
	} {
		got := nugetRefs(t, map[string]string{
			"Directory.Packages.props": props(tc.props),
			"src/App/App.csproj":       project(tc.project),
		}, "src/App/App.csproj")
		require.Equalf(t, tc.want, got, "props %q, project %q", tc.props, tc.project)
	}
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
