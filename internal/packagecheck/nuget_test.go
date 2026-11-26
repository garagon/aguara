package packagecheck

import (
	"path/filepath"
	"testing"

	"github.com/garagon/aguara/internal/intel"
)

func TestParseNuGet_LockfileDirectAndTransitiveCrossFramework(t *testing.T) {
	target := Target{
		Ecosystem: intel.EcosystemNuGet,
		Path:      filepath.Join("testdata", "nuget-compromised", "packages.lock.json"),
		Source:    "packages.lock.json",
	}
	refs, err := ParseNuGet(target)
	if err != nil {
		t.Fatalf("ParseNuGet: %v", err)
	}
	// Expected: 3 unique (name, version) pairs after cross-
	// framework dedup. SiblingProject (type: Project) is
	// skipped because it has no `resolved`.
	want := map[string]string{
		"Newtonsoft.Json": "13.0.3",
		"Serilog":         "3.1.1",
		"Microsoft.Extensions.Logging.Abstractions": "8.0.0",
	}
	if len(refs) != len(want) {
		t.Fatalf("refs = %d, want %d (refs=%+v)", len(refs), len(want), refs)
	}
	for _, r := range refs {
		v, ok := want[r.Name]
		if !ok {
			t.Errorf("unexpected package %q", r.Name)
			continue
		}
		if r.Version != v {
			t.Errorf("package %q: version = %q, want %q", r.Name, r.Version, v)
		}
		if r.Source != "packages.lock.json" {
			t.Errorf("package %q: source = %q, want packages.lock.json", r.Name, r.Source)
		}
	}
}

func TestParseNuGet_LockfileSkipsEntriesWithoutResolved(t *testing.T) {
	refs, _ := ParseNuGet(Target{
		Ecosystem: intel.EcosystemNuGet,
		Path:      filepath.Join("testdata", "nuget-compromised", "packages.lock.json"),
		Source:    "packages.lock.json",
	})
	for _, r := range refs {
		if r.Name == "SiblingProject" {
			t.Errorf("type:Project entry without `resolved` leaked: %+v", r)
		}
	}
}

func TestParseNuGet_LockfileMalformedJSONErrors(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "packages.lock.json")
	writeFile(t, path, "{not json")
	_, err := ParseNuGet(Target{Ecosystem: intel.EcosystemNuGet, Path: path, Source: "packages.lock.json"})
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestParseNuGet_CsprojAttributeAndChildVersion(t *testing.T) {
	target := Target{
		Ecosystem: intel.EcosystemNuGet,
		Path:      filepath.Join("testdata", "nuget-compromised", "MyApp.csproj"),
		Source:    "csproj",
	}
	refs, err := ParseNuGet(target)
	if err != nil {
		t.Fatalf("ParseNuGet: %v", err)
	}
	// Expected: 4 emitted (3 Include + 1 Update). The
	// Unresolved.Prop entry skips because $(UndefinedVersion)
	// has no PropertyGroup binding.
	want := map[string]string{
		"Newtonsoft.Json":              "13.0.3",
		"Serilog":                      "3.1.1",
		"Microsoft.Extensions.Logging": "8.0.0",
		"Polly":                        "8.2.0",
	}
	if len(refs) != len(want) {
		t.Fatalf("refs = %d, want %d (refs=%+v)", len(refs), len(want), refs)
	}
	for _, r := range refs {
		v, ok := want[r.Name]
		if !ok {
			t.Errorf("unexpected package %q (probably unresolved property leak)", r.Name)
			continue
		}
		if r.Version != v {
			t.Errorf("package %q: version = %q, want %q", r.Name, r.Version, v)
		}
		if r.Source != "csproj" {
			t.Errorf("package %q: source = %q, want csproj", r.Name, r.Source)
		}
	}
}

func TestParseNuGet_CsprojSkipsUnresolvedProperty(t *testing.T) {
	refs, _ := ParseNuGet(Target{
		Ecosystem: intel.EcosystemNuGet,
		Path:      filepath.Join("testdata", "nuget-compromised", "MyApp.csproj"),
		Source:    "csproj",
	})
	for _, r := range refs {
		if r.Name == "Unresolved.Prop" {
			t.Errorf("unresolved $(UndefinedVersion) leaked: %+v", r)
		}
	}
}

func TestParseNuGet_CsprojExactRangeReadsTheVersion(t *testing.T) {
	// "[1.2.3]" is NuGet's exact-match notation; ranges and floating
	// versions keep their literal spelling and match nothing.
	path := filepath.Join(t.TempDir(), "App.csproj")
	writeFile(t, path, `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>
<PackageReference Include="Exact.Pkg" Version="[1.2.3]" />
<PackageReference Include="Spaced.Pkg" Version="[ 2.0.0 ]" />
<PackageReference Include="Range.Pkg" Version="[1.0,2.0)" />
<PackageReference Include="Open.Pkg" Version="[1.0,]" />
</ItemGroup></Project>`)
	refs, err := ParseNuGet(Target{Ecosystem: intel.EcosystemNuGet, Path: path, Source: "csproj"})
	if err != nil {
		t.Fatalf("ParseNuGet: %v", err)
	}
	// Ranges select whatever a feed offers at restore time: unpinned.
	want := map[string]string{"Exact.Pkg": "1.2.3", "Spaced.Pkg": "2.0.0", "Range.Pkg": "unpinned [1.0,2.0)", "Open.Pkg": "unpinned [1.0,]"}
	if len(refs) != len(want) {
		t.Fatalf("refs = %+v, want %d", refs, len(want))
	}
	for _, r := range refs {
		got := r.Version
		if r.Unpinned {
			got = "unpinned " + r.Constraint
		}
		if want[r.Name] != got {
			t.Errorf("%s: version = %q, want %q", r.Name, got, want[r.Name])
		}
	}
}

// Central package management: versions come from VersionOverride or the
// nearest Directory.Packages.props inside the checked root; floating,
// range and missing versions are unpinned unless packages.lock.json
// records the restore.
func TestParseNuGet_CentralPackageManagement(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "Directory.Packages.props"), `<Project>
<PropertyGroup><ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally><SerilogVersion>3.1.1</SerilogVersion></PropertyGroup>
<ItemGroup>
<PackageVersion Include="Newtonsoft.Json" Version="13.0.3" />
<PackageVersion Include="Serilog" Version="$(SerilogVersion)" />
<PackageVersion Include="Floating.Pkg" Version="2.*" />
<PackageVersion Include="Overridden" Version="1.0.0" />
<GlobalPackageReference Include="Analyzers.Pkg" Version="4.0.0" />
</ItemGroup></Project>`)
	proj := filepath.Join(root, "src", "App", "App.csproj")
	writeFile(t, proj, `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>
<PackageReference Include="newtonsoft.json" />
<PackageReference Include="Serilog" />
<PackageReference Include="Floating.Pkg" />
<PackageReference Include="Overridden" VersionOverride="1.5.0" />
<PackageReference Include="Not.Central" />
</ItemGroup></Project>`)
	refs, err := ParseNuGet(Target{Ecosystem: intel.EcosystemNuGet, Path: proj, Source: "csproj", Root: root})
	if err != nil {
		t.Fatalf("ParseNuGet: %v", err)
	}
	got := map[string]string{}
	for _, r := range refs {
		v := r.Version
		if r.Unpinned {
			v = "unpinned " + r.Constraint
		}
		got[r.Name] = v
	}
	want := map[string]string{
		"newtonsoft.json": "13.0.3", "Serilog": "3.1.1", "Floating.Pkg": "unpinned 2.*",
		"Overridden": "1.5.0", "Not.Central": "unpinned ", "Analyzers.Pkg": "4.0.0",
	}
	if len(got) != len(want) {
		t.Fatalf("refs = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}

	// A props file outside the checked root is not read.
	refs, err = ParseNuGet(Target{Ecosystem: intel.EcosystemNuGet, Path: proj, Source: "csproj", Root: filepath.Join(root, "src")})
	if err != nil {
		t.Fatalf("ParseNuGet: %v", err)
	}
	for _, r := range refs {
		if r.Name == "newtonsoft.json" && !r.Unpinned {
			t.Errorf("version read from a props file outside the root: %+v", r)
		}
	}

	// packages.lock.json beside the project records the restore, so the
	// project file's open versions add nothing unpinned.
	writeFile(t, filepath.Join(root, "src", "App", "packages.lock.json"), `{"version":1,"dependencies":{}}`)
	refs, err = ParseNuGet(Target{Ecosystem: intel.EcosystemNuGet, Path: proj, Source: "csproj", Root: root})
	if err != nil {
		t.Fatalf("ParseNuGet: %v", err)
	}
	for _, r := range refs {
		if r.Unpinned {
			t.Errorf("unpinned ref beside packages.lock.json: %+v", r)
		}
	}
}

func TestParseNuGet_FsprojAndVbprojShareParser(t *testing.T) {
	for _, c := range []struct{ dir, file, source, name, version string }{
		{"nuget-fsproj", "FsApp.fsproj", "fsproj", "FSharp.Core", "8.0.100"},
		{"nuget-vbproj", "VbApp.vbproj", "vbproj", "Microsoft.VisualBasic", "10.3.0"},
	} {
		t.Run(c.source, func(t *testing.T) {
			refs, err := ParseNuGet(Target{
				Ecosystem: intel.EcosystemNuGet,
				Path:      filepath.Join("testdata", c.dir, c.file),
				Source:    c.source,
			})
			if err != nil {
				t.Fatalf("ParseNuGet: %v", err)
			}
			if len(refs) != 1 || refs[0].Name != c.name || refs[0].Version != c.version {
				t.Errorf("got %+v, want one %s %s ref", refs, c.name, c.version)
			}
			if refs[0].Source != c.source {
				t.Errorf("source = %q, want %q", refs[0].Source, c.source)
			}
		})
	}
}

func TestParseNuGet_CsprojMalformedXMLErrors(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "Bad.csproj")
	writeFile(t, path, "<Project><Unclosed")
	_, err := ParseNuGet(Target{Ecosystem: intel.EcosystemNuGet, Path: path, Source: "csproj"})
	if err == nil {
		t.Fatal("expected error for malformed XML")
	}
}

func TestParseNuGet_RejectsUnknownSource(t *testing.T) {
	_, err := ParseNuGet(Target{Ecosystem: intel.EcosystemNuGet, Path: "/dev/null", Source: "Cargo.lock"})
	if err == nil {
		t.Fatal("expected error for unsupported source")
	}
}

func TestResolveMSBuildProperty(t *testing.T) {
	props := map[string]string{"SerilogVersion": "3.1.1", "EmptyProp": ""}

	t.Run("literal returns unchanged", func(t *testing.T) {
		v, ok := resolveMSBuildProperty("8.0.0", props)
		if !ok || v != "8.0.0" {
			t.Errorf("got (%q, %v), want (8.0.0, true)", v, ok)
		}
	})
	t.Run("known property resolves", func(t *testing.T) {
		v, ok := resolveMSBuildProperty("$(SerilogVersion)", props)
		if !ok || v != "3.1.1" {
			t.Errorf("got (%q, %v), want (3.1.1, true)", v, ok)
		}
	})
	t.Run("unknown property fails", func(t *testing.T) {
		_, ok := resolveMSBuildProperty("$(Unknown)", props)
		if ok {
			t.Errorf("expected unresolved property to fail")
		}
	})
	t.Run("empty property fails", func(t *testing.T) {
		_, ok := resolveMSBuildProperty("$(EmptyProp)", props)
		if ok {
			t.Errorf("expected empty property to fail")
		}
	})
}
