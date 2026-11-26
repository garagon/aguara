package packagecheck

import (
	"path/filepath"
	"testing"

	"github.com/garagon/aguara/internal/intel"
)

func TestParseGoSum_DedupesGoModSuffix(t *testing.T) {
	target := Target{
		Ecosystem: intel.EcosystemGo,
		Path:      filepath.Join("testdata", "go-compromised", "go.sum"),
		Source:    "go.sum",
	}
	refs, err := ParseGo(target)
	if err != nil {
		t.Fatalf("ParseGo: %v", err)
	}
	// 4 lines, 2 unique (module, version) pairs after collapsing
	// the `/go.mod` suffix entries.
	if got, want := len(refs), 2; got != want {
		t.Fatalf("refs = %d, want %d (refs=%+v)", got, want, refs)
	}
	want := map[string]string{
		"example.com/malicious-mod":   "v1.2.3",
		"github.com/stretchr/testify": "v1.10.0",
	}
	for _, r := range refs {
		if r.Ecosystem != intel.EcosystemGo {
			t.Errorf("ref %q: ecosystem = %q, want Go", r.Name, r.Ecosystem)
		}
		if r.Source != "go.sum" {
			t.Errorf("ref %q: source = %q, want go.sum", r.Name, r.Source)
		}
		wantVer, ok := want[r.Name]
		if !ok {
			t.Errorf("unexpected module %q", r.Name)
			continue
		}
		if r.Version != wantVer {
			t.Errorf("module %q: version = %q, want %q", r.Name, r.Version, wantVer)
		}
	}
}

func TestParseGoSum_GoModOnlyEntryStillEmitsPackage(t *testing.T) {
	// A transitive dependency Go resolved only the proxy hash for:
	// only the `/go.mod` line is present. The /go.mod suffix must
	// be stripped and the underlying version kept.
	tmp := t.TempDir()
	sumPath := filepath.Join(tmp, "go.sum")
	writeFile(t, sumPath, "example.com/transit v3.0.0/go.mod h1:fakehash=\n")

	refs, err := ParseGo(Target{Ecosystem: intel.EcosystemGo, Path: sumPath, Source: "go.sum"})
	if err != nil {
		t.Fatalf("ParseGo: %v", err)
	}
	if len(refs) != 1 {
		t.Fatalf("refs = %d, want 1 (refs=%+v)", len(refs), refs)
	}
	if refs[0].Name != "example.com/transit" || refs[0].Version != "v3.0.0" {
		t.Errorf("got %+v, want example.com/transit v3.0.0", refs[0])
	}
}

func TestParseGoMod_SingleLineAndBlockRequires(t *testing.T) {
	target := Target{
		Ecosystem: intel.EcosystemGo,
		Path:      filepath.Join("testdata", "go-mod-only", "go.mod"),
		Source:    "go.mod",
	}
	refs, err := ParseGo(target)
	if err != nil {
		t.Fatalf("ParseGo: %v", err)
	}
	// Expected: 3 from the block + 1 single-line = 4 deps total.
	// `module`, `go`, and both `replace` lines are skipped.
	wantSet := map[string]string{
		"github.com/stretchr/testify": "v1.10.0",
		"example.com/malicious-mod":   "v1.2.3",
		"example.com/other":           "v2.0.0",
		"github.com/spf13/cobra":      "v1.8.0",
	}
	if len(refs) != len(wantSet) {
		t.Fatalf("refs = %d, want %d (refs=%+v)", len(refs), len(wantSet), refs)
	}
	for _, r := range refs {
		ver, ok := wantSet[r.Name]
		if !ok {
			t.Errorf("unexpected module %q", r.Name)
			continue
		}
		if r.Version != ver {
			t.Errorf("module %q: version = %q, want %q", r.Name, r.Version, ver)
		}
		if r.Source != "go.mod" {
			t.Errorf("module %q: source = %q, want go.mod", r.Name, r.Source)
		}
	}
}

func TestParseGoMod_ReplaceLocalDoesNotEmitPackage(t *testing.T) {
	// `replace example.com/old => ./local-fork` must NOT produce a
	// PackageRef. Local replacements have no module-version the
	// matcher could consume.
	for _, ref := range mustParse(t, filepath.Join("testdata", "go-mod-only", "go.mod")) {
		if ref.Name == "example.com/old" || ref.Name == "./local-fork" {
			t.Errorf("local replace leaked into refs: %+v", ref)
		}
	}
}

func TestParseGoMod_ReplaceRegistryNotEmittedInPR2(t *testing.T) {
	// PR #2 skips registry-replace handling. `replace
	// example.com/swapped => example.com/replacement v9.9.9` MUST
	// NOT show up as a require. A follow-up PR will resolve the
	// substitution chain; for now we lock the conservative
	// behaviour so a future change to ParseGo is intentional.
	for _, ref := range mustParse(t, filepath.Join("testdata", "go-mod-only", "go.mod")) {
		if ref.Name == "example.com/swapped" || ref.Name == "example.com/replacement" {
			t.Errorf("replace target leaked into refs: %+v", ref)
		}
	}
}

func TestParseGoMod_StripsInlineComments(t *testing.T) {
	// `example.com/malicious-mod v1.2.3 // indirect` should parse
	// as the module + version with the comment stripped.
	tmp := t.TempDir()
	modPath := filepath.Join(tmp, "go.mod")
	writeFile(t, modPath, "module example.com/x\n\nrequire example.com/mod v1.0.0 // indirect\n")
	refs, err := ParseGo(Target{Ecosystem: intel.EcosystemGo, Path: modPath, Source: "go.mod"})
	if err != nil {
		t.Fatalf("ParseGo: %v", err)
	}
	if len(refs) != 1 || refs[0].Name != "example.com/mod" || refs[0].Version != "v1.0.0" {
		t.Errorf("refs = %+v, want one require example.com/mod v1.0.0", refs)
	}
}

func TestParseGoMod_QuotedModulePathAndVersion(t *testing.T) {
	// go.mod may write a module path or version as a Go string literal.
	tmp := t.TempDir()
	modPath := filepath.Join(tmp, "go.mod")
	writeFile(t, modPath, "module example.com/x\n\nrequire (\n\t\"example.com/quoted\" v1.0.0\n\texample.com/raw `v2.0.0+incompatible`\n)\n")
	refs, err := ParseGo(Target{Ecosystem: intel.EcosystemGo, Path: modPath, Source: "go.mod"})
	if err != nil {
		t.Fatalf("ParseGo: %v", err)
	}
	if len(refs) != 2 || refs[0].Name != "example.com/quoted" || refs[0].Version != "v1.0.0" ||
		refs[1].Name != "example.com/raw" || refs[1].Version != "v2.0.0+incompatible" {
		t.Errorf("refs = %+v, want example.com/quoted v1.0.0 and example.com/raw v2.0.0+incompatible", refs)
	}
}

func TestRunner_GoSumMatchesAdvisoryWithoutLeadingV(t *testing.T) {
	// OSV Go records list "0.69.4"; go.sum writes "v0.69.4", including on
	// the /go.mod hash line. The pair is one finding.
	tmp := t.TempDir()
	sumPath := filepath.Join(tmp, "go.sum")
	writeFile(t, sumPath, "github.com/example/scanner v0.69.4 h1:AAAA=\ngithub.com/example/scanner v0.69.4/go.mod h1:BBBB=\n"+
		"github.com/example/scanner v0.69.40 h1:CCCC=\n")
	runner := &Runner{Matcher: intel.NewMatcher(intel.Snapshot{
		SchemaVersion: intel.CurrentSchemaVersion,
		Records: []intel.Record{{
			ID: "GHSA-GO-BARE", Ecosystem: intel.EcosystemGo, Name: "github.com/example/scanner",
			Kind: intel.KindMalicious, Versions: []string{"0.69.4"},
		}},
	})}
	res, err := runner.Run([]Target{{Ecosystem: intel.EcosystemGo, Path: sumPath, Source: "go.sum"}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Hits) != 1 || res.Hits[0].Ref.Version != "v0.69.4" {
		t.Fatalf("hits = %+v, want one hit on v0.69.4", res.Hits)
	}
}

// A go.sum version with only a `/go.mod` hash was read during version
// selection and never downloaded or built; it matches only advisories
// covering every version. A zip hash, or a go.mod require, makes it a
// version the build uses.
func TestRunner_GoSumGraphOnlyVersions(t *testing.T) {
	const mod = "github.com/example/scanner"
	matcher := intel.NewMatcher(intel.Snapshot{
		SchemaVersion: intel.CurrentSchemaVersion,
		Records: []intel.Record{{
			ID: "GHSA-GO-EXACT", Ecosystem: intel.EcosystemGo, Name: mod,
			Kind: intel.KindMalicious, Versions: []string{"0.69.4"},
		}},
		AllVersions: []intel.AllVersionsEntry{{ID: "MAL-GO-ALL", Ecosystem: intel.EcosystemGo, Name: "github.com/evil/everything"}},
	})
	graphOnly := mod + " v0.69.4/go.mod h1:AAAA=\n" + mod + " v0.69.5 h1:BBBB=\n" + mod + " v0.69.5/go.mod h1:CCCC=\n"
	for _, tc := range []struct {
		name, sum, gomod string
		want             []string
	}{
		{"graph-only compromised version, clean selected", graphOnly,
			"module example.com/app\n\ngo 1.22\n\nrequire " + mod + " v0.69.5\n", nil},
		{"graph-only without a go.mod", graphOnly, "", nil},
		{"zip hash for the compromised version", mod + " v0.69.4 h1:AAAA=\n" + mod + " v0.69.4/go.mod h1:BBBB=\n", "", []string{"v0.69.4"}},
		{"go.mod requires the compromised version", mod + " v0.69.4/go.mod h1:AAAA=\n",
			"module example.com/app\n\ngo 1.22\n\nrequire " + mod + " v0.69.4 // indirect\n", []string{"v0.69.4"}},
		{"go.mod requires a version go.sum lacks", mod + " v0.69.5 h1:BBBB=\n",
			"module example.com/app\n\ngo 1.22\n\nrequire " + mod + " v0.69.4\n", []string{"v0.69.4"}},
		{"graph-only entry of a module malicious in every version", "github.com/evil/everything v1.0.0/go.mod h1:AAAA=\n", "", []string{"v1.0.0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, "go.sum"), tc.sum)
			if tc.gomod != "" {
				writeFile(t, filepath.Join(dir, "go.mod"), tc.gomod)
			}
			targets, err := Discover(dir, []string{intel.EcosystemGo})
			if err != nil || len(targets) != 1 || targets[0].Source != "go.sum" {
				t.Fatalf("targets = %+v, err %v", targets, err)
			}
			res, err := (&Runner{Matcher: matcher}).Run(targets)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			var got []string
			for _, h := range res.Hits {
				got = append(got, h.Ref.Version)
			}
			if len(got) != len(tc.want) || (len(got) == 1 && got[0] != tc.want[0]) {
				t.Errorf("hits = %v, want %v", got, tc.want)
			}
		})
	}
}

// A replace directive does not hide the required module: it is still
// matched, and the ref records what the build uses instead.
func TestParseGoMod_RecordsReplacements(t *testing.T) {
	tmp := t.TempDir()
	modPath := filepath.Join(tmp, "go.mod")
	writeFile(t, modPath, "module example.com/x\n\nrequire (\n\texample.com/a v1.0.0\n\texample.com/b v2.0.0+incompatible\n\texample.com/c v1.1.0\n)\n\n"+
		"replace example.com/a => ../local/a\n\nreplace (\n\texample.com/b v2.0.0+incompatible => example.com/fork/b v2.0.1+incompatible\n\texample.com/c v1.0.0 => example.com/c v1.0.1\n)\n")
	refs, err := ParseGo(Target{Ecosystem: intel.EcosystemGo, Path: modPath, Source: "go.mod"})
	if err != nil {
		t.Fatalf("ParseGo: %v", err)
	}
	want := map[string]string{"example.com/a": "../local/a", "example.com/b": "example.com/fork/b v2.0.1+incompatible", "example.com/c": ""}
	if len(refs) != 3 {
		t.Fatalf("refs = %+v", refs)
	}
	for _, r := range refs {
		if r.Replacement != want[r.Name] {
			t.Errorf("%s: replacement = %q, want %q", r.Name, r.Replacement, want[r.Name])
		}
	}

	// go.sum targets pick the replacements up from the go.mod beside them.
	writeFile(t, filepath.Join(tmp, "go.sum"), "example.com/b v2.0.0+incompatible h1:AAAA=\n")
	refs, err = ParseGo(Target{Ecosystem: intel.EcosystemGo, Path: filepath.Join(tmp, "go.sum"), Source: "go.sum"})
	if err != nil {
		t.Fatalf("ParseGo: %v", err)
	}
	for _, r := range refs {
		if r.Replacement != want[r.Name] {
			t.Errorf("go.sum %s: replacement = %q, want %q", r.Name, r.Replacement, want[r.Name])
		}
	}
}

// go.mod separates a directive from its arguments with any white space,
// and a block's "(" may follow the verb directly. A version go.mod both
// requires and excludes is still reported, marked as excluded.
func TestParseGoMod_DirectiveSpellingAndExcludes(t *testing.T) {
	tmp := t.TempDir()
	modPath := filepath.Join(tmp, "go.mod")
	writeFile(t, modPath, "module example.com/x\n\n"+
		"require\texample.com/tab v1.0.0\n"+
		"require(\n\texample.com/paren v2.0.0\n)\n"+
		"require example.com/excluded v1.1.0\n"+
		"require example.com/kept v1.2.0\n"+
		"exclude\texample.com/excluded v1.1.0\n"+
		"exclude(\n\texample.com/kept v1.0.0 // a lower version only\n\t\"example.com/tab\" \"v1.0.0\"\n)\n")
	for _, target := range []Target{
		{Ecosystem: intel.EcosystemGo, Path: modPath, Source: "go.mod"},
	} {
		refs, err := ParseGo(target)
		if err != nil {
			t.Fatalf("ParseGo: %v", err)
		}
		got := map[string]bool{}
		for _, r := range refs {
			got[r.Name+" "+r.Version] = r.Excluded
		}
		want := map[string]bool{
			"example.com/tab v1.0.0": true, "example.com/paren v2.0.0": false,
			"example.com/excluded v1.1.0": true, "example.com/kept v1.2.0": false,
		}
		if len(got) != len(want) {
			t.Fatalf("refs = %v, want %v", got, want)
		}
		for k, v := range want {
			if ex, ok := got[k]; !ok || ex != v {
				t.Errorf("%s: present %v excluded %v, want excluded %v", k, ok, ex, v)
			}
		}
	}

	// go.sum targets mark the versions the go.mod beside them excludes.
	writeFile(t, filepath.Join(tmp, "go.sum"), "example.com/excluded v1.1.0 h1:AAAA=\nexample.com/excluded v1.1.0/go.mod h1:BBBB=\n")
	refs, err := ParseGo(Target{Ecosystem: intel.EcosystemGo, Path: filepath.Join(tmp, "go.sum"), Source: "go.sum"})
	if err != nil {
		t.Fatalf("ParseGo: %v", err)
	}
	for _, r := range refs {
		if r.Name == "example.com/excluded" && (!r.Excluded || r.GraphOnly) {
			t.Errorf("go.sum excluded ref = %+v", r)
		}
	}
}

func TestParseGo_RejectsUnknownSource(t *testing.T) {
	_, err := ParseGo(Target{Ecosystem: intel.EcosystemGo, Path: "/dev/null", Source: "Cargo.lock"})
	if err == nil {
		t.Fatal("expected error for unsupported source")
	}
}

func mustParse(t *testing.T, path string) []PackageRef {
	t.Helper()
	refs, err := ParseGo(Target{Ecosystem: intel.EcosystemGo, Path: path, Source: filepath.Base(path)})
	if err != nil {
		t.Fatalf("ParseGo: %v", err)
	}
	return refs
}
