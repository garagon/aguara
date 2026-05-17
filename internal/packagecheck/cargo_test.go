package packagecheck

import (
	"path/filepath"
	"testing"

	"github.com/garagon/aguara/internal/intel"
)

func TestParseCargo_RegistryOnly(t *testing.T) {
	target := Target{
		Ecosystem: intel.EcosystemCargo,
		Path:      filepath.Join("testdata", "cargo-compromised", "Cargo.lock"),
		Source:    "Cargo.lock",
	}
	refs, err := ParseCargo(target)
	if err != nil {
		t.Fatalf("ParseCargo: %v", err)
	}
	// Expected crates: the three git-based crates.io registry
	// entries plus the one sparse-protocol crates.io entry. The
	// private-registry crates and the git/path/workspace entries
	// must NOT appear.
	want := map[string]string{
		"innocent-crate":    "0.1.0",
		"compromised-crate": "1.2.3",
		"with-deps":         "0.5.0",
		"sparse-crate":      "2.0.0",
	}
	if len(refs) != len(want) {
		t.Fatalf("refs = %d, want %d (refs=%+v)", len(refs), len(want), refs)
	}
	for _, r := range refs {
		if r.Ecosystem != intel.EcosystemCargo {
			t.Errorf("ref %q: ecosystem = %q, want crates.io", r.Name, r.Ecosystem)
		}
		if r.Source != "Cargo.lock" {
			t.Errorf("ref %q: source = %q, want Cargo.lock", r.Name, r.Source)
		}
		v, ok := want[r.Name]
		if !ok {
			t.Errorf("unexpected crate %q (probably a non-crates.io leak)", r.Name)
			continue
		}
		if r.Version != v {
			t.Errorf("crate %q: version = %q, want %q", r.Name, r.Version, v)
		}
	}
}

func TestParseCargo_ExcludesPrivateRegistries(t *testing.T) {
	// Private Cargo registries (Cloudsmith, JFrog Artifactory,
	// AWS CodeArtifact, internal mirrors) all use the same
	// `registry+<URL>` shape that the public crates.io index
	// uses. A naive `strings.HasPrefix("registry+")` would
	// emit those crates against the crates.io OSV ecosystem
	// and false-positive on any name collision with a public
	// advisory (e.g. a private `serde 1.0.197` matching a
	// real crates.io `serde 1.0.197` malicious entry).
	//
	// The cargo-compromised fixture has two private-registry
	// crates with names that look real (`private-mirror-crate`,
	// `jfrog-mirror-crate`) and one that uses a verbatim
	// crates.io name (`compromised-crate`) under the public
	// index. Only the public-index entry must come back.
	refs, err := ParseCargo(Target{
		Ecosystem: intel.EcosystemCargo,
		Path:      filepath.Join("testdata", "cargo-compromised", "Cargo.lock"),
		Source:    "Cargo.lock",
	})
	if err != nil {
		t.Fatalf("ParseCargo: %v", err)
	}
	for _, r := range refs {
		switch r.Name {
		case "private-mirror-crate":
			t.Errorf("private registry crate leaked: %+v", r)
		case "jfrog-mirror-crate":
			t.Errorf("JFrog registry crate leaked: %+v", r)
		}
	}
}

func TestParseCargo_AcceptsSparseCratesIOSource(t *testing.T) {
	// `sparse+https://index.crates.io/` is the Cargo 1.70+
	// sparse-protocol form for the public crates.io index.
	// The allowlist must include it so newer lockfiles do
	// not silently drop every public crate.
	refs, err := ParseCargo(Target{
		Ecosystem: intel.EcosystemCargo,
		Path:      filepath.Join("testdata", "cargo-compromised", "Cargo.lock"),
		Source:    "Cargo.lock",
	})
	if err != nil {
		t.Fatalf("ParseCargo: %v", err)
	}
	var foundSparse bool
	for _, r := range refs {
		if r.Name == "sparse-crate" && r.Version == "2.0.0" {
			foundSparse = true
		}
	}
	if !foundSparse {
		t.Errorf("sparse+https://index.crates.io/ entry was dropped (refs=%+v)", refs)
	}
}

func TestIsCratesIORegistrySource_TableDriven(t *testing.T) {
	tests := []struct {
		source string
		want   bool
	}{
		// Public crates.io, both protocols.
		{"registry+https://github.com/rust-lang/crates.io-index", true},
		{"sparse+https://index.crates.io/", true},
		// Private registries that share the `registry+` prefix.
		{"registry+https://private.example.com/index", false},
		{"registry+https://example.jfrog.io/cargo-local", false},
		{"registry+https://artifactory.example.org/cargo", false},
		// Git / path / empty (the parser's other rejection paths
		// also drop these, but isCratesIORegistrySource must say
		// no in isolation).
		{"git+https://github.com/foo/bar?rev=abc#abc", false},
		{"", false},
		// Defensive: small typos / variants that look like
		// crates.io but are not the canonical strings.
		{"registry+https://github.com/rust-lang/crates.io-index/", false},
		{"sparse+https://INDEX.crates.io/", false},
	}
	for _, tc := range tests {
		t.Run(tc.source, func(t *testing.T) {
			if got := isCratesIORegistrySource(tc.source); got != tc.want {
				t.Errorf("isCratesIORegistrySource(%q) = %v, want %v", tc.source, got, tc.want)
			}
		})
	}
}

func TestParseCargo_ExcludesGitAndPathDeps(t *testing.T) {
	// from-git has source=git+..., my-app has no source. Both
	// must NOT appear in refs even though their [[package]] block
	// is well-formed.
	refs, err := ParseCargo(Target{
		Ecosystem: intel.EcosystemCargo,
		Path:      filepath.Join("testdata", "cargo-compromised", "Cargo.lock"),
		Source:    "Cargo.lock",
	})
	if err != nil {
		t.Fatalf("ParseCargo: %v", err)
	}
	for _, r := range refs {
		if r.Name == "from-git" {
			t.Errorf("git-sourced crate leaked: %+v", r)
		}
		if r.Name == "my-app" {
			t.Errorf("source-less workspace member leaked: %+v", r)
		}
	}
}

func TestParseCargo_MalformedBlockDoesNotPanic(t *testing.T) {
	// Truncated Cargo.lock (open [[package]] block, missing
	// version field). The parser should return whatever it could
	// extract without panicking.
	tmp := t.TempDir()
	path := filepath.Join(tmp, "Cargo.lock")
	writeFile(t, path, "[[package]]\nname = \"trunc\"\n")
	refs, err := ParseCargo(Target{Ecosystem: intel.EcosystemCargo, Path: path, Source: "Cargo.lock"})
	if err != nil {
		t.Fatalf("ParseCargo: %v", err)
	}
	if len(refs) != 0 {
		t.Errorf("expected zero refs from version-less block, got %+v", refs)
	}
}

func TestParseCargo_EmptyLockfileReturnsEmpty(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "Cargo.lock")
	writeFile(t, path, "# Generated by Cargo\n")
	refs, err := ParseCargo(Target{Ecosystem: intel.EcosystemCargo, Path: path, Source: "Cargo.lock"})
	if err != nil {
		t.Fatalf("ParseCargo: %v", err)
	}
	if len(refs) != 0 {
		t.Errorf("empty Cargo.lock should produce zero refs, got %+v", refs)
	}
}
