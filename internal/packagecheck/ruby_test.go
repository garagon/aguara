package packagecheck

import (
	"path/filepath"
	"testing"

	"github.com/garagon/aguara/internal/intel"
)

func TestParseRuby_OnlyTopLevelSpecsFromGEMSection(t *testing.T) {
	target := Target{
		Ecosystem: intel.EcosystemRubyGems,
		Path:      filepath.Join("testdata", "ruby-compromised", "Gemfile.lock"),
		Source:    "Gemfile.lock",
	}
	refs, err := ParseRuby(target)
	if err != nil {
		t.Fatalf("ParseRuby: %v", err)
	}
	want := map[string]string{
		"rails":           "7.1.3",
		"rack":            "3.0.8",
		"compromised-gem": "2.0.0",
		"nokogiri":        "1.16.2-arm64-darwin",
	}
	if len(refs) != len(want) {
		t.Fatalf("refs = %d, want %d (refs=%+v)", len(refs), len(want), refs)
	}
	for _, r := range refs {
		v, ok := want[r.Name]
		if !ok {
			t.Errorf("unexpected gem %q", r.Name)
			continue
		}
		if r.Version != v {
			t.Errorf("gem %q: version = %q, want %q", r.Name, r.Version, v)
		}
		if r.Source != "Gemfile.lock" {
			t.Errorf("gem %q: source = %q, want Gemfile.lock", r.Name, r.Source)
		}
		if r.Ecosystem != intel.EcosystemRubyGems {
			t.Errorf("gem %q: ecosystem = %q, want RubyGems", r.Name, r.Ecosystem)
		}
	}
}

func TestParseRuby_IgnoresDependencyConstraints(t *testing.T) {
	// Lines like `      activesupport (= 7.1.3)` (6-space indent)
	// are dependency constraints, not installed gems. They must
	// NOT show up as refs.
	refs, _ := ParseRuby(Target{
		Ecosystem: intel.EcosystemRubyGems,
		Path:      filepath.Join("testdata", "ruby-compromised", "Gemfile.lock"),
		Source:    "Gemfile.lock",
	})
	for _, r := range refs {
		if r.Name == "activesupport" || r.Name == "actionpack" || r.Name == "rake" {
			t.Errorf("dependency constraint leaked as installed gem: %+v", r)
		}
	}
}

func TestParseRuby_IgnoresGITAndOtherSections(t *testing.T) {
	// `GIT specs:` entries are not RubyGems-registry gems; they
	// must not surface. PLATFORMS / DEPENDENCIES / BUNDLED WITH
	// lines must also be skipped.
	refs, _ := ParseRuby(Target{
		Ecosystem: intel.EcosystemRubyGems,
		Path:      filepath.Join("testdata", "ruby-compromised", "Gemfile.lock"),
		Source:    "Gemfile.lock",
	})
	for _, r := range refs {
		if r.Name == "git-only-gem" {
			t.Errorf("GIT-source gem leaked into RubyGems refs: %+v", r)
		}
		if r.Name == "arm64-darwin-23" || r.Name == "ruby" {
			t.Errorf("PLATFORMS section leaked: %+v", r)
		}
		if r.Version == "2.5.3" {
			t.Errorf("BUNDLED WITH leaked: %+v", r)
		}
	}
}

func TestParseRuby_PreservesPlatformSpecificVersion(t *testing.T) {
	// `nokogiri (1.16.2-arm64-darwin)` is a valid installed gem
	// with a platform suffix. The parser must keep the full
	// version string intact.
	refs, _ := ParseRuby(Target{
		Ecosystem: intel.EcosystemRubyGems,
		Path:      filepath.Join("testdata", "ruby-compromised", "Gemfile.lock"),
		Source:    "Gemfile.lock",
	})
	var got string
	for _, r := range refs {
		if r.Name == "nokogiri" {
			got = r.Version
		}
	}
	if got != "1.16.2-arm64-darwin" {
		t.Errorf("nokogiri version = %q, want 1.16.2-arm64-darwin", got)
	}
}

func TestParseRuby_EmptyLockfileReturnsEmpty(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "Gemfile.lock")
	writeFile(t, path, "")
	refs, err := ParseRuby(Target{Ecosystem: intel.EcosystemRubyGems, Path: path, Source: "Gemfile.lock"})
	if err != nil {
		t.Fatalf("ParseRuby: %v", err)
	}
	if len(refs) != 0 {
		t.Errorf("empty Gemfile.lock should produce zero refs, got %+v", refs)
	}
}

func TestParseRuby_LowercasesGemName(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "Gemfile.lock")
	writeFile(t, path, "GEM\n  remote: https://rubygems.org/\n  specs:\n    SomeGem (1.0.0)\n\nBUNDLED WITH\n   2.5.3\n")
	refs, _ := ParseRuby(Target{Ecosystem: intel.EcosystemRubyGems, Path: path, Source: "Gemfile.lock"})
	if len(refs) != 1 || refs[0].Name != "somegem" {
		t.Errorf("expected one lowercased somegem ref, got %+v", refs)
	}
}
