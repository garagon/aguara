package packagecheck

import (
	"path/filepath"
	"testing"

	"github.com/garagon/aguara/internal/intel"
)

func TestParseComposer_RuntimeAndDevPackages(t *testing.T) {
	target := Target{
		Ecosystem: intel.EcosystemPackagist,
		Path:      filepath.Join("testdata", "composer-compromised", "composer.lock"),
		Source:    "composer.lock",
	}
	refs, err := ParseComposer(target)
	if err != nil {
		t.Fatalf("ParseComposer: %v", err)
	}
	// 2 runtime + 2 dev = 4 refs. Names are lower-cased even when
	// the lockfile mixes case (`Monolog/Monolog`).
	if len(refs) != 4 {
		t.Fatalf("refs = %d, want 4 (refs=%+v)", len(refs), refs)
	}
	want := map[string]string{
		"monolog/monolog":      "v3.5.0",
		"guzzlehttp/guzzle":    "7.8.1",
		"compromised/dev-tool": "v1.0.0",
		"phpunit/phpunit":      "10.5.0",
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
		if r.Source != "composer.lock" {
			t.Errorf("package %q: source = %q, want composer.lock", r.Name, r.Source)
		}
		if r.Ecosystem != intel.EcosystemPackagist {
			t.Errorf("package %q: ecosystem = %q, want Packagist", r.Name, r.Ecosystem)
		}
	}
}

func TestParseComposer_PreservesRawVersionPrefix(t *testing.T) {
	// composer.lock often carries `v` prefixes (v3.5.0). The
	// parser preserves the raw lockfile string; the matcher
	// compares Composer's normalized form of both spellings.
	refs, err := ParseComposer(Target{
		Ecosystem: intel.EcosystemPackagist,
		Path:      filepath.Join("testdata", "composer-compromised", "composer.lock"),
		Source:    "composer.lock",
	})
	if err != nil {
		t.Fatalf("ParseComposer: %v", err)
	}
	var got string
	for _, r := range refs {
		if r.Name == "monolog/monolog" {
			got = r.Version
		}
	}
	if got != "v3.5.0" {
		t.Errorf("monolog version = %q, want v3.5.0 (raw lockfile value)", got)
	}
}

func TestParseComposer_MalformedJSONReturnsError(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "composer.lock")
	writeFile(t, path, "{not json")
	_, err := ParseComposer(Target{Ecosystem: intel.EcosystemPackagist, Path: path, Source: "composer.lock"})
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestParseComposer_SkipsMissingFields(t *testing.T) {
	// Entries without name or without version are skipped. The
	// matcher needs both to look up an advisory; emitting a ref
	// with one missing would inflate packages_read without ever
	// matching.
	tmp := t.TempDir()
	path := filepath.Join(tmp, "composer.lock")
	writeFile(t, path, `{"packages":[{"name":"ok/pkg","version":"1.0.0"},{"name":"no-version"},{"version":"orphan"}],"packages-dev":[]}`)
	refs, err := ParseComposer(Target{Ecosystem: intel.EcosystemPackagist, Path: path, Source: "composer.lock"})
	if err != nil {
		t.Fatalf("ParseComposer: %v", err)
	}
	if len(refs) != 1 || refs[0].Name != "ok/pkg" {
		t.Errorf("expected one ok/pkg ref, got %+v", refs)
	}
}
