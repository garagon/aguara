package packagecheck

import (
	"path/filepath"
	"testing"

	"github.com/garagon/aguara/internal/intel"
)

func TestParseMaven_PomXMLResolvesPropertiesExcludesScopes(t *testing.T) {
	target := Target{
		Ecosystem: intel.EcosystemMaven,
		Path:      filepath.Join("testdata", "maven-compromised", "pom.xml"),
		Source:    "pom.xml",
	}
	refs, err := ParseMaven(target)
	if err != nil {
		t.Fatalf("ParseMaven: %v", err)
	}
	// Expected: 3 emitted (jackson via property, commons-lang3
	// literal, log4j via property). test/provided/system scopes
	// drop their respective deps; the unresolved-placeholder
	// dependency is also dropped.
	want := map[string]string{
		"com.fasterxml.jackson.core:jackson-databind": "2.16.1",
		"org.apache.commons:commons-lang3":            "3.14.0",
		"org.apache.logging.log4j:log4j-core":         "2.22.1",
	}
	if len(refs) != len(want) {
		t.Fatalf("refs = %d, want %d (refs=%+v)", len(refs), len(want), refs)
	}
	for _, r := range refs {
		if r.Ecosystem != intel.EcosystemMaven {
			t.Errorf("ref %q: ecosystem = %q, want Maven", r.Name, r.Ecosystem)
		}
		if r.Source != "pom.xml" {
			t.Errorf("ref %q: source = %q, want pom.xml", r.Name, r.Source)
		}
		v, ok := want[r.Name]
		if !ok {
			t.Errorf("unexpected dep %q (excluded scope or unresolved property leaked)", r.Name)
			continue
		}
		if r.Version != v {
			t.Errorf("dep %q: version = %q, want %q", r.Name, r.Version, v)
		}
	}
}

func TestParseMaven_ExcludesTestProvidedSystemImportScopes(t *testing.T) {
	refs, _ := ParseMaven(Target{
		Ecosystem: intel.EcosystemMaven,
		Path:      filepath.Join("testdata", "maven-compromised", "pom.xml"),
		Source:    "pom.xml",
	})
	for _, r := range refs {
		switch r.Name {
		case "org.junit.jupiter:junit-jupiter":
			t.Errorf("test-scope dep leaked: %+v", r)
		case "jakarta.servlet:jakarta.servlet-api":
			t.Errorf("provided-scope dep leaked: %+v", r)
		case "com.local:local-jar":
			t.Errorf("system-scope dep leaked: %+v", r)
		}
	}
}

func TestParseMaven_SkipsUnresolvedPropertyPlaceholder(t *testing.T) {
	refs, _ := ParseMaven(Target{
		Ecosystem: intel.EcosystemMaven,
		Path:      filepath.Join("testdata", "maven-compromised", "pom.xml"),
		Source:    "pom.xml",
	})
	for _, r := range refs {
		if r.Name == "com.unresolved:missing-prop" {
			t.Errorf("unresolved ${not.defined.anywhere} leaked: %+v", r)
		}
		if r.Version == "${not.defined.anywhere}" {
			t.Errorf("literal property placeholder leaked as version: %+v", r)
		}
	}
}

func TestParseMaven_MalformedXMLReturnsError(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "pom.xml")
	writeFile(t, path, "<project><unclosed")
	_, err := ParseMaven(Target{Ecosystem: intel.EcosystemMaven, Path: path, Source: "pom.xml"})
	if err == nil {
		t.Fatal("expected error for malformed XML")
	}
}

func TestParseMaven_GradleLockfileBasic(t *testing.T) {
	target := Target{
		Ecosystem: intel.EcosystemMaven,
		Path:      filepath.Join("testdata", "maven-gradle", "gradle.lockfile"),
		Source:    "gradle.lockfile",
	}
	refs, err := ParseMaven(target)
	if err != nil {
		t.Fatalf("ParseMaven: %v", err)
	}
	// Expected: commons-lang3, guava. The `empty=...` marker
	// skips; the classifier-shaped line (group:name:version:
	// classifier=...) has 4 colon-parts and is also skipped per
	// PR #4 conservatism.
	want := map[string]string{
		"org.apache.commons:commons-lang3": "3.14.0",
		"com.google.guava:guava":           "33.0.0-jre",
	}
	if len(refs) != len(want) {
		t.Fatalf("refs = %d, want %d (refs=%+v)", len(refs), len(want), refs)
	}
	for _, r := range refs {
		v, ok := want[r.Name]
		if !ok {
			t.Errorf("unexpected dep %q", r.Name)
			continue
		}
		if r.Version != v {
			t.Errorf("dep %q: version = %q, want %q", r.Name, r.Version, v)
		}
		if r.Source != "gradle.lockfile" {
			t.Errorf("dep %q: source = %q, want gradle.lockfile", r.Name, r.Source)
		}
	}
}

func TestParseMaven_GradleDependencyLocksDirectory(t *testing.T) {
	// Per-configuration lockfiles live under
	// gradle/dependency-locks/<config>.lockfile. Discovery
	// emits one Target per file; the parser handles each
	// independently and the same parser path as gradle.lockfile.
	target := Target{
		Ecosystem: intel.EcosystemMaven,
		Path:      filepath.Join("testdata", "maven-gradle", "gradle", "dependency-locks", "compileClasspath.lockfile"),
		Source:    "gradle.lockfile",
	}
	refs, err := ParseMaven(target)
	if err != nil {
		t.Fatalf("ParseMaven: %v", err)
	}
	if len(refs) != 2 {
		t.Fatalf("refs = %d, want 2 (refs=%+v)", len(refs), refs)
	}
}

func TestParseMaven_GradleSkipsMalformedLines(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "gradle.lockfile")
	writeFile(t, path, "# comment\nempty=foo\nnot-a-coord=foo\nfoo:bar=foo\nfoo:bar:1.0:classifier=foo\nfoo:bar:1.0=compileClasspath\n")
	refs, err := ParseMaven(Target{Ecosystem: intel.EcosystemMaven, Path: path, Source: "gradle.lockfile"})
	if err != nil {
		t.Fatalf("ParseMaven: %v", err)
	}
	// Only `foo:bar:1.0` survives: comment skipped, `empty=`
	// skipped, two-colon `not-a-coord` skipped, two-colon
	// `foo:bar` skipped, four-colon classifier line skipped.
	if len(refs) != 1 || refs[0].Name != "foo:bar" || refs[0].Version != "1.0" {
		t.Errorf("expected one foo:bar 1.0 ref, got %+v", refs)
	}
}

func TestParseMaven_RejectsUnknownSource(t *testing.T) {
	_, err := ParseMaven(Target{Ecosystem: intel.EcosystemMaven, Path: "/dev/null", Source: "Cargo.lock"})
	if err == nil {
		t.Fatal("expected error for unsupported source")
	}
}

func TestResolveMavenProperty(t *testing.T) {
	props := map[string]string{"foo.version": "1.2.3", "empty.prop": ""}

	t.Run("literal version returns unchanged", func(t *testing.T) {
		v, ok := resolveMavenProperty("4.5.6", props)
		if !ok || v != "4.5.6" {
			t.Errorf("got (%q, %v), want (4.5.6, true)", v, ok)
		}
	})
	t.Run("known placeholder resolves", func(t *testing.T) {
		v, ok := resolveMavenProperty("${foo.version}", props)
		if !ok || v != "1.2.3" {
			t.Errorf("got (%q, %v), want (1.2.3, true)", v, ok)
		}
	})
	t.Run("unknown placeholder fails", func(t *testing.T) {
		_, ok := resolveMavenProperty("${unknown}", props)
		if ok {
			t.Errorf("expected unresolved property to fail")
		}
	})
	t.Run("known placeholder with empty value fails", func(t *testing.T) {
		_, ok := resolveMavenProperty("${empty.prop}", props)
		if ok {
			t.Errorf("expected empty property to fail")
		}
	})
}
