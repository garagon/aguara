package packagecheck

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/garagon/aguara/internal/intel"
	"github.com/stretchr/testify/require"
)

// writeLock writes content to a package-lock.json in a fresh temp dir
// and returns a Target pointing at it.
func writeLock(t *testing.T, content string) Target {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "package-lock.json")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return Target{Ecosystem: intel.EcosystemNPM, Path: path, Source: "package-lock.json"}
}

// refSet flattens parsed refs into "name@version" strings for order-
// independent assertions; order itself is checked separately.
func refSet(refs []PackageRef) []string {
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		out = append(out, r.Name+"@"+r.Version)
	}
	return out
}

func TestParsePackageLock_V3PackagesMap(t *testing.T) {
	// lockfileVersion 3: only `packages`, no `dependencies`.
	refs, err := ParsePackageLock(writeLock(t, `{
	  "name": "myapp",
	  "lockfileVersion": 3,
	  "packages": {
	    "": { "name": "myapp", "version": "1.0.0" },
	    "node_modules/foo": { "version": "1.2.3", "resolved": "https://registry.npmjs.org/foo/-/foo-1.2.3.tgz" },
	    "node_modules/bar": { "version": "4.5.6", "resolved": "https://registry.npmjs.org/bar/-/bar-4.5.6.tgz" }
	  }
	}`))
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"foo@1.2.3", "bar@4.5.6"}, refSet(refs))
	for _, r := range refs {
		require.Equal(t, intel.EcosystemNPM, r.Ecosystem)
		require.Equal(t, "package-lock.json", r.Source)
	}
}

func TestParsePackageLock_V2PackagesMapPreferredOverDependencies(t *testing.T) {
	// lockfileVersion 2 carries BOTH packages and the legacy
	// dependencies mirror. The parser must read `packages` only, so
	// the legacy mirror's stale entry must NOT appear (no double count
	// and no resurrecting a removed dep).
	refs, err := ParsePackageLock(writeLock(t, `{
	  "name": "myapp",
	  "lockfileVersion": 2,
	  "packages": {
	    "": { "name": "myapp", "version": "1.0.0" },
	    "node_modules/foo": { "version": "1.2.3", "resolved": "https://registry.npmjs.org/foo/-/foo-1.2.3.tgz" }
	  },
	  "dependencies": {
	    "foo": { "version": "1.2.3" },
	    "stale-only-in-legacy-mirror": { "version": "9.9.9" }
	  }
	}`))
	require.NoError(t, err)
	require.Equal(t, []string{"foo@1.2.3"}, refSet(refs))
}

func TestParsePackageLock_V1RecursiveDependencies(t *testing.T) {
	// lockfileVersion 1: no `packages`, recursive `dependencies` tree.
	refs, err := ParsePackageLock(writeLock(t, `{
	  "name": "myapp",
	  "lockfileVersion": 1,
	  "dependencies": {
	    "foo": {
	      "version": "1.2.3",
	      "resolved": "https://registry.npmjs.org/foo/-/foo-1.2.3.tgz",
	      "dependencies": {
	        "bar": { "version": "4.5.6", "resolved": "https://registry.npmjs.org/bar/-/bar-4.5.6.tgz" }
	      }
	    }
	  }
	}`))
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"foo@1.2.3", "bar@4.5.6"}, refSet(refs))
}

func TestParsePackageLock_ScopedPackage(t *testing.T) {
	// Scoped names survive verbatim in both lockfile shapes.
	v3, err := ParsePackageLock(writeLock(t, `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": { "name": "myapp", "version": "1.0.0" },
	    "node_modules/@scope/pkg": { "version": "2.0.0", "resolved": "https://registry.npmjs.org/@scope/pkg/-/pkg-2.0.0.tgz" }
	  }
	}`))
	require.NoError(t, err)
	require.Equal(t, []string{"@scope/pkg@2.0.0"}, refSet(v3))

	v1, err := ParsePackageLock(writeLock(t, `{
	  "lockfileVersion": 1,
	  "dependencies": {
	    "@scope/pkg": { "version": "2.0.0", "resolved": "https://registry.npmjs.org/@scope/pkg/-/pkg-2.0.0.tgz" }
	  }
	}`))
	require.NoError(t, err)
	require.Equal(t, []string{"@scope/pkg@2.0.0"}, refSet(v1))
}

func TestParsePackageLock_NestedDependency(t *testing.T) {
	// v2/v3 nest a dependency-of-a-dependency under a second
	// node_modules/ segment; the name is the LAST segment. A scoped
	// nested dep keeps its scope.
	refs, err := ParsePackageLock(writeLock(t, `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": { "name": "myapp", "version": "1.0.0" },
	    "node_modules/a": { "version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz" },
	    "node_modules/a/node_modules/foo": { "version": "1.5.0", "resolved": "https://registry.npmjs.org/foo/-/foo-1.5.0.tgz" },
	    "node_modules/a/node_modules/@scope/pkg": { "version": "3.1.0", "resolved": "https://registry.npmjs.org/@scope/pkg/-/pkg-3.1.0.tgz" }
	  }
	}`))
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"a@1.0.0", "foo@1.5.0", "@scope/pkg@3.1.0"}, refSet(refs))
}

func TestParsePackageLock_DedupSameNameVersion(t *testing.T) {
	// The same (name, version) installed at two paths collapses to one
	// ref (dedup is on (name, version), not on path).
	refs, err := ParsePackageLock(writeLock(t, `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": { "name": "myapp", "version": "1.0.0" },
	    "node_modules/foo": { "version": "1.2.3", "resolved": "https://registry.npmjs.org/foo/-/foo-1.2.3.tgz" },
	    "node_modules/a/node_modules/foo": { "version": "1.2.3", "resolved": "https://registry.npmjs.org/foo/-/foo-1.2.3.tgz" }
	  }
	}`))
	require.NoError(t, err)
	require.Equal(t, []string{"foo@1.2.3"}, refSet(refs))
}

func TestParsePackageLock_SameNameDifferentVersionsNotDeduped(t *testing.T) {
	// Two versions of the same package are distinct exposures and must
	// both survive.
	refs, err := ParsePackageLock(writeLock(t, `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": { "name": "myapp", "version": "1.0.0" },
	    "node_modules/foo": { "version": "1.2.3", "resolved": "https://registry.npmjs.org/foo/-/foo-1.2.3.tgz" },
	    "node_modules/a/node_modules/foo": { "version": "2.0.0", "resolved": "https://registry.npmjs.org/foo/-/foo-2.0.0.tgz" }
	  }
	}`))
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"foo@1.2.3", "foo@2.0.0"}, refSet(refs))
}

func TestParsePackageLock_SkipsNonRegistrySources(t *testing.T) {
	// Every non-registry shape must be skipped: a workspace source
	// dir key, a link symlink, a file:/git+/workspace: version, a git+
	// resolved, an aliased npm: version, the root project, and a
	// versionless entry. The one clean registry dep is all that
	// survives.
	refs, err := ParsePackageLock(writeLock(t, `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": { "name": "myapp", "version": "1.0.0" },
	    "node_modules/clean": { "version": "1.0.0", "resolved": "https://registry.npmjs.org/clean/-/clean-1.0.0.tgz" },
	    "node_modules/linked": { "resolved": "../local", "link": true },
	    "node_modules/from-file": { "version": "file:../local-pkg" },
	    "node_modules/from-git": { "version": "1.0.0", "resolved": "git+https://github.com/u/repo.git#abc123" },
	    "node_modules/from-workspace": { "version": "workspace:*" },
	    "node_modules/aliased": { "version": "npm:real-pkg@1.0.0" },
	    "node_modules/no-version": { "resolved": "https://registry.npmjs.org/x/-/x-1.0.0.tgz" },
	    "packages/my-workspace-member": { "name": "my-workspace-member", "version": "0.1.0" }
	  }
	}`))
	require.NoError(t, err)
	require.Equal(t, []string{"clean@1.0.0"}, refSet(refs))
}

func TestParsePackageLock_V1SkipsNonRegistryButRecursesChildren(t *testing.T) {
	// A v1 git-sourced parent is skipped, but its registry children
	// are still audited (recursion is unconditional on the parent's
	// registry status).
	refs, err := ParsePackageLock(writeLock(t, `{
	  "lockfileVersion": 1,
	  "dependencies": {
	    "from-git": {
	      "version": "1.0.0",
	      "resolved": "git+https://github.com/u/repo.git#abc",
	      "dependencies": {
	        "real-child": { "version": "2.2.2", "resolved": "https://registry.npmjs.org/real-child/-/real-child-2.2.2.tgz" }
	      }
	    }
	  }
	}`))
	require.NoError(t, err)
	require.Equal(t, []string{"real-child@2.2.2"}, refSet(refs))
}

func TestParsePackageLock_DeterministicOrder(t *testing.T) {
	// Output is sorted by name@version regardless of map iteration.
	refs, err := ParsePackageLock(writeLock(t, `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": { "name": "myapp", "version": "1.0.0" },
	    "node_modules/zeta": { "version": "1.0.0", "resolved": "https://registry.npmjs.org/zeta/-/zeta-1.0.0.tgz" },
	    "node_modules/alpha": { "version": "2.0.0", "resolved": "https://registry.npmjs.org/alpha/-/alpha-2.0.0.tgz" },
	    "node_modules/@scope/mid": { "version": "1.0.0", "resolved": "https://registry.npmjs.org/@scope/mid/-/mid-1.0.0.tgz" }
	  }
	}`))
	require.NoError(t, err)
	require.Equal(t, []string{"@scope/mid@1.0.0", "alpha@2.0.0", "zeta@1.0.0"}, refSet(refs))
}

func TestValidNPMName(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"foo", "foo", true},
		{"@scope/pkg", "@scope/pkg", true},
		{"", "", false},
		{"foo/bar", "", false},        // unscoped with a slash
		{"@scope/pkg/extra", "", false}, // scoped with extra segment
		{"@scope", "", false},          // scope without package
		{"@/pkg", "", false},           // empty scope
		{"@scope/", "", false},         // empty package
	}
	for _, c := range cases {
		got, ok := validNPMName(c.in)
		require.Equalf(t, c.ok, ok, "validNPMName(%q) ok", c.in)
		if c.ok {
			require.Equalf(t, c.want, got, "validNPMName(%q) name", c.in)
		}
	}
}

func TestPackageLockName(t *testing.T) {
	cases := []struct {
		key  string
		want string
		ok   bool
	}{
		{"", "", false},                                         // root
		{"node_modules/foo", "foo", true},                       // unscoped
		{"node_modules/@scope/pkg", "@scope/pkg", true},         // scoped
		{"packages/a/node_modules/foo", "foo", true},            // nested unscoped
		{"packages/a/node_modules/@scope/pkg", "@scope/pkg", true}, // nested scoped
		{"node_modules/a/node_modules/foo", "foo", true},        // dep-of-dep
		{"packages/a", "", false},                               // workspace src dir
		{"some/other/path", "", false},                          // no node_modules segment
	}
	for _, c := range cases {
		got, ok := packageLockName(c.key)
		require.Equalf(t, c.ok, ok, "packageLockName(%q) ok", c.key)
		if c.ok {
			require.Equalf(t, c.want, got, "packageLockName(%q) name", c.key)
		}
	}
}

// --- Runner smoke: the new coverage flows through the matcher,
// for both an exact-version advisory and a range advisory (npm is the
// phase-1 range-evaluable ecosystem, so the range hit proves
// package-lock coverage benefits from range matching). ---

func TestRunner_PackageLockExactAndRangeHits(t *testing.T) {
	snap := intel.Snapshot{
		SchemaVersion: intel.CurrentSchemaVersion,
		GeneratedAt:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Records: []intel.Record{
			{
				ID:        "MAL-EXACT",
				Ecosystem: intel.EcosystemNPM,
				Name:      "evil-exact",
				Kind:      intel.KindMalicious,
				Versions:  []string{"1.2.3"},
			},
			{
				ID:        "MAL-RANGE",
				Ecosystem: intel.EcosystemNPM,
				Name:      "evil-range",
				Kind:      intel.KindMalicious,
				Ranges:    []intel.VersionRange{{Type: "semver", Introduced: "1.0.0", Fixed: "2.0.0"}},
			},
		},
	}
	runner := &Runner{Matcher: intel.NewMatcher(snap)}

	target := writeLock(t, `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": { "name": "myapp", "version": "1.0.0" },
	    "node_modules/evil-exact": { "version": "1.2.3", "resolved": "https://registry.npmjs.org/evil-exact/-/evil-exact-1.2.3.tgz" },
	    "node_modules/evil-range": { "version": "1.5.0", "resolved": "https://registry.npmjs.org/evil-range/-/evil-range-1.5.0.tgz" },
	    "node_modules/safe": { "version": "9.9.9", "resolved": "https://registry.npmjs.org/safe/-/safe-9.9.9.tgz" }
	  }
	}`)
	res, err := runner.Run([]Target{target})
	require.NoError(t, err)

	require.Len(t, res.Ecosystems, 1)
	er := res.Ecosystems[0]
	require.Equal(t, intel.EcosystemNPM, er.Ecosystem)
	require.Equal(t, "package-lock.json", er.Source)
	require.Equal(t, 3, er.PackagesRead)
	require.Equal(t, 2, er.FindingsCount)

	got := map[string]string{} // name@version -> record ID
	for _, h := range res.Hits {
		got[h.Ref.Name+"@"+h.Ref.Version] = h.Record.ID
	}
	require.Equal(t, "MAL-EXACT", got["evil-exact@1.2.3"])
	require.Equal(t, "MAL-RANGE", got["evil-range@1.5.0"], "range advisory must hit a version inside [1.0.0, 2.0.0)")
	require.NotContains(t, got, "safe@9.9.9")
}

func TestDiscover_PicksPackageLock(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{"lockfileVersion":3,"packages":{}}`), 0o600))
	targets, err := Discover(dir, []string{intel.EcosystemNPM})
	require.NoError(t, err)
	require.Len(t, targets, 1)
	require.Equal(t, "package-lock.json", targets[0].Source)
	require.Equal(t, intel.EcosystemNPM, targets[0].Ecosystem)
}
