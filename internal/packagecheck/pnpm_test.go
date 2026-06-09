package packagecheck

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/garagon/aguara/internal/intel"
	"github.com/stretchr/testify/require"
)

func TestParsePnpmPackageKey(t *testing.T) {
	cases := []struct {
		name     string
		key      string
		wantName string
		wantVer  string
		wantOK   bool
	}{
		// Accepted shapes
		{"unscoped modern", "node-ipc@9.2.3", "node-ipc", "9.2.3", true},
		{"unscoped slash-prefixed", "/node-ipc@9.2.3", "node-ipc", "9.2.3", true},
		{"scoped modern", "@scope/pkg@1.2.3", "@scope/pkg", "1.2.3", true},
		{"scoped slash-prefixed", "/@scope/pkg@1.2.3", "@scope/pkg", "1.2.3", true},
		{"peer-dep underscore suffix", "lodash@4.17.21_react@18.0.0", "lodash", "4.17.21", true},
		{"peer-dep paren suffix v9", "react@18.2.0(some-peer@1.0.0)", "react", "18.2.0", true},
		{"prerelease version", "preact@10.0.0-alpha.1", "preact", "10.0.0-alpha.1", true},

		// Rejected: non-registry sources
		{"file: ref", "file:../local-pkg", "", "", false},
		{"file: slash-prefixed", "/file:../local-pkg", "", "", false},
		{"link: ref", "link:../local-pkg", "", "", false},
		{"workspace: ref", "workspace:*", "", "", false},
		{"github: ref", "github:user/repo", "", "", false},
		{"git: ref", "git:user/repo", "", "", false},
		{"https: ref", "https://example.com/pkg", "", "", false},

		// Legacy v5 slash-separator format
		{"v5 unscoped", "/lodash/4.17.21", "lodash", "4.17.21", true},
		{"v5 scoped", "/@types/node/20.5.0", "@types/node", "20.5.0", true},
		{"v5 unscoped slash-only no leading", "lodash/4.17.21", "lodash", "4.17.21", true},
		// Legacy v5 + peer-dep suffix: the "@" in the peer suffix
		// must NOT be picked as the version separator.
		{"v5 unscoped + peer underscore", "lodash/4.17.21_react@18.0.0", "lodash", "4.17.21", true},
		{"v5 scoped + peer underscore", "/@types/node/20.5.0_typescript@5.0.0", "@types/node", "20.5.0", true},

		// v9+ scoped key with a SCOPED peer suffix. The "/" inside
		// "@types/node" inflates the key's slash count to 2 and
		// would otherwise route through the v5 fallback (splitting
		// on the wrong slash). Pre-stripping the paren suffix
		// keeps the modern branch active.
		{"v9 scoped + scoped peer paren", "@commitlint/cli@19.6.1(@types/node@22.10.2)", "@commitlint/cli", "19.6.1", true},
		{"v9 scoped + unscoped peer paren", "@vitejs/plugin-react@4.0.0(vite@4.4.4)", "@vitejs/plugin-react", "4.0.0", true},
		{"v9 unscoped + scoped peer paren", "react@18.2.0(@types/react@18.0.0)", "react", "18.2.0", true},

		// Rejected: malformed
		{"bare name no version", "node-ipc", "", "", false},
		{"empty version after @", "node-ipc@", "", "", false},
		{"only @", "@", "", "", false},
		{"empty string", "", "", "", false},
		{"bare scope without version", "@scope/pkg", "", "", false},
		{"slash with empty version", "/lodash/", "", "", false},

		// npm: alias entries -> resolve to the REAL registry package,
		// discarding the local alias name.
		{"alias unscoped real", "safe-ipc@npm:node-ipc@9.2.3", "node-ipc", "9.2.3", true},
		{"alias scoped real", "safe-rbac@npm:@redhat-cloud-services/rbac-client@2.1.5", "@redhat-cloud-services/rbac-client", "2.1.5", true},
		{"scoped alias unscoped real", "@local/safe-ipc@npm:node-ipc@9.2.3", "node-ipc", "9.2.3", true},
		{"alias slash-prefixed", "/safe-ipc@npm:node-ipc@9.2.3", "node-ipc", "9.2.3", true},
		{"alias real + scoped peer paren", "safe-react@npm:react@18.2.0(@types/react@18.0.0)", "react", "18.2.0", true},
		{"alias real + underscore peer", "safe-react@npm:react@18.2.0_react-dom@18.2.0", "react", "18.2.0", true},
		{"alias real prerelease", "safe@npm:preact@10.0.0-alpha.1", "preact", "10.0.0-alpha.1", true},

		// npm: alias entries that are NOT unambiguously resolvable.
		{"alias real no version", "safe@npm:node-ipc", "", "", false},
		{"alias real caret range", "safe@npm:node-ipc@^9.2.0", "", "", false},
		{"alias real tilde range", "safe@npm:node-ipc@~9.2.0", "", "", false},
		{"alias real x-range", "safe@npm:node-ipc@9.2.x", "", "", false},
		{"alias real dist-tag", "safe@npm:node-ipc@latest", "", "", false},
		{"alias real partial version", "safe@npm:node-ipc@9.2", "", "", false},
		{"alias empty real", "safe@npm:", "", "", false},
		{"alias scoped real no version", "safe@npm:@scope/pkg", "", "", false},
		{"alias scoped real empty version", "safe@npm:@scope/pkg@", "", "", false},
		// A non-npm alias target (alias@workspace:/file:/github:) does not
		// contain "@npm:", so it never routes through the alias path and
		// the normal non-registry rejection applies.
		{"alias workspace target", "safe@workspace:node-ipc@9.2.3", "", "", false},
		{"alias file target", "safe@file:../node-ipc", "", "", false},
		{"alias github target", "safe@github:user/repo", "", "", false},
		// A file dependency whose PATH contains "@npm:" must be treated
		// as the file dep it is (first protocol wins), not resolved to
		// the npm package in the path. Otherwise a local directory turns
		// into a false advisory hit.
		{"file dep with npm in path", "local-safe@file:safe@npm:node-ipc@9.2.3", "", "", false},
		{"link dep with npm in path", "local@link:vendor@npm:node-ipc@9.2.3", "", "", false},
		// Slash-prefixed bare non-registry key whose path contains
		// "@npm:": after the leading "/" is stripped it starts with
		// "file:", so it is rejected before alias routing.
		{"slash file: prefix with npm in path", "/file:safe@npm:node-ipc@9.2.3", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotName, gotVer, gotOK := parsePnpmPackageKey(tc.key)
			require.Equal(t, tc.wantOK, gotOK, "ok mismatch")
			if tc.wantOK {
				require.Equal(t, tc.wantName, gotName, "name mismatch")
				require.Equal(t, tc.wantVer, gotVer, "version mismatch")
			}
		})
	}
}

func TestParsePNPMLock_ReadsUnscopedPackage(t *testing.T) {
	dir := t.TempDir()
	lock := filepath.Join(dir, "pnpm-lock.yaml")
	require.NoError(t, os.WriteFile(lock, []byte(`lockfileVersion: '9.0'

packages:
  node-ipc@9.2.3:
    resolution:
      integrity: sha512-stub==
`), 0o644))

	refs, err := ParsePNPMLock(Target{
		Ecosystem: intel.EcosystemNPM,
		Path:      lock,
		Source:    "pnpm-lock.yaml",
	})
	require.NoError(t, err)
	require.Len(t, refs, 1)
	require.Equal(t, intel.EcosystemNPM, refs[0].Ecosystem)
	require.Equal(t, "node-ipc", refs[0].Name)
	require.Equal(t, "9.2.3", refs[0].Version)
	require.Equal(t, "pnpm-lock.yaml", refs[0].Source)
	require.Equal(t, lock, refs[0].Path)
}

func TestParsePNPMLock_ReadsScopedPackage(t *testing.T) {
	dir := t.TempDir()
	lock := filepath.Join(dir, "pnpm-lock.yaml")
	require.NoError(t, os.WriteFile(lock, []byte(`lockfileVersion: '9.0'

packages:
  '@vitejs/plugin-react@4.0.0':
    resolution:
      integrity: sha512-stub==
  '@types/node@20.5.0':
    resolution:
      integrity: sha512-stub==
`), 0o644))

	refs, err := ParsePNPMLock(Target{
		Ecosystem: intel.EcosystemNPM,
		Path:      lock,
		Source:    "pnpm-lock.yaml",
	})
	require.NoError(t, err)
	require.Len(t, refs, 2)
	// Map iteration is non-deterministic; sort by name for stable assertions.
	sort.Slice(refs, func(i, j int) bool { return refs[i].Name < refs[j].Name })
	require.Equal(t, "@types/node", refs[0].Name)
	require.Equal(t, "20.5.0", refs[0].Version)
	require.Equal(t, "@vitejs/plugin-react", refs[1].Name)
	require.Equal(t, "4.0.0", refs[1].Version)
}

func TestParsePNPMLock_ResolvesNpmAlias(t *testing.T) {
	// A dependency installed under a local alias name must be matched
	// against the REAL registry package, not the alias.
	dir := t.TempDir()
	lock := filepath.Join(dir, "pnpm-lock.yaml")
	require.NoError(t, os.WriteFile(lock, []byte(`lockfileVersion: '9.0'

packages:
  safe-ipc@npm:node-ipc@9.2.3:
    resolution:
      integrity: sha512-stub==
`), 0o644))

	refs, err := ParsePNPMLock(Target{
		Ecosystem: intel.EcosystemNPM,
		Path:      lock,
		Source:    "pnpm-lock.yaml",
	})
	require.NoError(t, err)
	require.Len(t, refs, 1)
	require.Equal(t, "node-ipc", refs[0].Name, "alias must resolve to the real registry package")
	require.Equal(t, "9.2.3", refs[0].Version)
	require.Equal(t, "pnpm-lock.yaml", refs[0].Source)
}

func TestParsePNPMLock_DedupsAliasAndRealEntry(t *testing.T) {
	// When the same real package appears both directly and behind an
	// alias, the existing (name, version) dedup must collapse them to a
	// single ref so packages_read / findings are not inflated.
	dir := t.TempDir()
	lock := filepath.Join(dir, "pnpm-lock.yaml")
	require.NoError(t, os.WriteFile(lock, []byte(`lockfileVersion: '9.0'

packages:
  node-ipc@9.2.3:
    resolution:
      integrity: sha512-stub==
  safe-ipc@npm:node-ipc@9.2.3:
    resolution:
      integrity: sha512-stub==
`), 0o644))

	refs, err := ParsePNPMLock(Target{
		Ecosystem: intel.EcosystemNPM,
		Path:      lock,
		Source:    "pnpm-lock.yaml",
	})
	require.NoError(t, err)
	require.Len(t, refs, 1, "alias + real entry for the same package must dedup to one ref")
	require.Equal(t, "node-ipc", refs[0].Name)
	require.Equal(t, "9.2.3", refs[0].Version)
}

func TestParsePNPMLock_IgnoresWorkspaceAndFileRefs(t *testing.T) {
	// pnpm-lock.yaml routinely contains entries that are NOT npm
	// registry packages: workspace siblings, file: relative paths,
	// link: symlinks, github: URLs. Matching those against npm
	// advisories would false-positive on name collisions (a local
	// "lodash" symlink picking up every lodash CVE). The parser
	// must skip them silently.
	dir := t.TempDir()
	lock := filepath.Join(dir, "pnpm-lock.yaml")
	require.NoError(t, os.WriteFile(lock, []byte(`lockfileVersion: '9.0'

packages:
  node-ipc@9.2.3:
    resolution:
      integrity: sha512-stub==
  'workspace:*':
    resolution:
      integrity: sha512-stub==
  'file:../local-lodash':
    resolution:
      integrity: sha512-stub==
  'link:../sibling':
    resolution:
      integrity: sha512-stub==
  'github:user/repo':
    resolution:
      integrity: sha512-stub==
`), 0o644))

	refs, err := ParsePNPMLock(Target{
		Ecosystem: intel.EcosystemNPM,
		Path:      lock,
		Source:    "pnpm-lock.yaml",
	})
	require.NoError(t, err)
	require.Len(t, refs, 1, "only node-ipc@9.2.3 should be emitted; non-registry entries filtered")
	require.Equal(t, "node-ipc", refs[0].Name)
	require.Equal(t, "9.2.3", refs[0].Version)
}

func TestParsePNPMLock_PeerDepSuffix(t *testing.T) {
	// pnpm encodes resolved peer-dep relationships into the package
	// key. The actual installed version is the part before the
	// underscore (pre-v9) or the opening paren (v9+). The parser
	// strips both so matcher comparison uses the clean version.
	dir := t.TempDir()
	lock := filepath.Join(dir, "pnpm-lock.yaml")
	require.NoError(t, os.WriteFile(lock, []byte(`lockfileVersion: '9.0'

packages:
  lodash@4.17.21_react@18.0.0:
    resolution:
      integrity: sha512-stub==
  react@18.2.0(some-peer@1.0.0):
    resolution:
      integrity: sha512-stub==
`), 0o644))

	refs, err := ParsePNPMLock(Target{
		Ecosystem: intel.EcosystemNPM,
		Path:      lock,
		Source:    "pnpm-lock.yaml",
	})
	require.NoError(t, err)
	require.Len(t, refs, 2)
	sort.Slice(refs, func(i, j int) bool { return refs[i].Name < refs[j].Name })
	require.Equal(t, "lodash", refs[0].Name)
	require.Equal(t, "4.17.21", refs[0].Version, "peer-dep underscore suffix must be stripped")
	require.Equal(t, "react", refs[1].Name)
	require.Equal(t, "18.2.0", refs[1].Version, "peer-dep paren suffix must be stripped")
}

func TestParsePNPMLock_EmptyPackages(t *testing.T) {
	// A lockfile with a packages: key but no entries should produce
	// zero refs without erroring. Same shape pnpm emits for a
	// workspace root with all deps under sub-packages.
	dir := t.TempDir()
	lock := filepath.Join(dir, "pnpm-lock.yaml")
	require.NoError(t, os.WriteFile(lock, []byte(`lockfileVersion: '9.0'

packages: {}
`), 0o644))

	refs, err := ParsePNPMLock(Target{
		Ecosystem: intel.EcosystemNPM,
		Path:      lock,
		Source:    "pnpm-lock.yaml",
	})
	require.NoError(t, err)
	require.Empty(t, refs)
}

func TestParsePNPMLock_DedupsPeerResolvedDuplicates(t *testing.T) {
	// pnpm encodes resolved peer-dep relationships into the
	// package key, so the same (name, version) can appear under
	// several keys when a package is consumed with different peer
	// resolutions. Without dedup the runner would emit one Hit
	// per peer-variant and inflate both packages_read and
	// findings_count for compromised packages. Lock the dedup at
	// the parser boundary so the contract is consistent regardless
	// of which dispatcher consumes the refs.
	dir := t.TempDir()
	lock := filepath.Join(dir, "pnpm-lock.yaml")
	require.NoError(t, os.WriteFile(lock, []byte(`lockfileVersion: '9.0'

packages:
  react@18.2.0(peer-a@1.0.0):
    resolution:
      integrity: sha512-stub==
  react@18.2.0(peer-b@2.0.0):
    resolution:
      integrity: sha512-stub==
  react@18.2.0_react-dom@18.0.0:
    resolution:
      integrity: sha512-stub==
  lodash@4.17.21:
    resolution:
      integrity: sha512-stub==
`), 0o644))

	refs, err := ParsePNPMLock(Target{
		Ecosystem: intel.EcosystemNPM,
		Path:      lock,
		Source:    "pnpm-lock.yaml",
	})
	require.NoError(t, err)
	require.Len(t, refs, 2, "three react@18.2.0 peer-variants must collapse to one ref + lodash")

	sort.Slice(refs, func(i, j int) bool { return refs[i].Name < refs[j].Name })
	require.Equal(t, "lodash", refs[0].Name)
	require.Equal(t, "react", refs[1].Name)
	require.Equal(t, "18.2.0", refs[1].Version)
}

func TestParsePNPMLock_DeterministicOrder(t *testing.T) {
	// Aguara advertises deterministic scans. ParsePNPMLock sorts
	// the package keys before emitting refs so the runner's Hits
	// and downstream Findings land in stable order across runs.
	// Without the sort, Go's randomized map iteration would
	// produce different JSON / terminal output between invocations
	// on the same lockfile.
	dir := t.TempDir()
	lock := filepath.Join(dir, "pnpm-lock.yaml")
	require.NoError(t, os.WriteFile(lock, []byte(`lockfileVersion: '9.0'

packages:
  zeta@1.0.0:
    resolution:
      integrity: sha512-stub==
  alpha@2.0.0:
    resolution:
      integrity: sha512-stub==
  mike@3.0.0:
    resolution:
      integrity: sha512-stub==
`), 0o644))

	want := []string{"alpha", "mike", "zeta"}
	for i := 0; i < 5; i++ {
		refs, err := ParsePNPMLock(Target{
			Ecosystem: intel.EcosystemNPM,
			Path:      lock,
			Source:    "pnpm-lock.yaml",
		})
		require.NoError(t, err)
		require.Len(t, refs, 3)
		got := []string{refs[0].Name, refs[1].Name, refs[2].Name}
		require.Equal(t, want, got, "run %d produced different order; ParsePNPMLock must be deterministic", i+1)
	}
}

func TestParsePNPMLock_MissingFile(t *testing.T) {
	_, err := ParsePNPMLock(Target{
		Ecosystem: intel.EcosystemNPM,
		Path:      "/nonexistent/pnpm-lock.yaml",
		Source:    "pnpm-lock.yaml",
	})
	require.Error(t, err)
}
