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

		// Rejected: malformed
		{"bare name no version", "node-ipc", "", "", false},
		{"empty version after @", "node-ipc@", "", "", false},
		{"only @", "@", "", "", false},
		{"empty string", "", "", "", false},
		{"bare scope without version", "@scope/pkg", "", "", false},
		{"slash with empty version", "/lodash/", "", "", false},
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

func TestParsePNPMLock_MissingFile(t *testing.T) {
	_, err := ParsePNPMLock(Target{
		Ecosystem: intel.EcosystemNPM,
		Path:      "/nonexistent/pnpm-lock.yaml",
		Source:    "pnpm-lock.yaml",
	})
	require.Error(t, err)
}
