package packagecheck

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/garagon/aguara/internal/intel"
	"github.com/stretchr/testify/require"
)

func writeBunLock(t *testing.T, body string) Target {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "bun.lock")
	require.NoError(t, os.WriteFile(p, []byte(body), 0o644))
	return Target{Ecosystem: intel.EcosystemNPM, Path: p, Source: "bun.lock"}
}

func TestParseBunLock_ResolvedPackages(t *testing.T) {
	// JSONC with trailing commas (what bun emits). The alias "safe-ipc"
	// resolves to the real node-ipc@9.2.3 via the array's first element.
	refs, err := ParseBunLock(writeBunLock(t, `{
  "lockfileVersion": 1,
  "workspaces": {
    "": { "dependencies": { "safe-ipc": "npm:node-ipc@9.2.3" }, },
  },
  "packages": {
    "@scope/pkg": ["@scope/pkg@1.2.3", "", {}, "sha512-FAKE=="],
    "lodash": ["lodash@4.17.21", "", { "dependencies": {} }, "sha512-FAKE=="],
    "safe-ipc": ["node-ipc@9.2.3", "", {}, "sha512-FAKE=="],
  }
}`))
	require.NoError(t, err)
	sort.Slice(refs, func(i, j int) bool { return refs[i].Name < refs[j].Name })
	require.Len(t, refs, 3)
	require.Equal(t, "@scope/pkg", refs[0].Name)
	require.Equal(t, "1.2.3", refs[0].Version)
	require.Equal(t, "lodash", refs[1].Name)
	require.Equal(t, "node-ipc", refs[2].Name, "alias must resolve to the real package")
	require.Equal(t, "9.2.3", refs[2].Version)
	require.Equal(t, "bun.lock", refs[2].Source)
}

func TestParseBunLock_SkipsNonRegistryAndRanges(t *testing.T) {
	// A git/file/workspace resolution or a non-exact version in the
	// first element is skipped; only clean registry tuples are emitted.
	refs, err := ParseBunLock(writeBunLock(t, `{
  "packages": {
    "good": ["good@1.0.0", "", {}, "sha512-FAKE=="],
    "fromgit": ["fromgit@github:user/repo", "", {}, ""],
    "local": ["local@workspace:packages/local", "", {}, ""],
    "bad": ["noversion", "", {}, ""],
  }
}`))
	require.NoError(t, err)
	require.Len(t, refs, 1)
	require.Equal(t, "good", refs[0].Name)
	require.Equal(t, "1.0.0", refs[0].Version)
}

func TestParseBunLock_NestedPackagesKeyIgnored(t *testing.T) {
	// A workspace member at path "packages" produces a nested
	// "packages": {...} under "workspaces". Only the TOP-LEVEL packages
	// map must be parsed, so the real resolved set is not missed.
	refs, err := ParseBunLock(writeBunLock(t, `{
  "lockfileVersion": 1,
  "workspaces": {
    "": { "name": "root" },
    "packages": { "name": "packages", "dependencies": { "x": "1.0.0" } },
  },
  "packages": {
    "real-dep": ["real-dep@2.3.4", "", {}, "sha512-FAKE=="],
  }
}`))
	require.NoError(t, err)
	require.Len(t, refs, 1)
	require.Equal(t, "real-dep", refs[0].Name)
	require.Equal(t, "2.3.4", refs[0].Version)
}

func TestParseBunLock_Dedup(t *testing.T) {
	refs, err := ParseBunLock(writeBunLock(t, `{
  "packages": {
    "lodash": ["lodash@4.17.21", "", {}, "sha512-FAKE=="],
    "alias-lodash": ["lodash@4.17.21", "", {}, "sha512-FAKE=="],
  }
}`))
	require.NoError(t, err)
	require.Len(t, refs, 1, "same (name, version) from an alias + direct must dedup")
}

func TestParseBunLock_MalformedNoPanic(t *testing.T) {
	// No packages object, or junk: no refs, no error, no panic.
	for _, body := range []string{``, `not json`, `{"workspaces":{}}`, `{"packages":{`} {
		refs, err := ParseBunLock(writeBunLock(t, body))
		require.NoError(t, err)
		require.Empty(t, refs)
	}
}

func TestParseBunLock_DeterministicOrder(t *testing.T) {
	body := `{
  "packages": {
    "z": ["zeta@2.0.0", "", {}, ""],
    "a": ["alpha@1.0.0", "", {}, ""],
  }
}`
	tgt := writeBunLock(t, body)
	var first []PackageRef
	for i := 0; i < 3; i++ {
		refs, err := ParseBunLock(tgt)
		require.NoError(t, err)
		if i == 0 {
			first = refs
			continue
		}
		require.Equal(t, first, refs, "ParseBunLock must be deterministic")
	}
}
