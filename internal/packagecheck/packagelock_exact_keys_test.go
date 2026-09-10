package packagecheck

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPackageLockExactIdentityKeys(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		want        int
	}{
		{"case cannot erase packages", `{"packages":{"node_modules/example":{"version":"1.0.0"}},"Packages":null}`, 1},
		{"case cannot change version", `{"packages":{"node_modules/example":{"version":"1.0.0","Version":"2.0.0"}}}`, 1},
		{"case cannot introduce packages", `{"Packages":{"node_modules/example":{"version":"1.0.0"}}}`, 0},
		{"last exact packages wins", `{"packages":{"node_modules/example":{"version":"1.0.0"}},"packages":{}}`, 0},
		{"legacy dependency case", `{"dependencies":{"example":{"version":"1.0.0","Version":"2.0.0"}},"Dependencies":null}`, 1},
		{"source aliases ignored", `{"packages":{"node_modules/example":{"version":"1.0.0","Resolved":"file:local","Link":true,"Name":"other"}}}`, 1},
		{"overwritten invalid entry", `{"packages":{"node_modules/example":42,"node_modules/example":{"version":"1.0.0"}}}`, 1},
		{"legacy invalid entry replaced", `{"dependencies":{"example":42,"example":{"version":"1.0.0"}}}`, 1},
		{"nested dependencies replaced", `{"dependencies":{"parent":{"dependencies":{"example":{"version":"1.0.0"}},"dependencies":{}}}}`, 0},
		{"final empty packages permits legacy fallback", `{"packages":{"node_modules/old":{"version":"9.0.0"}},"packages":{},"dependencies":{"example":{"version":"1.0.0"}}}`, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "package-lock.json")
			require.NoError(t, os.WriteFile(path, []byte(tc.input), 0o600))
			refs, err := ParsePackageLock(Target{Path: path})
			require.NoError(t, err)
			require.Len(t, refs, tc.want)
			if tc.want > 0 {
				require.Equal(t, "example", refs[0].Name)
				require.Equal(t, "1.0.0", refs[0].Version)
			}
		})
	}
}

func TestPackageLockDependencyDecodeBudget(t *testing.T) {
	data := []byte(`{"example":{"version":"1.0.0"}}`)
	budget := int64(len(data))
	got, err := decodeLockDependencies(data, 0, &budget)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Zero(t, budget)
	budget = int64(len(data) - 1)
	got, err = decodeLockDependencies(data, 0, &budget)
	require.ErrorContains(t, err, "budget")
	require.Nil(t, got)
	budget = 1024
	got, err = decodeLockDependencies(data, 128, &budget)
	require.ErrorContains(t, err, "budget")
	require.Nil(t, got)
	parent := []byte(`{"parent":{"dependencies":{"example":{"version":"1.0.0"}}}}`)
	budget = int64(len(parent))
	got, err = decodeLockDependencies(parent, 0, &budget)
	require.ErrorContains(t, err, "budget")
	require.Nil(t, got, "nested work must share the parent budget")
}
