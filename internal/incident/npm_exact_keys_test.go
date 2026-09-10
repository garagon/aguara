package incident

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInstalledNPMExactIdentityKeys(t *testing.T) {
	for _, tc := range []struct{ input, name, version string }{
		{`{"name":"example","version":"1.0.0","Name":"other","Version":"2.0.0"}`, "example", "1.0.0"},
		{`{"Name":"example","Version":"1.0.0"}`, "", ""},
		{`{"name":"example","version":"1.0.0","version":null}`, "example", ""},
	} {
		path := filepath.Join(t.TempDir(), "package.json")
		require.NoError(t, os.WriteFile(path, []byte(tc.input), 0o600))
		pkg := parseNPMPackage(path)
		require.Equal(t, tc.name, pkg.Name)
		require.Equal(t, tc.version, pkg.Version)
	}
}
