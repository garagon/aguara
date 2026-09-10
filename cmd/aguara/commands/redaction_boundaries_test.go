package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScanPrivateKeyRedactionFormats(t *testing.T) {
	const body = "QUdVQVJBX1NZTlRIRVRJQ19QUklWQVRFX0tFWQ=="
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "key.txt"), []byte("-----BEGIN PRIVATE KEY-----\n"+body+"\n-----END PRIVATE KEY-----\n"), 0o600))
	for _, format := range []string{"json", "sarif", "markdown", "terminal"} {
		t.Run(format, func(t *testing.T) {
			data := scanToFile(t, dir, "--format", format, "--workers", "1", "--no-color")
			require.NotEmpty(t, data)
			require.NotContains(t, string(data), body)
		})
	}
	t.Run("explicit opt out", func(t *testing.T) {
		data := scanToFile(t, dir, "--format", "json", "--workers", "1", "--no-redact")
		require.Contains(t, string(data), body)
	})
	t.Run("audit", func(t *testing.T) {
		result := auditToFile(t, dir)
		require.NotEmpty(t, result.Scan.Findings)
		data, err := json.Marshal(result)
		require.NoError(t, err)
		require.NotContains(t, string(data), body)
	})
}
