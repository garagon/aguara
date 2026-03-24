package incident

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCleanDryRunNoChanges(t *testing.T) {
	dir := t.TempDir()

	// Create a malicious .pth
	pth := filepath.Join(dir, "evil.pth")
	require.NoError(t, os.WriteFile(pth, []byte("import os; os.system('bad')"), 0644))

	result, err := Clean(CleanOptions{
		DryRun:    true,
		CheckOpts: CheckOptions{Path: dir},
	})
	require.NoError(t, err)
	assert.True(t, result.DryRun)

	// File should still exist (dry run)
	_, err = os.Stat(pth)
	assert.NoError(t, err, "dry run should not delete files")
}

func TestCleanQuarantinesFile(t *testing.T) {
	dir := t.TempDir()

	pth := filepath.Join(dir, "evil.pth")
	require.NoError(t, os.WriteFile(pth, []byte("import subprocess; subprocess.Popen(['evil'])"), 0644))

	result, err := Clean(CleanOptions{
		DryRun:    false,
		CheckOpts: CheckOptions{Path: dir},
	})
	require.NoError(t, err)

	// File should be removed from original location
	_, err = os.Stat(pth)
	assert.True(t, os.IsNotExist(err), "file should be quarantined (removed from original)")

	// Should be in quarantine
	assert.NotEmpty(t, result.QuarantineDir)
	quarantined := filepath.Join(result.QuarantineDir, "evil.pth")
	_, err = os.Stat(quarantined)
	assert.NoError(t, err, "file should exist in quarantine dir")
}

func TestCleanNothingFound(t *testing.T) {
	dir := t.TempDir()

	result, err := Clean(CleanOptions{
		CheckOpts: CheckOptions{Path: dir},
	})
	require.NoError(t, err)
	assert.Empty(t, result.Actions, "clean env should have no actions")
}

func TestCleanReportsCredentials(t *testing.T) {
	dir := t.TempDir()

	// Even with nothing to clean, credentials should be reported
	result, err := Clean(CleanOptions{
		CheckOpts: CheckOptions{Path: dir},
	})
	require.NoError(t, err)
	assert.NotEmpty(t, result.Credentials)
}

func TestCleanActionTypes(t *testing.T) {
	dir := t.TempDir()

	// Compromised package
	d := filepath.Join(dir, "litellm-1.82.8.dist-info")
	require.NoError(t, os.Mkdir(d, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(d, "METADATA"), []byte(
		"Name: litellm\nVersion: 1.82.8\n",
	), 0644))

	// Malicious .pth
	pth := filepath.Join(dir, "litellm_init.pth")
	require.NoError(t, os.WriteFile(pth, []byte("import os; os.system('bad')"), 0644))

	// Dry run to inspect actions without side effects
	result, err := Clean(CleanOptions{
		DryRun:    true,
		CheckOpts: CheckOptions{Path: dir},
	})
	require.NoError(t, err)

	types := map[string]bool{}
	for _, a := range result.Actions {
		types[a.Type] = true
	}
	assert.True(t, types["uninstall"], "should have uninstall action for compromised package")
	assert.True(t, types["delete"], "should have delete action for malicious .pth")
}
