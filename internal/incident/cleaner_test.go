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

func TestQuarantineFileMovesIntoQuarantine(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "evil.pth")
	require.NoError(t, os.WriteFile(src, []byte("payload"), 0644))
	q := filepath.Join(dir, "quarantine")

	ok, errMsg := quarantineFile(src, q)
	require.True(t, ok, errMsg)

	_, err := os.Stat(src)
	assert.True(t, os.IsNotExist(err), "source must be gone after quarantine")
	data, err := os.ReadFile(filepath.Join(q, "evil.pth"))
	require.NoError(t, err)
	assert.Equal(t, "payload", string(data))
}

func TestQuarantineFileMissingSource(t *testing.T) {
	dir := t.TempDir()
	ok, errMsg := quarantineFile(filepath.Join(dir, "does-not-exist.pth"), filepath.Join(dir, "q"))
	assert.False(t, ok)
	assert.NotEmpty(t, errMsg)
}

func TestQuarantineDirMovesDirectory(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "evil-pkg")
	require.NoError(t, os.MkdirAll(src, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(src, "index.js"), []byte("x"), 0644))
	q := filepath.Join(dir, "quarantine")

	ok, errMsg := quarantineDir(src, q)
	require.True(t, ok, errMsg)

	_, err := os.Stat(src)
	assert.True(t, os.IsNotExist(err))
	_, err = os.Stat(filepath.Join(q, "evil-pkg", "index.js"))
	assert.NoError(t, err)
}

func TestQuarantineDirMissingSource(t *testing.T) {
	dir := t.TempDir()
	ok, errMsg := quarantineDir(filepath.Join(dir, "nope"), filepath.Join(dir, "q"))
	assert.False(t, ok)
	assert.NotEmpty(t, errMsg)
}

func TestRemoveFileHelper(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "victim.txt")
	require.NoError(t, os.WriteFile(path, []byte("x"), 0644))

	ok, errMsg := removeFile(path)
	require.True(t, ok, errMsg)
	_, err := os.Stat(path)
	assert.True(t, os.IsNotExist(err))

	ok, errMsg = removeFile(path)
	assert.False(t, ok, "second removal must report the miss")
	assert.NotEmpty(t, errMsg)
}

func TestUninstallPackageWithoutTools(t *testing.T) {
	// With an empty PATH neither uv nor pip resolve, so the helper
	// must fail with the documented message instead of hanging or
	// executing anything.
	t.Setenv("PATH", t.TempDir())
	ok, errMsg := uninstallPackage("evil-pkg")
	assert.False(t, ok)
	assert.Contains(t, errMsg, "neither pip nor uv found")
}

func TestDisableServiceWithoutSystemctl(t *testing.T) {
	// systemctl is absent from an empty PATH (and from macOS hosts);
	// the helper must report failure, not panic. Note the message is
	// empty in this path: CombinedOutput fails before producing any
	// output and the helper only relays command output, not the exec
	// error itself.
	t.Setenv("PATH", t.TempDir())
	ok, _ := disableService("evil.service")
	assert.False(t, ok)
}
