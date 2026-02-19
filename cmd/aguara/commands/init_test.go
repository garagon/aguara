package commands

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInitCreatesFiles(t *testing.T) {
	dir := t.TempDir()

	err := runInit(nil, []string{dir})
	require.NoError(t, err)

	// Check all files were created
	for _, name := range []string{
		".aguara.yml",
		".aguaraignore",
		filepath.Join(".github", "workflows", "aguara.yml"),
	} {
		path := filepath.Join(dir, name)
		_, err := os.Stat(path)
		require.NoError(t, err, "expected %s to exist", name)

		data, err := os.ReadFile(path)
		require.NoError(t, err)
		require.NotEmpty(t, data, "expected %s to have content", name)
	}
}

func TestInitSkipsExisting(t *testing.T) {
	dir := t.TempDir()

	// Pre-create .aguara.yml with custom content
	existing := filepath.Join(dir, ".aguara.yml")
	require.NoError(t, os.WriteFile(existing, []byte("custom: true\n"), 0644))

	err := runInit(nil, []string{dir})
	require.NoError(t, err)

	// Existing file should not be overwritten
	data, err := os.ReadFile(existing)
	require.NoError(t, err)
	require.Equal(t, "custom: true\n", string(data))

	// Other files should still be created
	_, err = os.Stat(filepath.Join(dir, ".aguaraignore"))
	require.NoError(t, err)
}

func TestInitCreatesSubdirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "subdir", "project")

	err := runInit(nil, []string{dir})
	require.NoError(t, err)

	_, err = os.Stat(filepath.Join(dir, ".aguara.yml"))
	require.NoError(t, err)

	_, err = os.Stat(filepath.Join(dir, ".github", "workflows", "aguara.yml"))
	require.NoError(t, err)
}

func TestInitHookCreatesPreCommit(t *testing.T) {
	dir := t.TempDir()
	// Create .git directory
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".git"), 0755))

	flagHook = true
	defer func() { flagHook = false }()

	err := runInit(nil, []string{dir})
	require.NoError(t, err)

	hookPath := filepath.Join(dir, ".git", "hooks", "pre-commit")
	info, err := os.Stat(hookPath)
	require.NoError(t, err)
	require.True(t, info.Mode()&0111 != 0, "hook should be executable")

	data, err := os.ReadFile(hookPath)
	require.NoError(t, err)
	require.Contains(t, string(data), "aguara scan")
}

func TestInitHookNoGitDir(t *testing.T) {
	dir := t.TempDir()

	flagHook = true
	defer func() { flagHook = false }()

	err := runInit(nil, []string{dir})
	require.Error(t, err)
	require.Contains(t, err.Error(), ".git")
}

func TestInitHookSkipsExisting(t *testing.T) {
	dir := t.TempDir()
	hooksDir := filepath.Join(dir, ".git", "hooks")
	require.NoError(t, os.MkdirAll(hooksDir, 0755))

	hookPath := filepath.Join(hooksDir, "pre-commit")
	require.NoError(t, os.WriteFile(hookPath, []byte("#!/bin/sh\necho custom\n"), 0755))

	flagHook = true
	defer func() { flagHook = false }()

	err := runInit(nil, []string{dir})
	require.NoError(t, err)

	data, err := os.ReadFile(hookPath)
	require.NoError(t, err)
	require.Contains(t, string(data), "echo custom", "existing hook should not be overwritten")
}

func TestInitCIOnly(t *testing.T) {
	dir := t.TempDir()

	flagCIOnly = true
	defer func() { flagCIOnly = false }()

	err := runInit(nil, []string{dir})
	require.NoError(t, err)

	// Workflow file should exist
	wfPath := filepath.Join(dir, ".github", "workflows", "aguara.yml")
	_, err = os.Stat(wfPath)
	require.NoError(t, err)

	// Config files should NOT exist
	_, err = os.Stat(filepath.Join(dir, ".aguara.yml"))
	require.True(t, os.IsNotExist(err), ".aguara.yml should not be created with --ci")

	_, err = os.Stat(filepath.Join(dir, ".aguaraignore"))
	require.True(t, os.IsNotExist(err), ".aguaraignore should not be created with --ci")
}

func TestInitDefaultDir(t *testing.T) {
	// Save and restore working directory
	orig, err := os.Getwd()
	require.NoError(t, err)
	defer func() { _ = os.Chdir(orig) }()

	dir := t.TempDir()
	require.NoError(t, os.Chdir(dir))

	err = runInit(nil, []string{})
	require.NoError(t, err)

	_, err = os.Stat(filepath.Join(dir, ".aguara.yml"))
	require.NoError(t, err)
}
