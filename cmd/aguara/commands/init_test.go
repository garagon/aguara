package commands

import (
	"os"
	"path/filepath"
	"strings"
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

func TestInitWorkflowUsesActionNotBrokenAsset(t *testing.T) {
	// QA regression on v0.16.0: the scaffolded workflow downloaded
	// `aguara-linux-amd64` from /releases/latest/download/, an asset
	// shape that does not exist (release assets are tar.gz archives
	// like `aguara_0.16.0_linux_amd64.tar.gz`). The curl 404'd and
	// every new-user CI job broke at install.
	//
	// The workflow must now:
	//   1. NOT reference the broken `aguara-linux-amd64` asset,
	//   2. NOT manually curl install.sh in the workflow itself
	//      (the action does that with checksum verification),
	//   3. USE the official `garagon/aguara` action so version pin
	//      + checksum verify happen via the action's contract.
	dir := t.TempDir()
	require.NoError(t, runInit(nil, []string{dir}))

	wf, err := os.ReadFile(filepath.Join(dir, ".github", "workflows", "aguara.yml"))
	require.NoError(t, err)
	body := string(wf)

	require.NotContains(t, body, "aguara-linux-amd64",
		"workflow must not reference the non-existent aguara-linux-amd64 asset (release assets are tar.gz archives)")
	require.NotContains(t, body, "/releases/latest/download/aguara",
		"workflow must not curl release assets directly; the action handles install + checksum")
	require.True(t, strings.Contains(body, "uses: garagon/aguara@"),
		"workflow must invoke the official garagon/aguara action so version pin + checksum verify are guaranteed")
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
