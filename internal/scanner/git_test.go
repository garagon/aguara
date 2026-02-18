package scanner_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/garagon/aguara/internal/scanner"
	"github.com/stretchr/testify/require"
)

func skipIfNoGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
}

func TestGitChangedFilesModifiedAndUntracked(t *testing.T) {
	skipIfNoGit(t)

	dir := t.TempDir()

	// Init repo and create initial commit
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=test",
			"GIT_AUTHOR_EMAIL=test@test.com",
			"GIT_COMMITTER_NAME=test",
			"GIT_COMMITTER_EMAIL=test@test.com",
		)
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "git %v: %s", args, out)
	}

	run("init")
	run("config", "user.email", "test@test.com")
	run("config", "user.name", "test")

	// Create and commit initial file
	require.NoError(t, os.WriteFile(filepath.Join(dir, "committed.md"), []byte("ok"), 0644))
	run("add", "committed.md")
	run("commit", "-m", "init")

	// Modify tracked file
	require.NoError(t, os.WriteFile(filepath.Join(dir, "committed.md"), []byte("changed"), 0644))

	// Add untracked text file
	require.NoError(t, os.WriteFile(filepath.Join(dir, "untracked.txt"), []byte("new"), 0644))

	// Add binary file (should be filtered)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "image.png"), []byte{0x89, 0x50}, 0644))

	files, err := scanner.GitChangedFiles(dir)
	require.NoError(t, err)

	require.Contains(t, files, "committed.md")
	require.Contains(t, files, "untracked.txt")

	for _, f := range files {
		require.NotEqual(t, "image.png", f, "binary files should be filtered")
	}
}

func TestGitChangedFilesNotARepo(t *testing.T) {
	skipIfNoGit(t)

	dir := t.TempDir()
	files, err := scanner.GitChangedFiles(dir)
	require.NoError(t, err)
	require.Empty(t, files)
}
