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

// initGitRepo creates a repository with one commit containing files.
func initGitRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@test.com",
			"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@test.com",
		)
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "git %v: %s", args, out)
	}
	run("init", "-q")
	for name, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	}
	run("add", ".")
	run("commit", "-q", "-m", "init")
	return dir
}

// A subdirectory target gets paths relative to itself, limited to its
// subtree. git diff used to report repository-root-relative paths, so
// "sub/tracked.md" was joined to "sub" and the change silently skipped.
func TestGitChangedFilesFromSubdirectory(t *testing.T) {
	skipIfNoGit(t)
	repo := initGitRepo(t, map[string]string{
		"top.md":            "ok",
		"sub/tracked.md":    "ok",
		"sub/deep/other.md": "ok",
	})
	for _, name := range []string{"top.md", "sub/tracked.md", "sub/deep/other.md"} {
		require.NoError(t, os.WriteFile(filepath.Join(repo, filepath.FromSlash(name)), []byte("changed"), 0o644))
	}
	require.NoError(t, os.WriteFile(filepath.Join(repo, "sub", "new.md"), []byte("new"), 0o644))

	files, err := scanner.GitChangedFiles(filepath.Join(repo, "sub"))
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"tracked.md", "deep/other.md", "new.md"}, files)
	for _, f := range files {
		_, err := os.Stat(filepath.Join(repo, "sub", filepath.FromSlash(f)))
		require.NoError(t, err, "%s must resolve under the target", f)
	}

	files, err = scanner.GitChangedFiles(repo)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"top.md", "sub/tracked.md", "sub/deep/other.md", "sub/new.md"}, files)
}

// Names git would quote (non-ASCII, spaces) come back verbatim.
func TestGitChangedFilesKeepsSpecialNamesUnquoted(t *testing.T) {
	skipIfNoGit(t)
	repo := initGitRepo(t, map[string]string{"notas añadidas.md": "ok"})
	require.NoError(t, os.WriteFile(filepath.Join(repo, "notas añadidas.md"), []byte("changed"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(repo, "nueva página.md"), []byte("new"), 0o644))

	files, err := scanner.GitChangedFiles(repo)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"notas añadidas.md", "nueva página.md"}, files)
}

func TestGitChangedFilesNotARepo(t *testing.T) {
	skipIfNoGit(t)

	// Outside a work tree there is no change set; an empty result would
	// read as "no changes" and let a --changed scan pass on nothing.
	dir := t.TempDir()
	files, err := scanner.GitChangedFiles(dir)
	require.ErrorIs(t, err, scanner.ErrNotGitRepository)
	require.Empty(t, files)
}

func TestGitChangedFilesRejectsFileRoot(t *testing.T) {
	skipIfNoGit(t)
	repo := initGitRepo(t, map[string]string{"a.md": "ok"})
	_, err := scanner.GitChangedFiles(filepath.Join(repo, "a.md"))
	require.ErrorContains(t, err, "is not a directory")
}

// A repository without commits lists staged files from the index.
func TestGitChangedFilesWithoutCommits(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	for _, args := range [][]string{{"init", "-q"}, {"add", "staged.md"}} {
		if args[0] == "add" {
			require.NoError(t, os.WriteFile(filepath.Join(dir, "staged.md"), []byte("new"), 0o644))
		}
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "git %v: %s", args, out)
	}
	files, err := scanner.GitChangedFiles(dir)
	require.NoError(t, err)
	require.Equal(t, []string{"staged.md"}, files)
}

// GitSubmoduleHead reads a commit only for the top of a work tree: a
// directory inside the superproject (a submodule that is not checked out,
// with stray files) must not report the superproject's HEAD.
func TestGitSubmoduleHeadOnlyForWorkTreeTop(t *testing.T) {
	skipIfNoGit(t)
	dir := t.TempDir()
	run := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=t@t")
		out, err := cmd.Output()
		require.NoError(t, err, "git %v", args)
		return string(out)
	}
	run("init", "-q")
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "sub"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "sub", "a.md"), []byte("a"), 0o600))
	run("add", ".")
	run("commit", "-q", "-m", "init")
	head := run("rev-parse", "HEAD")
	require.Equal(t, head[:len(head)-1], scanner.GitSubmoduleHead(dir))
	require.Empty(t, scanner.GitSubmoduleHead(filepath.Join(dir, "sub")))
	require.Empty(t, scanner.GitSubmoduleHead(t.TempDir()), "not a work tree")
}
