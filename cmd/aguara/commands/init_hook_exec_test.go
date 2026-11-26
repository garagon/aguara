package commands

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// stubScanner writes an aguara stand-in that records its arguments and the
// files of the directory it is asked to scan (NUL-separated, relative to
// that directory), and fails like a threshold breach when any of them
// contains MALICIOUS.
func stubScanner(t *testing.T) (bin, record string) {
	t.Helper()
	dir := t.TempDir()
	bin = filepath.Join(dir, "aguara-stub")
	record = filepath.Join(dir, "record")
	script := `#!/bin/sh
[ "$1" = scan ] || exit 3
echo "notice: applied policy owned by the scanned project: $2/.aguaraignore (pass --project-policy ignore to scan without it)" >&2
echo "  Target: $2  ·  3 files"
echo "  ✖ RULE_001  $2/docs/x.md:1"
printf '%s\n' "$*" >"` + record + `.args"
(cd "$2" && find . -type f -print0) >"` + record + `"
if grep -rq MALICIOUS "$2"; then
	echo "stub: findings" >&2
	exit 1
fi
exit 0
`
	require.NoError(t, os.WriteFile(bin, []byte(script), 0o755))
	return bin, record
}

func recordedFiles(t *testing.T, record string) []string {
	t.Helper()
	data, err := os.ReadFile(record)
	require.NoError(t, err)
	var files []string
	for _, f := range strings.Split(string(data), "\x00") {
		if f != "" {
			files = append(files, strings.TrimPrefix(f, "./"))
		}
	}
	sort.Strings(files)
	return files
}

func commitWithHook(t *testing.T, repo, bin string) (string, error) {
	t.Helper()
	c := exec.Command("git", "commit", "-q", "-m", "change")
	c.Dir = repo
	c.Env = append(os.Environ(),
		"AGUARA_BIN="+bin,
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=t@t",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=t@t",
	)
	out, err := c.CombinedOutput()
	return string(out), err
}

func writeRepoFile(t *testing.T, repo, name, content string) {
	t.Helper()
	path := filepath.Join(repo, name)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

// The generated hook scans what the commit will contain: the staged blobs
// of added and modified files, under their repository paths, including
// names with spaces and newlines. Untracked files and work tree edits that
// are not staged are not scanned, and a commit that stages malicious
// content is blocked even when the work tree copy was cleaned afterwards.
func TestPreCommitHookScansStagedContent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the hook is a POSIX shell script")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}
	repo := gitRepo(t)
	bin, record := stubScanner(t)
	captureStdoutBytes(t, func() { require.NoError(t, initHook(repo)) })

	writeRepoFile(t, repo, ".aguaraignore", "dist/\n")
	writeRepoFile(t, repo, "README.md", "# project\n")
	runGit(t, repo, "add", ".aguaraignore", "README.md")
	out, err := commitWithHook(t, repo, bin)
	require.NoError(t, err, out)

	// Clean staged files with awkward names; malicious content only in an
	// untracked file and in an unstaged edit.
	writeRepoFile(t, repo, "docs/notes with space.md", "# notes\n")
	writeRepoFile(t, repo, "line\nbreak.md", "# odd name\n")
	writeRepoFile(t, repo, "untracked.md", "MALICIOUS\n")
	runGit(t, repo, "add", "docs/notes with space.md", "line\nbreak.md")
	writeRepoFile(t, repo, "README.md", "MALICIOUS unstaged edit\n")
	out, err = commitWithHook(t, repo, bin)
	require.NoError(t, err, out)
	require.Equal(t, []string{".aguaraignore", "docs/notes with space.md", "line\nbreak.md"}, recordedFiles(t, record),
		"only staged files are scanned, plus the committed .aguaraignore")
	args, err := os.ReadFile(record + ".args")
	require.NoError(t, err)
	require.Contains(t, string(args), "--fail-on high")
	// Notices name repository paths, not the temporary copy, and do not
	// suggest a flag the hook does not take.
	require.Contains(t, out, "notice: applied policy owned by the scanned project: .aguaraignore\n")
	require.Contains(t, out, "  Target: staged files  ·  3 files\n", "the report names the staged files, not the temporary copy")
	require.Contains(t, out, "  ✖ RULE_001  docs/x.md:1\n")
	require.NotContains(t, out, "aguara-pre-commit.")
	require.NotContains(t, out, "--project-policy")

	// Malicious content staged, then the work tree copy reverted.
	writeRepoFile(t, repo, "SKILL.md", "MALICIOUS staged\n")
	runGit(t, repo, "add", "SKILL.md")
	writeRepoFile(t, repo, "SKILL.md", "# harmless\n")
	out, err = commitWithHook(t, repo, bin)
	require.Error(t, err, "a commit of malicious staged content is blocked")
	require.Contains(t, out, "commit blocked")

	// Clean content staged, malicious content only in the work tree.
	runGit(t, repo, "add", "SKILL.md")
	writeRepoFile(t, repo, "SKILL.md", "MALICIOUS unstaged\n")
	out, err = commitWithHook(t, repo, bin)
	require.NoError(t, err, out)

	// A commit with nothing to scan (only a deletion) does not run the
	// scanner at all.
	require.NoError(t, os.Remove(record))
	runGit(t, repo, "rm", "-q", "docs/notes with space.md")
	out, err = commitWithHook(t, repo, bin)
	require.NoError(t, err, out)
	_, err = os.Stat(record)
	require.True(t, os.IsNotExist(err), "the scanner is not run for a commit without content")
}

// Without the scanner the hook fails closed with a message instead of
// letting every commit through.
func TestPreCommitHookFailsWhenScannerIsMissing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the hook is a POSIX shell script")
	}
	repo := gitRepo(t)
	captureStdoutBytes(t, func() { require.NoError(t, initHook(repo)) })
	writeRepoFile(t, repo, "README.md", "# project\n")
	runGit(t, repo, "add", "README.md")
	out, err := commitWithHook(t, repo, filepath.Join(t.TempDir(), "no-such-aguara"))
	require.Error(t, err)
	require.Contains(t, out, "not found")
}
