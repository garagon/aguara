package scanner

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// ErrNotGitRepository reports that a --changed root is not inside a git
// work tree, so there is no change set to scan. It is an error rather
// than an empty change set: an empty result would read as a clean scan
// of changes that were never listed.
var ErrNotGitRepository = errors.New("not inside a git work tree")

// GitChangedFiles returns files under root that have been modified,
// staged, or are untracked in the git repository containing root. root
// may be the repository root or any directory inside it; returned paths
// are relative to root (not to the repository root) so callers can join
// them to root. Binary extensions are filtered out.
//
// Every failure to list changes is an error: git missing from PATH, a
// root that is not a directory inside a work tree (ErrNotGitRepository),
// or a git command that fails. An empty slice with a nil error means git
// listed no changes.
func GitChangedFiles(root string) ([]string, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return nil, fmt.Errorf("git is not available on PATH: %w", err)
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", root)
	}

	out, err := runGit(root, "rev-parse", "--is-inside-work-tree")
	if err != nil {
		return nil, fmt.Errorf("%s is %w (%v)", root, ErrNotGitRepository, err)
	}
	if strings.TrimSpace(out) != "true" {
		return nil, fmt.Errorf("%s is %w", root, ErrNotGitRepository)
	}

	seen := make(map[string]bool)
	var files []string

	// Tracked changes (staged + unstaged) against HEAD, or the index in
	// a repository without commits yet. git diff reports paths relative
	// to the repository root; --relative makes them relative to root and
	// limits them to its subtree, matching ls-files below. Without it a
	// subdirectory target joined "sub/file.md" to "sub" and silently
	// skipped the file as deleted. -z keeps names with special
	// characters unquoted.
	diff := []string{"diff", "--relative", "--name-only", "-z"}
	if _, err := runGit(root, "rev-parse", "--verify", "--quiet", "HEAD"); err == nil {
		diff = append(diff, "HEAD")
	} else {
		diff = append(diff, "--cached")
	}
	out, err = runGit(root, diff...)
	if err != nil {
		return nil, fmt.Errorf("listing changed files: %w", err)
	}
	for _, f := range splitNUL(out) {
		if !seen[f] {
			seen[f] = true
			files = append(files, f)
		}
	}

	// Untracked files (already relative to root).
	out, err = runGit(root, "ls-files", "--others", "--exclude-standard", "-z")
	if err != nil {
		return nil, fmt.Errorf("listing untracked files: %w", err)
	}
	for _, f := range splitNUL(out) {
		if !seen[f] {
			seen[f] = true
			files = append(files, f)
		}
	}

	// Filter out binary extensions
	var result []string
	for _, f := range files {
		if !isBinaryExt(f) {
			result = append(result, f)
		}
	}
	return result, nil
}

// GitSubmodulePaths returns the git submodules (gitlink entries of the
// index) under root, relative to root like GitChangedFiles. A changed
// submodule is listed by GitChangedFiles as its path; this set tells a
// submodule that is not checked out apart from a deleted file.
func GitSubmodulePaths(root string) (map[string]bool, error) {
	out, err := runGit(root, "ls-files", "--stage", "-z")
	if err != nil {
		return nil, fmt.Errorf("listing submodules: %w", err)
	}
	submodules := map[string]bool{}
	for _, entry := range splitNUL(out) {
		// "<mode> <object> <stage>\t<path>"; gitlinks have mode 160000.
		meta, path, ok := strings.Cut(entry, "\t")
		if ok && strings.HasPrefix(meta, "160000 ") {
			submodules[path] = true
		}
	}
	return submodules, nil
}

// runGit runs git in dir and returns stdout. A failure carries git's
// stderr so the caller can show why (for example a repository git
// refuses to use because of its ownership).
func runGit(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			if msg := strings.TrimSpace(string(exitErr.Stderr)); msg != "" {
				return "", fmt.Errorf("git %s: %s", args[0], msg)
			}
		}
		return "", fmt.Errorf("git %s: %w", args[0], err)
	}
	return string(out), nil
}

// splitNUL splits git's -z output into non-empty paths.
func splitNUL(s string) []string {
	var out []string
	for _, f := range strings.Split(s, "\x00") {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}
