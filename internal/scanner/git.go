package scanner

import (
	"os/exec"
	"strings"
)

// GitChangedFiles returns files under root that have been modified,
// staged, or are untracked in the git repository containing root. root
// may be the repository root or any directory inside it; returned paths
// are relative to root (not to the repository root) so callers can join
// them to root. Binary extensions are filtered out. If root is not a git
// repository the function returns an empty slice and no error.
func GitChangedFiles(root string) ([]string, error) {
	// Check that git is available
	if _, err := exec.LookPath("git"); err != nil {
		return nil, nil
	}

	// Check we're inside a git repo
	if _, err := runGit(root, "rev-parse", "--git-dir"); err != nil {
		return nil, nil
	}

	seen := make(map[string]bool)
	var files []string

	// Tracked changes (staged + unstaged). Falls back to --cached for
	// repos without any commits yet. git diff reports paths relative to
	// the repository root; --relative makes them relative to root and
	// limits them to its subtree, matching ls-files below. Without it a
	// subdirectory target joined "sub/file.md" to "sub" and silently
	// skipped the file as deleted. -z keeps names with special
	// characters unquoted.
	out, err := runGit(root, "diff", "--relative", "--name-only", "-z", "HEAD")
	if err != nil {
		out, err = runGit(root, "diff", "--relative", "--name-only", "-z", "--cached")
		if err != nil {
			return nil, nil
		}
	}
	for _, f := range splitNUL(out) {
		if !seen[f] {
			seen[f] = true
			files = append(files, f)
		}
	}

	// Untracked files (already relative to root).
	out, err = runGit(root, "ls-files", "--others", "--exclude-standard", "-z")
	if err == nil {
		for _, f := range splitNUL(out) {
			if !seen[f] {
				seen[f] = true
				files = append(files, f)
			}
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

func runGit(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return "", err
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
