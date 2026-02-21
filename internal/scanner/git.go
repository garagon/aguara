package scanner

import (
	"os/exec"
	"strings"
)

// GitChangedFiles returns files that have been modified, staged, or are
// untracked in the git repository rooted at root. Binary extensions are
// filtered out. If root is not a git repository the function returns an
// empty slice and no error.
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
	// repos without any commits yet.
	out, err := runGit(root, "diff", "--name-only", "HEAD")
	if err != nil {
		out, err = runGit(root, "diff", "--name-only", "--cached")
		if err != nil {
			return nil, nil
		}
	}
	for _, f := range splitLines(out) {
		if f != "" && !seen[f] {
			seen[f] = true
			files = append(files, f)
		}
	}

	// Untracked files
	out, err = runGit(root, "ls-files", "--others", "--exclude-standard")
	if err == nil {
		for _, f := range splitLines(out) {
			if f != "" && !seen[f] {
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

func splitLines(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}
