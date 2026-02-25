package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// checkPathHint prints a one-time hint to stderr if the aguara binary
// appears to live in a go/bin directory that isn't in the user's PATH.
// All errors are silently ignored — this is a best-effort UX hint.
func checkPathHint() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return
	}

	dir := filepath.Dir(exe)
	if !isGoBinDir(dir) {
		return
	}

	if dirInPATH(dir) {
		return
	}

	marker := hintMarkerPath()
	if marker == "" {
		return
	}
	if _, err := os.Stat(marker); err == nil {
		return // already shown
	}

	rcFile := shellConfigFile()
	fmt.Fprintf(os.Stderr, "\nTip: Add Go's bin directory to your PATH to run aguara from anywhere:\n\n")
	fmt.Fprintf(os.Stderr, "  echo 'export PATH=\"$HOME/go/bin:$PATH\"' >> %s\n", rcFile)
	fmt.Fprintf(os.Stderr, "  source %s\n\n", rcFile)

	// Write marker so we never show again.
	_ = os.MkdirAll(filepath.Dir(marker), 0o755)
	_ = os.WriteFile(marker, nil, 0o644)
}

// isGoBinDir reports whether dir ends with a "go/bin" segment.
func isGoBinDir(dir string) bool {
	dir = filepath.ToSlash(dir)
	return strings.HasSuffix(dir, "/go/bin")
}

// dirInPATH reports whether dir appears in the system PATH.
func dirInPATH(dir string) bool {
	for _, p := range filepath.SplitList(os.Getenv("PATH")) {
		if p == dir {
			return true
		}
	}
	return false
}

// shellConfigFile returns the user's shell rc file path based on $SHELL,
// falling back to OS defaults (zsh on macOS, bash on Linux).
func shellConfigFile() string {
	shell := os.Getenv("SHELL")
	switch {
	case strings.Contains(shell, "zsh"):
		return "~/.zshrc"
	case strings.Contains(shell, "bash"):
		return "~/.bashrc"
	default:
		if runtime.GOOS == "darwin" {
			return "~/.zshrc"
		}
		return "~/.bashrc"
	}
}

// hintMarkerPath returns the path to the marker file that records
// we've already shown the PATH hint. Returns "" if home dir is unknown.
func hintMarkerPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".aguara", ".path-hint-shown")
}
