package incident

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// CleanOptions configures a clean run.
type CleanOptions struct {
	DryRun      bool
	PurgeCaches bool
	CheckOpts   CheckOptions
}

// CleanAction describes a single cleanup action.
type CleanAction struct {
	Type   string `json:"type"`   // "uninstall", "delete", "disable", "purge"
	Target string `json:"target"` // what gets removed
	Done   bool   `json:"done"`
	Error  string `json:"error,omitempty"`
}

// CleanResult holds the outcome of a clean run.
type CleanResult struct {
	QuarantineDir string           `json:"quarantine_dir"`
	Actions       []CleanAction    `json:"actions"`
	Credentials   []CredentialFile `json:"credentials"`
	DryRun        bool             `json:"dry_run"`
}

// Clean detects and removes compromised packages and persistence artifacts.
func Clean(opts CleanOptions) (*CleanResult, error) {
	checkResult, err := Check(opts.CheckOpts)
	if err != nil {
		return nil, err
	}

	if len(checkResult.Findings) == 0 {
		return &CleanResult{
			DryRun:      opts.DryRun,
			Credentials: checkResult.Credentials,
		}, nil
	}

	ts := time.Now().Format("2006-01-02T150405")
	quarantine := filepath.Join(os.TempDir(), "aguara-quarantine", ts)

	result := &CleanResult{
		QuarantineDir: quarantine,
		DryRun:        opts.DryRun,
		Credentials:   checkResult.Credentials,
	}

	for _, f := range checkResult.Findings {
		switch {
		case strings.Contains(f.Title, "known compromised package"):
			// Extract package name from title ("litellm 1.82.8 is a known...")
			parts := strings.SplitN(f.Title, " ", 2)
			pkgName := parts[0]
			action := CleanAction{
				Type:   "uninstall",
				Target: pkgName,
			}
			if !opts.DryRun {
				action.Done, action.Error = uninstallPackage(pkgName)
			}
			result.Actions = append(result.Actions, action)

		case strings.Contains(f.Title, "contains executable code") && strings.HasSuffix(f.Path, ".pth"):
			action := CleanAction{
				Type:   "delete",
				Target: f.Path,
			}
			if !opts.DryRun {
				action.Done, action.Error = quarantineFile(f.Path, quarantine)
			}
			result.Actions = append(result.Actions, action)

		case strings.Contains(f.Title, "Persistence artifact"):
			path := f.Path
			info, err := os.Stat(path)
			if err != nil {
				continue
			}

			// Disable systemd service if applicable
			if strings.HasSuffix(path, ".service") {
				svcName := filepath.Base(path)
				action := CleanAction{
					Type:   "disable",
					Target: "systemctl --user disable " + svcName,
				}
				if !opts.DryRun {
					action.Done, action.Error = disableService(svcName)
				}
				result.Actions = append(result.Actions, action)
			}

			action := CleanAction{
				Type:   "delete",
				Target: path,
			}
			if !opts.DryRun {
				if info.IsDir() {
					action.Done, action.Error = quarantineDir(path, quarantine)
				} else {
					action.Done, action.Error = quarantineFile(path, quarantine)
				}
			}
			result.Actions = append(result.Actions, action)

		case strings.Contains(f.Title, "Cached compromised"):
			if opts.PurgeCaches {
				action := CleanAction{
					Type:   "purge",
					Target: f.Path,
				}
				if !opts.DryRun {
					action.Done, action.Error = removeFile(f.Path)
				}
				result.Actions = append(result.Actions, action)
			}
		}
	}

	// Purge pip/uv caches if requested
	if opts.PurgeCaches && !opts.DryRun {
		if path, err := exec.LookPath("pip"); err == nil {
			_ = exec.Command(path, "cache", "purge").Run()
		}
	}

	return result, nil
}

func uninstallPackage(name string) (bool, string) {
	// Try uv first, then pip
	for _, tool := range []string{"uv", "pip"} {
		path, err := exec.LookPath(tool)
		if err != nil {
			continue
		}
		var cmd *exec.Cmd
		if tool == "uv" {
			cmd = exec.Command(path, "pip", "uninstall", name, "--yes")
		} else {
			cmd = exec.Command(path, "uninstall", name, "-y")
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			return false, fmt.Sprintf("%s uninstall failed: %s", tool, strings.TrimSpace(string(out)))
		}
		return true, ""
	}
	return false, "neither pip nor uv found in PATH"
}

func quarantineFile(src, quarantineDir string) (bool, string) {
	if err := os.MkdirAll(quarantineDir, 0700); err != nil {
		return false, err.Error()
	}
	dst := filepath.Join(quarantineDir, filepath.Base(src))
	if err := os.Rename(src, dst); err != nil {
		// Cross-device? Copy then delete.
		data, readErr := os.ReadFile(src)
		if readErr != nil {
			return false, readErr.Error()
		}
		if writeErr := os.WriteFile(dst, data, 0600); writeErr != nil {
			return false, writeErr.Error()
		}
		_ = os.Remove(src)
	}
	return true, ""
}

func quarantineDir(src, quarantineDir string) (bool, string) {
	dst := filepath.Join(quarantineDir, filepath.Base(src))
	if err := os.MkdirAll(quarantineDir, 0700); err != nil {
		return false, err.Error()
	}
	if err := os.Rename(src, dst); err != nil {
		return false, err.Error()
	}
	return true, ""
}

func disableService(name string) (bool, string) {
	cmd := exec.Command("systemctl", "--user", "disable", name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false, strings.TrimSpace(string(out))
	}
	return true, ""
}

func removeFile(path string) (bool, string) {
	if err := os.Remove(path); err != nil {
		return false, err.Error()
	}
	return true, ""
}
