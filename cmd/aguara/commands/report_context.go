package commands

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/garagon/aguara/internal/output"
	"github.com/garagon/aguara/internal/rulecatalog"
	"github.com/garagon/aguara/internal/rulemeta"
	"github.com/garagon/aguara/internal/types"
)

// scanReport is what a scan report needs beyond the ScanResult: the rule
// configuration (for rule documentation and the catalog identity), the
// target the finding paths are relative to (for repository-relative SARIF
// locations) and how the command will exit (for SARIF invocations).
type scanReport struct {
	res *rulecatalog.Resolution
	// target is the scanned path; "" when the findings do not belong to
	// one directory (scan --auto).
	target string
	// runErr is the error the command returns after writing the report:
	// nil, a gate error (exit 1) or another error (exit 2).
	runErr error
	// threshold is the --fail-on value in effect, for the exit
	// description of a run that did not trip it.
	threshold string
	// notes are extra tool execution notifications for the SARIF run.
	notes []output.SARIFNotification
}

// toolInfo identifies this binary in JSON reports.
func toolInfo() types.ToolInfo {
	commit := Commit
	if commit == "none" {
		commit = ""
	}
	return types.ToolInfo{Name: "aguara", Version: Version, Commit: commit}
}

// reportHeader is the schema_version / tool / catalog header of the JSON
// reports. res may be nil, which omits the catalog.
func reportHeader(res *rulecatalog.Resolution) *output.ReportHeader {
	h := &output.ReportHeader{SchemaVersion: output.ReportSchemaVersion, Tool: toolInfo()}
	if res != nil {
		id := res.Identity()
		h.Catalog = &id
	}
	return h
}

// builtinCatalog resolves the built-in rules only, for reports of commands
// that take no rule options (check, version).
func builtinCatalog() *rulecatalog.Resolution {
	res, err := rulecatalog.Resolve(rulecatalog.Input{})
	if err != nil {
		return nil
	}
	return res
}

// sarifOptions builds the SARIF run options for a report.
func sarifOptions(rep scanReport) output.SARIFOptions {
	opts := output.SARIFOptions{Category: flagSARIFCategory, Commit: toolInfo().Commit}
	if rep.res != nil {
		opts.Catalog = rulemeta.Index(rep.res.Catalog(""))
		opts.BuiltinRules = rulecatalog.BuiltinIDs()
		id := rep.res.Identity()
		opts.CatalogDigest = &id
	}
	if rep.target != "" {
		opts.URIPrefix, opts.InWorkTree = sarifURIBase(rep.target)
		opts.LocalRoots = localRoots(rep.target)
	}
	opts.Invocation = sarifInvocation(rep.runErr, rep.threshold, rep.notes)
	return opts
}

// sarifInvocation describes how the command ends: exit 0 or 1 means the
// analysis completed; exit 2 means it did not (or the command was misused),
// which is recorded as an unsuccessful execution with the reason as an
// error notification.
func sarifInvocation(runErr error, threshold string, notes []output.SARIFNotification) *output.SARIFInvocation {
	code := exitCodeFor(runErr)
	inv := &output.SARIFInvocation{
		ExecutionSuccessful: code != exitError,
		ExitCode:            code,
		ExitCodeDescription: gateDescription(runErr, threshold),
		Notifications:       append([]output.SARIFNotification(nil), notes...),
	}
	if code == exitError {
		inv.Notifications = append(inv.Notifications, output.SARIFNotification{Level: "error", Message: runErr.Error()})
	}
	return inv
}

// sarifURIBase returns how SARIF artifact URIs are rooted for a scan of
// target: when target is inside a git work tree, the slash path from the
// work tree root to the directory finding paths are relative to (target,
// or a file target's directory) and true; otherwise "" and false, which
// keeps URIs relative to the target. URIs are never absolute.
func sarifURIBase(target string) (prefix string, inWorkTree bool) {
	dir, ok := resolvedDir(target)
	if !ok {
		return "", false
	}
	root, ok := workTreeRoot(dir)
	if !ok {
		return "", false
	}
	rel, err := filepath.Rel(root, dir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	if rel == "." {
		return "", true
	}
	return filepath.ToSlash(rel), true
}

// resolvedDir is target as an absolute path with symbolic links resolved,
// or its directory when target is a file.
func resolvedDir(target string) (string, bool) {
	abs, err := filepath.Abs(target)
	if err != nil {
		return "", false
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", false
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", false
	}
	if !info.IsDir() {
		resolved = filepath.Dir(resolved)
	}
	return resolved, true
}

// workTreeRoot walks up from dir to the nearest directory holding a .git
// entry (a directory, or a file for linked work trees and submodules).
func workTreeRoot(dir string) (string, bool) {
	for d := dir; ; {
		if info, err := os.Lstat(filepath.Join(d, ".git")); err == nil && (info.IsDir() || info.Mode().IsRegular()) {
			return d, true
		}
		parent := filepath.Dir(d)
		if parent == d {
			return "", false
		}
		d = parent
	}
}

// sourceRelativeURI maps a file path (absolute or relative to the working
// directory) to a SARIF URI relative to base, the source root (a work tree
// root or a scan directory). It returns "" when the file is not under base.
func sourceRelativeURI(base, p string) string {
	if base == "" || p == "" {
		return ""
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	} else if dir, err := filepath.EvalSymlinks(filepath.Dir(abs)); err == nil {
		// A dangling or unreadable leaf still maps through its directory.
		abs = filepath.Join(dir, filepath.Base(abs))
	}
	rel, err := filepath.Rel(base, abs)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return ""
	}
	return filepath.ToSlash(rel)
}

// localRoots lists the absolute local directories SARIF output for target
// is relative to: the git work tree root when target is inside one, else
// the target directory, each in its resolved and in its written form (they
// differ when the path goes through a symbolic link, such as /tmp on
// macOS). SARIF rewrites paths under them as relative and drops any other
// absolute path from run properties.
func localRoots(target string) []string {
	if target == "" {
		target = "."
	}
	dir, ok := resolvedDir(target)
	if !ok {
		return nil
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		return []string{dir}
	}
	if info, err := os.Stat(abs); err == nil && !info.IsDir() {
		abs = filepath.Dir(abs)
	}
	base := dir
	if root, ok := workTreeRoot(dir); ok {
		base = root
	}
	roots := []string{base}
	// The written form of base: abs with the same suffix below base.
	if rel, err := filepath.Rel(base, dir); err == nil {
		written := abs
		if rel != "." {
			written = strings.TrimSuffix(abs, string(filepath.Separator)+rel)
		}
		if written != base {
			roots = append(roots, written)
		}
	}
	return roots
}

// sarifSourceRoot is the directory package finding URIs are relative to
// for a check or audit of target: the git work tree root when target is in
// one (true), else the target directory itself (false).
func sarifSourceRoot(target string) (string, bool) {
	if target == "" {
		target = "."
	}
	dir, ok := resolvedDir(target)
	if !ok {
		return "", false
	}
	if root, ok := workTreeRoot(dir); ok {
		return root, true
	}
	return dir, false
}
