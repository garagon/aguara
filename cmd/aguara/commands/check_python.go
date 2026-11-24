package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/garagon/aguara/internal/incident"
	"github.com/garagon/aguara/internal/intel"
	"github.com/garagon/aguara/internal/packagecheck"
)

// ecoPythonLock labels plans whose only Python evidence is dependency
// files (uv.lock, poetry.lock, requirements.txt, ...). ecoPython stays
// the label of the installed-environment check, whose terminal guidance
// points at `aguara clean`, which does not apply to a lockfile.
const ecoPythonLock = "python-lockfile"

// pythonEnvironment is one virtual environment a check evaluates in
// addition to the target's dependency files.
type pythonEnvironment struct {
	root         string // the environment directory
	sitePackages string
	origin       string // "target", ".venv", "venv" or "VIRTUAL_ENV"
}

// discoverPythonEnvironments returns the virtual environments that
// belong to the target directory root:
//
//   - root itself, when it is a virtual environment;
//   - root/.venv and root/venv;
//   - the environment named by VIRTUAL_ENV, when it is inside root.
//
// When implicit is true (no path was given, so the target is the current
// directory), the active VIRTUAL_ENV is also evaluated wherever it lives:
// it is the environment the user is working in. For an explicit path an
// unrelated active environment is never read.
//
// A project-local candidate must resolve to a directory inside root (a
// symlinked .venv pointing elsewhere is not project evidence) holding a
// pyvenv.cfg marker, and its site-packages must resolve inside it. The
// active environment follows the same site-packages layout lookup the
// installed-tree check has always used for VIRTUAL_ENV.
func discoverPythonEnvironments(root string, implicit bool) []pythonEnvironment {
	rootReal, err := realPath(root)
	if err != nil {
		return nil
	}
	type candidate struct {
		dir, origin string
		local       bool
	}
	candidates := []candidate{
		{root, "target", true},
		{filepath.Join(root, ".venv"), ".venv", true},
		{filepath.Join(root, "venv"), "venv", true},
	}
	if venv := os.Getenv("VIRTUAL_ENV"); venv != "" {
		if venvReal, err := realPath(venv); err == nil && pathWithin(rootReal, venvReal) {
			candidates = append(candidates, candidate{venv, "VIRTUAL_ENV", true})
		} else if implicit {
			candidates = append(candidates, candidate{venv, "VIRTUAL_ENV", false})
		}
	}
	var out []pythonEnvironment
	seen := map[string]bool{}
	for _, c := range candidates {
		dirReal, err := realPath(c.dir)
		if err != nil || seen[dirReal] {
			continue
		}
		if c.local && (!pathWithin(rootReal, dirReal) || !isVirtualEnvRoot(dirReal)) {
			continue
		}
		sites := venvSitePackages(c.dir, dirReal, c.local)
		if len(sites) == 0 {
			continue
		}
		seen[dirReal] = true
		for _, site := range sites {
			out = append(out, pythonEnvironment{root: c.dir, sitePackages: site, origin: c.origin})
		}
	}
	return out
}

// isVirtualEnvRoot reports a PEP 405 environment: pyvenv.cfg is a
// regular file at its root.
func isVirtualEnvRoot(dir string) bool {
	info, err := os.Lstat(filepath.Join(dir, "pyvenv.cfg"))
	return err == nil && info.Mode().IsRegular()
}

// venvSitePackages lists the site-packages directories of a virtual
// environment (POSIX CPython and PyPy layouts, and the Windows Lib
// layout). For a project-local environment each one must resolve inside
// the environment.
func venvSitePackages(dir, dirReal string, local bool) []string {
	var out []string
	for _, pattern := range []string{
		filepath.Join(dir, "lib", "python*", "site-packages"),
		filepath.Join(dir, "lib", "pypy*", "site-packages"),
		filepath.Join(dir, "Lib", "site-packages"),
	} {
		matches, _ := filepath.Glob(pattern)
		for _, m := range matches {
			if !statDir(m) {
				continue
			}
			if local {
				if r, err := realPath(m); err != nil || !pathWithin(dirReal, r) {
					continue
				}
			}
			if !containsString(out, m) {
				out = append(out, m)
			}
		}
	}
	return out
}

func realPath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(abs)
}

func pathWithin(root, p string) bool {
	rel, err := filepath.Rel(root, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// addPythonEnvironments attaches the target's virtual environments to
// the plan. When the legacy installed-tree check runs with
// auto-discovery (no path), it already reads the VIRTUAL_ENV
// environment, so that environment is not evaluated twice.
func addPythonEnvironments(plan *checkPlan, root string, implicit bool) {
	plan.pythonEnvs = discoverPythonEnvironments(root, implicit)
	if !plan.runPython || plan.pythonPath != "" {
		return
	}
	venv := os.Getenv("VIRTUAL_ENV")
	if venv == "" {
		return
	}
	venvReal, err := realPath(venv)
	if err != nil {
		return
	}
	kept := plan.pythonEnvs[:0]
	for _, env := range plan.pythonEnvs {
		if r, err := realPath(env.root); err == nil && r == venvReal {
			continue
		}
		kept = append(kept, env)
	}
	plan.pythonEnvs = kept
}

// hasNonPythonTargets reports a discovered dependency file of any
// ecosystem other than PyPI. `aguara check` without a path falls back to
// the installed-environment check only when there is none, which keeps
// that fallback where it was before Python dependency files were read.
func hasNonPythonTargets(targets []packagecheck.Target) bool {
	for _, t := range targets {
		if t.Ecosystem != intel.EcosystemPyPI {
			return true
		}
	}
	return false
}

// wantsPythonDependencyFiles reports whether an explicit --ecosystem
// python check should also discover dependency files and environments
// under path. A path that is itself an installed tree keeps the
// historical installed-tree-only behaviour.
func wantsPythonDependencyFiles(path string) bool {
	if path == "" {
		return true
	}
	resolved, err := filepath.Abs(path)
	if err != nil {
		resolved = path
	}
	return !looksLikePythonSitePackages(resolved)
}

// runPythonEnvironments evaluates every environment in the plan.
func runPythonEnvironments(plan checkPlan, override *incident.IntelOverride) ([]*incident.CheckResult, error) {
	var parts []*incident.CheckResult
	for _, env := range plan.pythonEnvs {
		r, err := incident.CheckEnvironment(incident.CheckOptions{Path: env.sitePackages, Intel: override})
		if err != nil {
			return nil, err
		}
		parts = append(parts, r)
	}
	return parts, nil
}

// pythonLockFindingText words a PyPI dependency-file hit: every matching
// advisory ID, the dependency group when the file records one, and an
// unpinned entry's declared specifier.
func pythonLockFindingText(hit packagecheck.Hit) (title, remediation string) {
	ids := hit.AdvisoryIDs
	if len(ids) == 0 {
		ids = []string{hit.Record.ID}
	}
	name, version := hit.Ref.Name, hit.Ref.Version
	if hit.Ref.Unpinned {
		version = "(unpinned"
		if hit.Ref.Constraint != "" {
			version += " " + hit.Ref.Constraint
		}
		version += "; every version is affected)"
	}
	title = fmt.Sprintf("%s %s is a known compromised PyPI package (%s)", name, version, strings.Join(ids, ", "))
	const rotate = " Rotate credentials reachable from environments and CI runs that installed it."
	if strings.HasSuffix(hit.Ref.Source, ".txt") {
		kind := "requirement"
		if hit.Ref.Group == "constraint" {
			kind = "constraint"
		}
		remediation = fmt.Sprintf("Remove or change the %s %s in %s so no affected release is selected, without installing the compromised version.", name, kind, hit.Ref.Source) + rotate
		return title, remediation
	}
	group := ""
	if hit.Ref.Group != "" {
		group = fmt.Sprintf(" (dependency group: %s)", hit.Ref.Group)
	}
	remediation = fmt.Sprintf("Remove %s%s from the project's dependencies or require a release no advisory covers, then regenerate %s without installing the compromised version.", name, group, hit.Ref.Source) + rotate
	return title, remediation
}
