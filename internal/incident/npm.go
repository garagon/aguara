package incident

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// NPMPackage is a package parsed from a node_modules entry's package.json.
type NPMPackage struct {
	Name    string
	Version string
	Dir     string // package.json's containing directory
}

// CheckNPM scans a node_modules tree (recursively, since deps install
// nested copies) and reports any installed package whose
// (ecosystem, name, version) tuple matches the embedded npm IOC set.
// The check is offline and read-only.
//
// opts.Path must point at a node_modules directory. The caller is
// responsible for choosing the right tree (project node_modules, a
// global install, an unpacked tarball under tmp). If opts.Path is
// empty CheckNPM returns an error rather than guessing, because
// `aguara check` for npm has no canonical autodiscovery location and
// silently scanning the wrong tree would mislead the operator.
func CheckNPM(opts CheckOptions) (*CheckResult, error) {
	if opts.Path == "" {
		return nil, fmt.Errorf("npm check requires --path pointing at a node_modules directory or a project root that contains one")
	}
	root, err := resolveNPMRoot(opts.Path)
	if err != nil {
		return nil, err
	}

	// Initialize the result with non-nil slices so the JSON output is
	// the stable `[]` shape (not `null`) when nothing is found.
	// Credentials is still empty here because npm has no equivalent of
	// the Python credential-files map; we keep the field empty rather
	// than nil for schema stability.
	result := &CheckResult{
		Environment: root,
		Findings:    []Finding{},
		Credentials: []CredentialFile{},
		Intel:       embeddedIntelSummary(),
	}

	packages := readInstalledNPMPackages(root)
	result.PackagesRead = len(packages)
	for _, pkg := range packages {
		cp := IsCompromisedIn(EcosystemNPM, pkg.Name, pkg.Version)
		if cp == nil {
			continue
		}
		result.Findings = append(result.Findings, Finding{
			Severity:    SevCritical,
			Title:       fmt.Sprintf("%s %s is a known compromised npm package (%s)", pkg.Name, pkg.Version, cp.Advisory),
			Detail:      cp.Summary,
			Path:        pkg.Dir,
			Remediation: fmt.Sprintf("Remove %s@%s, audit recent runs of the surrounding pipeline, and rotate any tokens this environment has held.", pkg.Name, pkg.Version),
		})
	}

	return result, nil
}

// resolveNPMRoot turns the user-supplied path into the actual
// node_modules directory to walk. The supplied path may already be a
// node_modules tree, in which case it is returned unchanged; or it
// may be a project root whose child node_modules holds the install
// graph. Any other shape returns an error so the operator does not
// silently get a clean report for a path the checker cannot
// interpret.
func resolveNPMRoot(p string) (string, error) {
	info, err := os.Stat(p)
	if err != nil {
		return "", fmt.Errorf("npm check: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("npm check: %s is not a directory", p)
	}
	if filepath.Base(p) == "node_modules" {
		return p, nil
	}
	candidate := filepath.Join(p, "node_modules")
	if cinfo, cerr := os.Stat(candidate); cerr == nil && cinfo.IsDir() {
		return candidate, nil
	}
	return "", fmt.Errorf("npm check: %s is not a node_modules directory and contains no node_modules subdirectory; pass the path to a node_modules tree or its parent project", p)
}

// readInstalledNPMPackages walks node_modules recursively (since npm
// can install nested copies of the same package at different versions)
// and parses each package.json it finds. Scoped packages (@scope/name)
// resolve correctly because the scope directory contains the package
// directory which contains package.json.
//
// Manifests are only counted when their package directory's parent is
// a node_modules directory (directly for unscoped packages, or via a
// @scope directory whose parent is node_modules). A package's own
// examples/ or fixtures/ subtree may contain a stray package.json
// that npm does not treat as an installed dependency; those are
// skipped so they cannot trigger a false-positive compromise finding.
func readInstalledNPMPackages(root string) []NPMPackage {
	var pkgs []NPMPackage
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Base(path) != "package.json" {
			return nil
		}
		if !isInstalledPackageManifest(path, root) {
			return nil
		}
		pkg := parseNPMPackage(path)
		if pkg.Name != "" && pkg.Version != "" {
			pkgs = append(pkgs, pkg)
		}
		return nil
	})
	return pkgs
}

// isInstalledPackageManifest returns true when path is reachable from
// root via a canonical install layout. Two layouts are accepted:
//
//	npm:   <name>[/node_modules/<name>]*         (optional @scope at each name)
//	pnpm:  .pnpm/<spec>/node_modules/<name>      (the virtual store)
//
// Top-level npm entries are <name> or @scope/<name>. pnpm exposes
// top-level packages as symlinks pointing into the .pnpm virtual
// store; filepath.WalkDir does not follow those symlinks, so the
// real manifests are reached via the .pnpm/<spec>/node_modules/...
// path and need to be admitted here. Any other intermediate
// segment (examples/, test/, fixtures/, dist/, etc.) means the
// manifest is bundled test data rather than an installed
// dependency.
func isInstalledPackageManifest(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	if len(parts) < 2 || parts[len(parts)-1] != "package.json" {
		return false
	}
	const (
		expectName            = iota // start; <name>, @scope, or .pnpm
		expectScopedName             // after @scope, expect the leaf name
		expectNodeOrEnd              // after a name, expect /node_modules or end
		expectPnpmSpec               // after .pnpm, expect a spec token
		expectPnpmNodeModules        // after the spec, expect /node_modules
	)
	state := expectName
	for _, seg := range parts[:len(parts)-1] {
		switch state {
		case expectName:
			if seg == ".pnpm" {
				state = expectPnpmSpec
				continue
			}
			if strings.HasPrefix(seg, "@") {
				state = expectScopedName
				continue
			}
			state = expectNodeOrEnd
		case expectScopedName:
			state = expectNodeOrEnd
		case expectNodeOrEnd:
			if seg != "node_modules" {
				return false
			}
			state = expectName
		case expectPnpmSpec:
			// Any non-empty token works as the pnpm spec (e.g.
			// event-stream@3.3.6, @scope+name@1.2.3).
			if seg == "" {
				return false
			}
			state = expectPnpmNodeModules
		case expectPnpmNodeModules:
			if seg != "node_modules" {
				return false
			}
			state = expectName
		}
	}
	return state == expectNodeOrEnd
}

// parseNPMPackage reads a package.json and extracts the name and
// version fields. Returns a zero-value NPMPackage if the file is
// malformed or missing those fields.
func parseNPMPackage(path string) NPMPackage {
	pkg := NPMPackage{Dir: filepath.Dir(path)}
	data, err := os.ReadFile(path)
	if err != nil {
		return pkg
	}
	var manifest struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return pkg
	}
	pkg.Name = manifest.Name
	pkg.Version = manifest.Version
	return pkg
}
