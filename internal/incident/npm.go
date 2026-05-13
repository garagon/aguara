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
		return nil, fmt.Errorf("npm check requires --path pointing at a node_modules directory")
	}
	info, err := os.Stat(opts.Path)
	if err != nil {
		return nil, fmt.Errorf("npm check: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("npm check: %s is not a directory", opts.Path)
	}

	result := &CheckResult{Environment: opts.Path}

	packages := readInstalledNPMPackages(opts.Path)
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
		if !isInstalledPackageManifest(path) {
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

// isInstalledPackageManifest returns true if the manifest at path lives
// at a real npm install boundary: either node_modules/<name>/package.json
// or node_modules/@scope/<name>/package.json. Manifests nested in
// examples / fixtures / test trees do not satisfy this and so are
// excluded from the installed-package walk.
func isInstalledPackageManifest(path string) bool {
	dir := filepath.Dir(path)
	parent := filepath.Dir(dir)
	if filepath.Base(parent) == "node_modules" {
		return true
	}
	// Scoped layout: node_modules/@scope/<name>/package.json.
	// parent here is the @scope directory; its parent is node_modules.
	if strings.HasPrefix(filepath.Base(parent), "@") &&
		filepath.Base(filepath.Dir(parent)) == "node_modules" {
		return true
	}
	return false
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
