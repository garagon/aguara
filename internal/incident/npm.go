package incident

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/garagon/aguara/internal/intel"
	"github.com/garagon/aguara/internal/jsonfields"
	"github.com/garagon/aguara/internal/packagecheck"
	"github.com/garagon/aguara/internal/safefile"
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
	// Probe readability before readInstalledNPMPackages runs. WalkDir
	// swallows traversal errors and returns nil, so without this
	// probe an unreadable node_modules (permission-denied bind mount,
	// CI runner with reduced caps, root-owned tree) would silently
	// produce an empty package list. Appending an ecosystems[] entry
	// with PackagesRead=0 then misrepresents an unreadable tree as
	// "scanned clean" to coverage consumers. Fail fast instead so
	// the caller surfaces the access failure as an error.
	if _, err := os.ReadDir(root); err != nil {
		return nil, fmt.Errorf("npm check: cannot read node_modules directory %s: %w", root, err)
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
		Ecosystems:  []packagecheck.EcosystemResult{},
		Intel:       intelSummaryFor(opts),
	}

	// Same wiring as the Python check path: route through the
	// intel matcher so any OSV record (embedded or refreshed)
	// participates in the match. matcherFor honours opts.Intel
	// so the CLI can pass a refreshed local snapshot without
	// touching package-level state.
	matcher := matcherFor(opts)
	packages, unread, err := readInstalledNPMPackages(root)
	if err != nil {
		return nil, err
	}
	result.PackagesRead = len(packages)
	result.Findings = append(result.Findings, unreadManifestFindings(unread)...)
	// npmFindings counts findings emitted by the npm package-match
	// step only. Mirrors the per-ecosystem accounting the
	// packagecheck path uses for its six ecosystems.
	npmFindings := 0
	for _, pkg := range packages {
		hits := matcher.MatchPackage(intel.MatchInput{
			Ecosystem: intel.EcosystemNPM,
			Name:      pkg.Name,
			Version:   pkg.Version,
			Path:      pkg.Dir,
		})
		if len(hits) == 0 {
			continue
		}
		// One Finding per (ecosystem, name, version, path) tuple even
		// when multiple intel records cover the same exposure (manual
		// snapshot + OSV record for the same package/version after
		// OSV catches up to a hand-curated advisory). The matcher
		// keeps returning every record so correlators can still see
		// the full set; this output layer collapses to the single
		// real-world exposure the user must act on.
		//
		// EmbeddedSnapshots() returns the manual snapshot first and
		// the OSV snapshot second, so hits[0] picks the manual
		// advisory ID (e.g. SOCKET-*) over the OSV one (MAL-*) when
		// both are present, keeping the finding's advisory token
		// stable across `aguara check` and `aguara check --fresh`.
		// The title names every matching advisory, as advisory_ids does.
		hit := hits[0]
		ids := matchIDs(hits)
		result.Findings = append(result.Findings, Finding{
			Severity:    SevCritical,
			Title:       fmt.Sprintf("%s %s is a known compromised npm package (%s)", pkg.Name, pkg.Version, strings.Join(ids, ", ")),
			Detail:      hit.Record.Summary,
			Path:        pkg.Dir,
			Remediation: fmt.Sprintf("Remove %s@%s, audit recent runs of the surrounding pipeline, and rotate any tokens this environment has held.", pkg.Name, pkg.Version),
			AdvisoryIDs: ids,
		})
		npmFindings++
	}
	// Surface npm as an Ecosystems[] entry on the result so JSON
	// consumers see consistent multi-ecosystem coverage data. Before
	// this, .Ecosystems was always [] for the npm path; consumers
	// reading the array would conclude npm was never scanned even
	// though packages WERE checked and findings WERE emitted. Always
	// append - even with PackagesRead=0 - so callers know the
	// pipeline ran and consulted the directory.
	result.Ecosystems = append(result.Ecosystems, packagecheck.EcosystemResult{
		Ecosystem:     intel.EcosystemNPM,
		Path:          root,
		Source:        "node_modules",
		PackagesRead:  len(packages),
		FindingsCount: npmFindings,
	})

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
//
// A manifest larger than maxInstalledManifestBytes is an error rather than
// a package left out: padding a package.json must not hide the package.
// A manifest that is not a readable regular file, and a directory that
// cannot be listed, are returned in unread so the check can say they were
// not evaluated.
func readInstalledNPMPackages(root string) (pkgs []NPMPackage, unread []unreadManifest, err error) {
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if path != root {
				unread = append(unread, unreadManifest{path: path, reason: "could not be listed"})
			}
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
		pkg, reason, err := readNPMPackage(path)
		if err != nil {
			return err
		}
		if reason != "" {
			unread = append(unread, unreadManifest{path: path, reason: reason})
			return nil
		}
		if pkg.Name != "" && pkg.Version != "" {
			pkgs = append(pkgs, pkg)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return pkgs, unread, nil
}

// unreadManifest is an installed package.json, or a directory under
// node_modules, that the check could not read.
type unreadManifest struct {
	path, reason string
}

// maxUnreadFindings bounds the WARNING findings for unread manifests; the
// rest are counted in one more finding.
const maxUnreadFindings = 100

// unreadManifestFindings turns unread manifests into WARNING findings: the
// packages they describe were not checked.
func unreadManifestFindings(unread []unreadManifest) []Finding {
	var findings []Finding
	for i, u := range unread {
		if i == maxUnreadFindings {
			findings = append(findings, Finding{
				Severity: SevWarning,
				Title:    fmt.Sprintf("%d more installed package manifests or directories could not be read; their packages were not checked", len(unread)-maxUnreadFindings),
			})
			break
		}
		dir, what := filepath.Dir(u.path), "Installed package manifest "+u.path
		if u.reason == "could not be listed" {
			dir, what = u.path, "Directory "+u.path
		}
		findings = append(findings, Finding{
			Severity:    SevWarning,
			Title:       fmt.Sprintf("%s %s; its packages were not checked", what, u.reason),
			Path:        dir,
			Remediation: "Inspect this package directory by hand: only a readable regular package.json can be checked against package intelligence.",
		})
	}
	return findings
}

// maxInstalledManifestBytes bounds one installed package.json, matching the
// dependency-file limit of the lockfile parsers.
const maxInstalledManifestBytes = 50 << 20

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
// malformed, missing those fields, unreadable or too large.
func parseNPMPackage(path string) NPMPackage {
	pkg, _, _ := readNPMPackage(path)
	return pkg
}

// readNPMPackage is parseNPMPackage with the size limit as an error. The
// read follows a symbolic link (package managers link installed trees) but
// never blocks on a named pipe or device. A manifest that cannot be read
// returns why in unread, so the caller can report it.
func readNPMPackage(path string) (pkg NPMPackage, unread string, err error) {
	pkg = NPMPackage{Dir: filepath.Dir(path)}
	data, readErr := safefile.ReadRegular(path, true, maxInstalledManifestBytes)
	var notRegular *safefile.NotRegularError
	switch {
	case errors.Is(readErr, safefile.ErrTooLarge):
		return pkg, "", fmt.Errorf("npm check: %s exceeds %d-byte limit", path, maxInstalledManifestBytes)
	case errors.As(readErr, &notRegular):
		return pkg, "is a " + safefile.DescribeMode(notRegular.Mode) + ", not a regular file", nil
	case readErr != nil:
		return pkg, "could not be read", nil
	}
	// Millions of padding keys would cost gigabytes to decode; like an
	// oversized manifest, that fails the check instead of hiding the
	// package.
	if err := packagecheck.CheckJSONNodeBudget(data, "package.json"); err != nil {
		return pkg, "", fmt.Errorf("npm check: %s: %w", path, err)
	}
	var manifest struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if jsonfields.Decode(data,
		jsonfields.Field{Name: "name", To: &manifest.Name},
		jsonfields.Field{Name: "version", To: &manifest.Version}) != nil {
		return pkg, "", nil // malformed: not a package, as before
	}
	pkg.Name = manifest.Name
	pkg.Version = manifest.Version
	return pkg, "", nil
}
