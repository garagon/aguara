package incident

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/garagon/aguara/internal/intel"
	"github.com/garagon/aguara/internal/packagecheck"
)

// Severity levels for check findings.
const (
	SevCritical = "CRITICAL"
	SevWarning  = "WARNING"
	SevInfo     = "INFO"
)

// Finding represents a single issue found by the checker.
type Finding struct {
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Detail      string `json:"detail"`
	Path        string `json:"path,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

// CredentialFile represents a credential path and its rotation guidance.
type CredentialFile struct {
	Path     string `json:"path"`
	Exists   bool   `json:"exists"`
	Guidance string `json:"guidance"`
}

// CheckResult holds all results from a check run.
type CheckResult struct {
	Environment  string           `json:"environment"`
	Findings     []Finding        `json:"findings"`
	Credentials  []CredentialFile `json:"credentials"`
	PackagesRead int              `json:"packages_read"`
	PthScanned   int              `json:"pth_scanned"`
	// Intel describes which threat-intel snapshot produced the
	// findings and whether it was offline-embedded or refreshed.
	// Populated by Check / CheckNPM; consumers can rely on it
	// being non-zero (mode + snapshot are always set).
	Intel IntelSummary `json:"intel"`
	// Ecosystems is the per-discovery-target summary the
	// packagecheck path produces (one entry per lockfile found).
	// Populated by the Go path in v0.17.0 PR #2; the legacy
	// incident.Check / incident.CheckNPM paths initialise it to
	// an empty non-nil slice so the JSON shape is always
	// `"ecosystems": []` rather than missing or `null`. Top-level
	// Findings stays the flat union across every path so JSON
	// consumers that read `findings` keep working unchanged.
	Ecosystems []packagecheck.EcosystemResult `json:"ecosystems"`
}

// IntelSummary tells the consumer (terminal output, JSON
// downstream, CI gate logic) which threat-intel snapshot produced
// the findings. The CLI exposes the same fields under `aguara
// status` so operators can reconcile the two.
//
// Stable contract:
//   - Mode is one of: "offline" (no network was used) or "online"
//     (an --fresh refresh ran in this invocation).
//   - Snapshot is one of: "embedded" (binary's built-in snapshot),
//     "local" (the on-disk cache at ~/.aguara/intel), or
//     "remote-fresh" (downloaded this invocation).
//   - Sources lists the SourceMeta.Kind values that fed the
//     snapshot, deduplicated.
//   - Stale is true when the snapshot is older than a freshness
//     threshold the CLI decides; left false here so the lower
//     layer does not own a policy.
type IntelSummary struct {
	Mode        string    `json:"mode"`
	Snapshot    string    `json:"snapshot"`
	GeneratedAt time.Time `json:"generated_at"`
	Sources     []string  `json:"sources"`
	Stale       bool      `json:"stale"`
}

// InstalledPackage is a package parsed from dist-info METADATA.
type InstalledPackage struct {
	Name    string
	Version string
	Dir     string // dist-info directory path
}

// CheckOptions configures a check run.
type CheckOptions struct {
	Path          string // explicit site-packages path, empty = auto-discover
	IncludeCaches bool
	// Intel overrides the embedded snapshots and IntelSummary that
	// the check pipeline uses. Nil means "use EmbeddedSnapshots()
	// and the offline/embedded IntelSummary" (the default for
	// every legacy caller). The CLI sets this when --fresh just
	// refreshed the local cache or when a local snapshot is
	// available, so IntelSummary reflects what actually matched.
	Intel *IntelOverride
}

// IntelOverride lets the CLI swap in a different snapshot set
// (e.g. embedded + local cache, or freshly downloaded) for one
// check run without mutating package-level state. Mode and
// SnapshotLabel populate the corresponding IntelSummary fields so
// downstream consumers see the truthful provenance.
type IntelOverride struct {
	Snapshots     []intel.Snapshot
	Mode          string // "offline" | "online"
	SnapshotLabel string // "embedded" | "local" | "remote-fresh"
}

// Check scans a Python environment for compromised packages and artifacts.
func Check(opts CheckOptions) (*CheckResult, error) {
	siteDir := opts.Path
	if siteDir == "" {
		siteDir = discoverSitePackages()
	}
	if siteDir == "" {
		return nil, fmt.Errorf("no Python site-packages directory found (use --path to specify)")
	}

	// Initialize the result with non-nil slices so the JSON output is
	// the stable `[]` shape (not `null`) when nothing is found.
	result := &CheckResult{
		Environment: siteDir,
		Findings:    []Finding{},
		Credentials: []CredentialFile{},
		Ecosystems:  []packagecheck.EcosystemResult{},
		Intel:       intelSummaryFor(opts),
	}

	// 1. Read installed packages and check against the intel matcher.
	// matcherFor honours an explicit opts.Intel override (e.g. the
	// CLI passing a refreshed local snapshot) and falls back to the
	// cached default matcher built from EmbeddedSnapshots() when no
	// override is present.
	matcher := matcherFor(opts)
	packages := readInstalledPackages(siteDir)
	result.PackagesRead = len(packages)
	for _, pkg := range packages {
		hits := matcher.MatchPackage(intel.MatchInput{
			Ecosystem: intel.EcosystemPyPI,
			Name:      pkg.Name,
			Version:   pkg.Version,
			Path:      pkg.Dir,
		})
		for _, hit := range hits {
			result.Findings = append(result.Findings, Finding{
				Severity:    SevCritical,
				Title:       fmt.Sprintf("%s %s is a known compromised package (%s)", pkg.Name, pkg.Version, hit.Record.ID),
				Detail:      hit.Record.Summary,
				Path:        pkg.Dir,
				Remediation: fmt.Sprintf("Run 'aguara clean' to remove %s and associated malware", pkg.Name),
			})
		}
	}

	// 2. Scan .pth files for executable content
	pthFiles := findPthFiles(siteDir)
	result.PthScanned = len(pthFiles)
	for _, pth := range pthFiles {
		if findings := checkPthFile(pth); len(findings) > 0 {
			result.Findings = append(result.Findings, findings...)
		}
	}

	// 3. Check for persistence artifacts
	result.Findings = append(result.Findings, checkPersistence()...)

	// 4. Check credential files at risk
	result.Credentials = checkCredentialFiles()

	// 5. Always check pip/uv/npx caches for compromised packages
	result.Findings = append(result.Findings, checkCaches(opts)...)

	return result, nil
}

// discoverSitePackages finds the current Python environment's site-packages.
func discoverSitePackages() string {
	// Check virtualenv first
	if venv := os.Getenv("VIRTUAL_ENV"); venv != "" {
		pattern := filepath.Join(venv, "lib", "python*", "site-packages")
		matches, _ := filepath.Glob(pattern)
		if len(matches) > 0 {
			return matches[0]
		}
	}

	// Common system site-packages locations
	candidates := []string{}
	home, _ := os.UserHomeDir()

	if runtime.GOOS == "darwin" {
		candidates = append(candidates,
			"/opt/homebrew/lib/python*/site-packages",
			"/usr/local/lib/python*/site-packages",
		)
	} else {
		candidates = append(candidates,
			"/usr/lib/python*/dist-packages",
			"/usr/local/lib/python*/site-packages",
		)
	}
	if home != "" {
		candidates = append(candidates,
			filepath.Join(home, ".local/lib/python*/site-packages"),
		)
	}

	for _, pattern := range candidates {
		matches, _ := filepath.Glob(pattern)
		if len(matches) > 0 {
			return matches[len(matches)-1] // highest Python version
		}
	}
	return ""
}

// readInstalledPackages reads METADATA from *.dist-info dirs.
func readInstalledPackages(siteDir string) []InstalledPackage {
	var packages []InstalledPackage

	entries, err := os.ReadDir(siteDir)
	if err != nil {
		return nil
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".dist-info") {
			continue
		}

		metaPath := filepath.Join(siteDir, name, "METADATA")
		pkg := parseMetadata(metaPath)
		if pkg.Name != "" {
			pkg.Dir = filepath.Join(siteDir, name)
			packages = append(packages, pkg)
		}
	}
	return packages
}

// parseMetadata extracts Name and Version from a dist-info METADATA file.
func parseMetadata(path string) InstalledPackage {
	f, err := os.Open(path)
	if err != nil {
		return InstalledPackage{}
	}
	defer func() { _ = f.Close() }()

	var pkg InstalledPackage
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break // headers end at first blank line
		}
		if strings.HasPrefix(line, "Name: ") {
			pkg.Name = strings.ToLower(strings.TrimPrefix(line, "Name: "))
		} else if strings.HasPrefix(line, "Version: ") {
			pkg.Version = strings.TrimPrefix(line, "Version: ")
		}
	}
	return pkg
}

// findPthFiles returns all .pth files in the given directory.
func findPthFiles(dir string) []string {
	var files []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".pth") {
			files = append(files, filepath.Join(dir, entry.Name()))
		}
	}
	return files
}

var pthExecRe = regexp.MustCompile(`(?i)(^import\s|subprocess|os\.system|os\.popen|exec\(|eval\(|compile\(|__import__|importlib|open\(|Path\()`)

// knownSafePth lists .pth filenames from standard Python ecosystem packages
// that legitimately use import statements for site customization.
var knownSafePth = map[string]bool{
	"_virtualenv.pth":          true,
	"distutils-precedence.pth": true,
	"easy-install.pth":         true,
	"setuptools.pth":           true,
	"coverage.pth":             true,
	"zope-nspkg.pth":           true,
}

// checkPthFile scans a .pth file for executable content.
func checkPthFile(path string) []Finding {
	if knownSafePth[filepath.Base(path)] {
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	content := string(data)
	if !pthExecRe.MatchString(content) {
		return nil
	}

	// Truncate content for display
	preview := content
	if len(preview) > 200 {
		preview = preview[:200] + "..."
	}
	preview = strings.ReplaceAll(preview, "\n", " ")

	return []Finding{{
		Severity:    SevCritical,
		Title:       fmt.Sprintf("%s contains executable code", filepath.Base(path)),
		Detail:      preview,
		Path:        path,
		Remediation: "Remove this .pth file. Legitimate .pth files contain only directory paths.",
	}}
}

// checkPersistence looks for known backdoor persistence artifacts.
func checkPersistence() []Finding {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	var findings []Finding
	artifacts := []struct {
		rel  string
		desc string
	}{
		{".config/sysmon/sysmon.py", "litellm backdoor script"},
		{".config/systemd/user/sysmon.service", "litellm systemd persistence"},
	}

	for _, a := range artifacts {
		path := filepath.Join(home, a.rel)
		if _, err := os.Stat(path); err == nil {
			findings = append(findings, Finding{
				Severity:    SevWarning,
				Title:       fmt.Sprintf("Persistence artifact found: %s", a.desc),
				Path:        path,
				Remediation: "Run 'aguara clean' to quarantine this file",
			})
		}
	}
	return findings
}

// checkCredentialFiles reports which credential files exist on the system.
func checkCredentialFiles() []CredentialFile {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	targets := []struct {
		rel      string
		guidance string
	}{
		{".ssh/id_rsa", "Rotate SSH keys (ssh-keygen -t ed25519)"},
		{".ssh/id_ed25519", "Rotate SSH keys and update authorized_keys on all servers"},
		{".aws/credentials", "Rotate AWS access keys in IAM console"},
		{".azure/config", "Rotate Azure credentials via az cli"},
		{".gcloud/credentials.db", "Rotate GCP credentials via gcloud auth revoke"},
		{".kube/config", "Rotate K8s certificates and service account tokens"},
		{".gitconfig", "Revoke git tokens at github.com/settings/tokens"},
		{".git-credentials", "Revoke all stored git credentials"},
		{".npmrc", "Rotate npm tokens at npmjs.com/settings/tokens"},
		{".pypirc", "Rotate PyPI tokens at pypi.org/manage/account"},
		{".pgpass", "Rotate PostgreSQL passwords"},
		{".my.cnf", "Rotate MySQL passwords"},
		{".env", "Rotate all API keys and secrets in .env"},
	}

	var creds []CredentialFile
	for _, t := range targets {
		path := filepath.Join(home, t.rel)
		_, err := os.Stat(path)
		creds = append(creds, CredentialFile{
			Path:     "~/" + t.rel,
			Exists:   err == nil,
			Guidance: t.guidance,
		})
	}
	return creds
}

// checkCaches looks for compromised packages and malicious files in pip/uv/npx cache dirs.
func checkCaches(opts CheckOptions) []Finding {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	var findings []Finding
	cacheDirs := []string{
		filepath.Join(home, ".cache/uv"),
		filepath.Join(home, ".cache/pip/wheels"),
		filepath.Join(home, ".cache/pip/http"),
		filepath.Join(home, ".npm/_npx"),
		filepath.Join(home, "Library/Caches/pip"), // macOS
	}

	matcher := matcherFor(opts)
	snaps := snapshotsFor(opts)
	// Precompute the PyPI filename-heuristic index ONCE outside
	// the per-file WalkDir loop. Before this, every cache file
	// re-iterated all snapshots' records and ran a fresh
	// strings.ToLower on each rec.Name. With v0.16's regenerated
	// OSV stub carrying ~1,400 PyPI records, a host with active
	// pip/uv caches (40k+ files is common) saw aguara check spike
	// to 30s+ scanning caches. The precompute moves the lower-case
	// and ecosystem filter out of the hot loop so per-file cost
	// scales with the substring matcher, not the snapshot size.
	pypiIndex := buildPyPIFilenameIndex(snaps)
	seen := make(map[string]bool) // deduplicate findings by path
	for _, dir := range cacheDirs {
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			name := d.Name()

			// Check .pth files for executable content
			if !d.IsDir() && strings.HasSuffix(name, ".pth") {
				if pthFindings := checkPthFile(path); len(pthFindings) > 0 && !seen[path] {
					seen[path] = true
					findings = append(findings, pthFindings...)
				}
				return nil
			}

			// Check METADATA in dist-info dirs for compromised versions.
			// Routed through the embedded matcher (manual + OSV) so an
			// OSV-only cache artifact is caught -- otherwise the
			// IntelSummary would advertise OSV provenance while the
			// cache scan silently missed records from that source.
			if d.IsDir() && strings.HasSuffix(name, ".dist-info") {
				metaPath := filepath.Join(path, "METADATA")
				pkg := parseMetadata(metaPath)
				if pkg.Name != "" {
					hits := matcher.MatchPackage(intel.MatchInput{
						Ecosystem: intel.EcosystemPyPI,
						Name:      pkg.Name,
						Version:   pkg.Version,
						Path:      path,
					})
					for _, hit := range hits {
						if seen[path] {
							break
						}
						seen[path] = true
						findings = append(findings, Finding{
							Severity:    SevCritical,
							Title:       fmt.Sprintf("Cached compromised package: %s %s (%s)", pkg.Name, pkg.Version, hit.Record.ID),
							Detail:      hit.Record.Summary,
							Path:        path,
							Remediation: "Run 'aguara clean --purge-caches' to remove cached packages",
						})
					}
				}
				return filepath.SkipDir
			}

			// Filename-based check for cache artifacts. The cache
			// scan is part of the Python check path, so only PyPI
			// entries apply here; npm rows live in a separate scan.
			// snapshotsFor(opts) honours an explicit override (e.g.
			// embedded + local cache) so a freshly-refreshed PyPI
			// advisory trips the heuristic without having to wait
			// for the next release.
			base := strings.ToLower(name)
			candidates := parsePyPIWheelName(base)
			if len(candidates) == 0 {
				// Filename is not a wheel/sdist shape (pip's
				// content-hash cache entries fall here). Skip
				// rather than substring-scan, which v0.15
				// false-positived on hex hashes that happened
				// to contain a record name.
				return nil
			}
			// Try every (name, rest) split. Hyphenated sdist names
			// (e.g. `233-misc-0.0.3.tar.gz`) have multiple
			// candidate boundaries; we accept the FIRST that hits
			// the index. The intel index is PEP 503 normalised so
			// we normalise the candidate before lookup.
			for _, cand := range candidates {
				if seen[path] {
					break
				}
				entries, ok := pypiIndex[intel.PEP503Normalize(cand.name)]
				if !ok {
					continue
				}
				for _, entry := range entries {
					if seen[path] {
						break
					}
					for _, v := range entry.versions {
						// Version must appear in the suffix
						// after the name. Without that constraint
						// `numpy-1.26.4.whl` could spuriously
						// match a record whose version string
						// lives only inside `numpy` itself
						// (1-digit versions like "1" would
						// explode otherwise).
						if strings.Contains(cand.rest, v) {
							seen[path] = true
							findings = append(findings, Finding{
								Severity:    SevWarning,
								Title:       fmt.Sprintf("Cached compromised artifact: %s %s (%s)", entry.displayName, v, entry.id),
								Path:        path,
								Remediation: "Run 'aguara clean --purge-caches' to remove cached packages",
							})
							break
						}
					}
				}
			}
			return nil
		})
	}
	return findings
}

// pypiFilenameEntry is one row in the precomputed PyPI filename-
// heuristic index. displayName preserves the original casing for
// the finding title; id is the OSV/manual advisory ID.
type pypiFilenameEntry struct {
	displayName string
	id          string
	versions    []string
}

// pypiFilenameIndex maps a PEP 503-normalised package name to the
// list of (id, displayName, versions) entries for that name. The
// per-file matcher parses the wheel/sdist filename, extracts the
// `<name>-<version>` prefix, normalises the name, and does an
// O(1) map lookup. This avoids the v0.15-era substring scan that
// false-positived on hash filenames (`...4123932...` matching a
// MAL record named "4123") and on typosquat prefixes ("nump"
// matching "numpy-1.26.4.whl"); both were observed regressions
// once the OSV stub started carrying real records.
type pypiFilenameIndex map[string][]pypiFilenameEntry

// buildPyPIFilenameIndex builds the precomputed heuristic index
// once per check run. Filters out withdrawn records, anything not
// tagged PyPI, and records with no Versions (filename heuristic
// needs at least one version to anchor a cache finding). Names
// are normalised via intel.PEP503Normalize so the lookup matches
// the canonical wheel-filename casing.
func buildPyPIFilenameIndex(snaps []intel.Snapshot) pypiFilenameIndex {
	idx := make(pypiFilenameIndex)
	for _, snap := range snaps {
		for _, rec := range snap.Records {
			if rec.Ecosystem != intel.EcosystemPyPI {
				continue
			}
			if rec.Withdrawn {
				continue
			}
			if len(rec.Versions) == 0 {
				continue
			}
			key := intel.PEP503Normalize(rec.Name)
			if key == "" {
				continue
			}
			idx[key] = append(idx[key], pypiFilenameEntry{
				displayName: rec.Name,
				id:          rec.ID,
				versions:    rec.Versions,
			})
		}
	}
	return idx
}

// parsePyPIWheelName extracts (name, rest) candidates from a PyPI
// cache filename. Returns the EMPTY slice for filenames that do
// not match a wheel/sdist shape (e.g. pip's content-hash cache
// entries in http-v2/) so the caller can skip them cleanly.
//
// Wheel: `<name>-<version>-<python>-<abi>-<platform>.whl`
//   - PEP 491: non-alphanumeric chars in name are normalised to `_`
//     in wheel filenames, so the wheel name never contains `-`.
//
// Sdist: `<name>-<version>.tar.gz` (or .zip)
//   - Name may contain `-` (e.g. `233-misc-0.0.3.tar.gz` has name
//     `233-misc`, version `0.0.3`).
//
// We resolve the ambiguity by emitting a candidate at every `-`
// position whose next byte is a digit (PEP 440 versions always
// start with a digit, possibly preceded by an epoch which itself
// starts with a digit). Callers try each candidate in order; the
// first that resolves in the intel index wins. For wheels there
// is exactly one such boundary; for hyphenated sdists there are
// typically two (the inner ones don't match the index but the
// last one does).
func parsePyPIWheelName(base string) []nameCandidate {
	var out []nameCandidate
	for i := 0; i < len(base); i++ {
		if base[i] != '-' {
			continue
		}
		if i+1 >= len(base) {
			break
		}
		if base[i+1] < '0' || base[i+1] > '9' {
			continue
		}
		if i == 0 {
			continue // leading '-' has no name part
		}
		out = append(out, nameCandidate{name: base[:i], rest: base[i+1:]})
	}
	return out
}

// nameCandidate is one possible (name, rest) split of a PyPI cache
// filename. parsePyPIWheelName returns all candidates; the caller
// tries each against the intel index until one resolves.
type nameCandidate struct {
	name string
	rest string
}
