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
		Intel:       embeddedIntelSummary(),
	}

	// 1. Read installed packages and check against the embedded
	// intel matcher (manual KnownCompromised + OSV-derived stub
	// from generated_intel.go). Going through the matcher rather
	// than the legacy IsCompromised slice scan means any OSV
	// record the maintainer regenerates is automatically picked
	// up here -- otherwise the IntelSummary would advertise "osv"
	// as a source the check pipeline never consults.
	matcher := defaultIntelMatcher()
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
	result.Findings = append(result.Findings, checkCaches()...)

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
func checkCaches() []Finding {
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

	matcher := defaultIntelMatcher()
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

			// Filename-based check for cache artifacts. The cache scan
			// is part of the Python check path, so only PyPI entries
			// apply here; npm rows live in a separate scan.
			base := strings.ToLower(name)
			for _, cp := range KnownCompromised {
				entryEco := cp.Ecosystem
				if entryEco == "" {
					entryEco = EcosystemPyPI
				}
				if entryEco != EcosystemPyPI {
					continue
				}
				if strings.Contains(base, cp.Name) {
					for _, v := range cp.Versions {
						if strings.Contains(base, v) && !seen[path] {
							seen[path] = true
							findings = append(findings, Finding{
								Severity:    SevWarning,
								Title:       fmt.Sprintf("Cached compromised artifact: %s %s", cp.Name, v),
								Path:        path,
								Remediation: "Run 'aguara clean --purge-caches' to remove cached packages",
							})
						}
					}
				}
			}
			return nil
		})
	}
	return findings
}
