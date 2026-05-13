// Package incident provides detection and cleanup of compromised packages,
// malicious .pth / lifecycle artifacts, and persistence vectors across the
// supported language ecosystems (Python and npm).
package incident

// Ecosystem identifiers for CompromisedPackage entries and IsCompromised
// lookups. The default empty value is treated as PyPI for backward
// compatibility with releases that predate the ecosystem field.
const (
	EcosystemPyPI = "pypi"
	EcosystemNPM  = "npm"
)

// CompromisedPackage describes a known-bad package+version combination.
// Ecosystem identifies the registry the package belongs to so the same
// data structure can hold PyPI and npm entries without collision (real
// names overlap across registries). IOCs is an optional list of
// indicators of compromise (file paths, hashes, network endpoints) that
// extend a detector beyond the package+version tuple.
type CompromisedPackage struct {
	Ecosystem string   `json:"ecosystem,omitempty"`
	Name      string   `json:"name"`
	Versions  []string `json:"versions"`
	Advisory  string   `json:"advisory"`
	Date      string   `json:"date"`
	Summary   string   `json:"summary"`
	IOCs      []IOC    `json:"iocs,omitempty"`
}

// IOC is a single indicator of compromise associated with a known-bad
// package. Type names the indicator class (path, hash, endpoint); Value
// is the literal string the detector looks for. Optional and additive;
// older entries that do not carry IOCs continue to work.
type IOC struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// KnownCompromised is the embedded list of known compromised packages.
// Updated with each Aguara release.
//
// Entries are matched by (Ecosystem, Name, Version). An entry with an
// empty Ecosystem is treated as PyPI so IsCompromised stays
// backward-compatible with prior callers that did not supply an
// ecosystem argument.
var KnownCompromised = []CompromisedPackage{
	{
		Ecosystem: EcosystemPyPI,
		Name:      "litellm",
		Versions:  []string{"1.82.7", "1.82.8"},
		Advisory:  "PYSEC-2026-litellm",
		Date:      "2026-03-24",
		Summary:   "Malicious .pth file exfiltrates credentials (SSH, cloud, K8s) and installs backdoor with systemd persistence",
	},

	// --- npm ---
	//
	// Historical npm compromises with publicly-published advisories.
	// Maintainers should extend this list as new incidents are
	// confirmed via npm advisories or vendor disclosures. Each entry
	// must cite the source advisory in the Advisory field; speculative
	// or unverified package/version tuples do not belong here.
	{
		Ecosystem: EcosystemNPM,
		Name:      "event-stream",
		Versions:  []string{"3.3.6"},
		Advisory:  "GHSA-mh6f-8j2x-4483",
		Date:      "2018-11-26",
		Summary:   "event-stream 3.3.6 shipped a malicious flatmap-stream dependency that targeted bitcoin wallets in copay-dash; the version was unpublished and remediated by maintainers.",
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "flatmap-stream",
		Versions:  []string{"0.1.1"},
		Advisory:  "GHSA-mh6f-8j2x-4483",
		Date:      "2018-11-26",
		Summary:   "Malicious dependency injected through event-stream 3.3.6; exfiltrated wallet data from copay-dash.",
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "ua-parser-js",
		Versions:  []string{"0.7.29", "0.8.0", "1.0.0"},
		Advisory:  "GHSA-pjwm-rvh2-c87w",
		Date:      "2021-10-22",
		Summary:   "Compromised ua-parser-js versions installed cryptominer and credential-stealing payloads on Linux and Windows.",
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "coa",
		Versions:  []string{"2.0.3", "2.0.4", "2.1.1", "2.1.3", "3.0.1", "3.1.3"},
		Advisory:  "GHSA-73qr-pfmq-6rp8",
		Date:      "2021-11-04",
		Summary:   "Compromised coa releases delivered credential-stealing payload; package was unpublished and remediated.",
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "rc",
		Versions:  []string{"1.2.9", "1.3.9", "2.3.9"},
		Advisory:  "GHSA-g2q5-5433-rhrf",
		Date:      "2021-11-12",
		Summary:   "Compromised rc releases delivered the same credential-stealing payload as the coa incident from the same week.",
	},
}

// IsCompromised checks if a package name+version is in the PyPI
// section of the known-bad list. The legacy two-argument signature
// pre-dates the Ecosystem field; it stays scoped to PyPI so a Python
// package that happens to share a name with an npm advisory (e.g.
// `rc`, `event-stream`) is not falsely flagged by the Python
// checker. Callers that want a cross-ecosystem or npm-only lookup
// should use IsCompromisedIn explicitly.
func IsCompromised(name, version string) *CompromisedPackage {
	return findCompromised(EcosystemPyPI, name, version)
}

// IsCompromisedIn restricts the lookup to a specific ecosystem. Use
// this from the npm checker so a PyPI package that happens to share a
// name with an npm package is not falsely flagged.
func IsCompromisedIn(ecosystem, name, version string) *CompromisedPackage {
	return findCompromised(ecosystem, name, version)
}

func findCompromised(ecosystem, name, version string) *CompromisedPackage {
	for i := range KnownCompromised {
		entry := &KnownCompromised[i]
		if entry.Name != name {
			continue
		}
		if ecosystem != "" {
			entryEco := entry.Ecosystem
			if entryEco == "" {
				entryEco = EcosystemPyPI
			}
			if entryEco != ecosystem {
				continue
			}
		}
		for _, v := range entry.Versions {
			if v == version {
				return entry
			}
		}
	}
	return nil
}
