// Package incident provides detection and cleanup of compromised packages,
// malicious .pth / lifecycle artifacts, and persistence vectors across the
// supported language ecosystems (Python and npm).
package incident

import "github.com/garagon/aguara/internal/intel"

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
	Ecosystem string `json:"ecosystem,omitempty"`
	Name      string `json:"name"`
	// Versions lists the exact affected versions. Either Versions or
	// Ranges (or both) must be set for an entry to match anything.
	Versions []string `json:"versions,omitempty"`
	// Ranges lists affected version ranges for packages where no exact
	// version list applies -- e.g. a whole-package compromise where
	// every published version is malicious (introduced:"0"). Ranges
	// match only for ecosystems whose grammar the runtime matcher can
	// evaluate (npm in phase 1; see intel.EcosystemSupportsRanges). A
	// range-only entry for an unsupported ecosystem will not match.
	Ranges   []intel.VersionRange `json:"ranges,omitempty"`
	Advisory string               `json:"advisory"`
	Date     string               `json:"date"`
	Summary  string               `json:"summary"`
	IOCs     []IOC                `json:"iocs,omitempty"`
}

// IOC is a single indicator of compromise associated with a known-bad
// package. Type names the indicator class (path, hash, endpoint); Value
// is the literal string the detector looks for. Optional and additive;
// older entries that do not carry IOCs continue to work.
type IOC struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// trapdoorAdvisory is the single advisory ID shared by every TrapDoor
// campaign entry below. One ID keeps the campaign readable in output
// and gives the matcher's same-ID version-merge a single anchor.
const trapdoorAdvisory = "SOCKET-2026-05-24-trapdoor"

// trapdoorWholePackageRange is the affected-range shared by the npm
// TrapDoor packages npm security-held entirely: OSV records them as
// introduced:"0" with no fixed version, meaning every published
// version is malicious. The range-capable matcher (npm semver) flags
// the package at any installed version. Shared so the 16 entries that
// use it stay consistent. We deliberately do NOT embed the equivalent
// OSV range corpus, which carries ~197k npm whole-package records and
// would bloat the binary roughly 7x; the campaign's confirmed packages
// ride the small hand-curated list instead.
var trapdoorWholePackageRange = []intel.VersionRange{{Type: "SEMVER", Introduced: "0"}}

// trapdoorNPMIOCs / trapdoorPyPIIOCs are the campaign indicators from
// the Socket report, attached as metadata to each TrapDoor entry. They
// are shared (the whole campaign uses one payload), so they live in a
// single slice each rather than being copy-pasted per entry. IOCs are
// metadata only: matching is by (ecosystem, name, version), so these
// never widen detection or risk a false positive.
var (
	trapdoorNPMIOCs = []IOC{
		{Type: "runtime", Value: "P-2024-001"},
		{Type: "path", Value: "trap-core.js"},
		{Type: "path", Value: ".cursorrules"},
		{Type: "path", Value: "CLAUDE.md"},
	}
	trapdoorPyPIIOCs = []IOC{
		{Type: "runtime", Value: "P-2024-001"},
		{Type: "endpoint", Value: "ddjidd564.github.io"},
		{Type: "path", Value: "defi-security-best-practices"},
	}
)

// miasmaAdvisory is the single advisory ID shared by every entry in
// the Red Hat / @redhat-cloud-services compromise below. One ID keeps
// the campaign readable in output and anchors the matcher's same-ID
// version merge.
const miasmaAdvisory = "AIKIDO-2026-06-01-redhat-miasma"

// miasmaSummary is the shared summary for every Miasma entry. The
// finding title already names the specific package+version+advisory,
// so the summary carries the campaign behaviour rather than per-package
// detail. Shared so the 32 entries stay consistent.
const miasmaSummary = "Red Hat @redhat-cloud-services/* npm compromise (\"Miasma\", a Mini Shai-Hulud derivative). " +
	"Affected versions declare a preinstall hook running `node index.js`, executing an obfuscated ~4.2 MB " +
	"credential-stealing payload that sweeps CI/OIDC tokens (GITHUB_TOKEN, ACTIONS_RUNTIME_TOKEN), npm/PyPI " +
	"publish tokens, AWS/GCP/Azure cloud credentials, HashiCorp Vault tokens, kubeconfig, SSH and GPG keys, " +
	"Docker registry credentials, and .env files. Published via GitHub Actions OIDC trusted-publishing abuse."

// miasmaIOCs are the campaign indicators from the Aikido report,
// attached as metadata to each Miasma entry. IOCs are metadata only:
// matching is by (ecosystem, name, version), so these never widen
// detection or risk a false positive.
var miasmaIOCs = []IOC{
	{Type: "runtime", Value: "Miasma"},
	{Type: "runtime", Value: "Mini Shai-Hulud"},
	{Type: "path", Value: "index.js"},
	{Type: "lifecycle", Value: "preinstall"},
	{Type: "credential-target", Value: "GITHUB_TOKEN"},
	{Type: "credential-target", Value: "ACTIONS_RUNTIME_TOKEN"},
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
	{
		Ecosystem: EcosystemNPM,
		Name:      "node-ipc",
		Versions:  []string{"9.1.6", "9.2.3", "12.0.1"},
		Advisory:  "SOCKET-2026-05-14-node-ipc",
		Date:      "2026-05-14",
		Summary:   "Compromised node-ipc releases shipped an obfuscated CommonJS credential-stealing payload in node-ipc.cjs; CommonJS consumers trigger it via require(\"node-ipc\"). Exfiltrates secrets via DNS TXT queries against bt.node.js and an HTTPS endpoint at sh.azurestaticprovider.net.",
		IOCs: []IOC{
			{Type: "hash", Value: "96097e0612d9575cb133021017fb1a5c68a03b60f9f3d24ebdc0e628d9034144"},
			{Type: "endpoint", Value: "sh.azurestaticprovider.net"},
			{Type: "endpoint", Value: "37.16.75.69"},
			{Type: "dns-zone", Value: "bt.node.js"},
			{Type: "runtime", Value: "__ntw"},
			{Type: "runtime", Value: "__ntRun"},
		},
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "node-ipc",
		Versions:  []string{"10.1.1", "10.1.2", "11.0.0", "11.1.0"},
		Advisory:  "SOCKET-node-ipc-historical-malicious",
		Date:      "2022-03-07",
		Summary:   "Historical malicious node-ipc releases (originally surfaced as the \"peacenotwar\" / RIAEvangelist incident) tied to destructive or unauthorized file-writing behavior on installs from specific geographies. Listed separately from the 2026 compromise because the payload and motivation differ.",
	},

	// --- Mini Shai-Hulud 2026 supply-chain wave (@antv) ---
	//
	// May 2026 campaign documented by Socket targeting AntV and a
	// small set of related visualization packages. The malicious
	// versions ship install-time / import-time credential-stealing
	// payloads. Every entry below is verified against the npm
	// registry: the registry's `deprecated` field on the version
	// carries an explicit security, "risk", "published in error",
	// or malicious-version notice. Versions without that registry
	// signal are intentionally omitted even when third-party
	// trackers list the package.
	//
	// The TanStack / Mistral / UiPath wave from the same campaign
	// is already covered by the embedded OSV snapshot
	// (MAL-2026-3432 and adjacent MAL-2026-* records) and is not
	// duplicated here.
	//
	// Sources:
	//   - https://socket.dev/blog/antv-packages-compromised
	//   - npm registry metadata (registry.npmjs.org)
	{
		Ecosystem: EcosystemNPM,
		Name:      "@antv/g2",
		Versions:  []string{"5.5.8", "5.6.8"},
		Advisory:  "SOCKET-2026-05-19-mini-shai-hulud-antv",
		Date:      "2026-05-19",
		Summary:   "Mini Shai-Hulud-linked npm compromise; affected @antv/g2 versions were flagged by the maintainers via npm's deprecated field (reason: \"risk\"). Aligned with the @antv wave Socket reported in May 2026.",
		IOCs: []IOC{
			{Type: "runtime", Value: "bun"},
			{Type: "path", Value: "setup.mjs"},
			{Type: "endpoint", Value: "filev2.getsession.org"},
			{Type: "endpoint", Value: "t.m-kosche.com"},
			{Type: "path", Value: "/api/public/otel/v1/traces"},
		},
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "@antv/g6",
		Versions:  []string{"5.2.1", "5.3.1"},
		Advisory:  "SOCKET-2026-05-19-mini-shai-hulud-antv",
		Date:      "2026-05-19",
		Summary:   "Mini Shai-Hulud-linked npm compromise; npm deprecated message flags these versions as published with a compromised key.",
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "@antv/x6",
		Versions:  []string{"3.2.7", "3.3.7"},
		Advisory:  "SOCKET-2026-05-19-mini-shai-hulud-antv",
		Date:      "2026-05-19",
		Summary:   "Mini Shai-Hulud-linked npm compromise; versions flagged via npm's deprecated field (reason: \"published in error\") and removed from latest dist-tag.",
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "@antv/l7",
		Versions:  []string{"2.26.10", "2.27.10"},
		Advisory:  "SOCKET-2026-05-19-mini-shai-hulud-antv",
		Date:      "2026-05-19",
		Summary:   "Mini Shai-Hulud-linked npm compromise; npm deprecated message labels these versions as malicious.",
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "@antv/f2",
		Versions:  []string{"5.16.0"},
		Advisory:  "SOCKET-2026-05-19-mini-shai-hulud-antv",
		Date:      "2026-05-19",
		Summary:   "Mini Shai-Hulud-linked npm compromise; npm deprecated message flags this version (reason: \"risk\").",
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "@antv/data-set",
		Versions:  []string{"0.12.8", "0.13.8"},
		Advisory:  "SOCKET-2026-05-19-mini-shai-hulud-antv",
		Date:      "2026-05-19",
		Summary:   "Mini Shai-Hulud-linked npm compromise; npm deprecated message flags these versions as published in error.",
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "echarts-for-react",
		Versions:  []string{"3.0.7", "3.1.7", "3.2.7"},
		Advisory:  "SOCKET-2026-05-19-mini-shai-hulud-antv",
		Date:      "2026-05-19",
		Summary:   "Mini Shai-Hulud-linked npm compromise affecting echarts-for-react alongside the @antv wave; npm deprecated message flags these versions as published in error.",
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "timeago.js",
		Versions:  []string{"4.1.2"},
		Advisory:  "SOCKET-2026-05-19-mini-shai-hulud-antv",
		Date:      "2026-05-19",
		Summary:   "Mini Shai-Hulud-linked npm compromise; npm deprecated message flags this version as published in error.",
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "size-sensor",
		Versions:  []string{"1.0.4", "1.1.4", "1.2.4"},
		Advisory:  "SOCKET-2026-05-19-mini-shai-hulud-antv",
		Date:      "2026-05-19",
		Summary:   "Mini Shai-Hulud-linked npm compromise; npm deprecated message flags these versions as published in error.",
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "canvas-nest.js",
		Versions:  []string{"2.2.4"},
		Advisory:  "SOCKET-2026-05-19-mini-shai-hulud-antv",
		Date:      "2026-05-19",
		Summary:   "Mini Shai-Hulud-linked npm compromise; npm deprecated message flags this version as published in error.",
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "@antv/g-image-exporter",
		Versions:  []string{"1.2.42"},
		Advisory:  "SOCKET-2026-05-19-mini-shai-hulud-antv",
		Date:      "2026-05-19",
		Summary:   "Mini Shai-Hulud-linked npm compromise; npm deprecated message flags this version as published in error. The version is also anomalous relative to the package's latest stable lineage (1.0.x), consistent with the @antv wave pattern of attacker-bumped majors/minors above the legitimate latest.",
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "@antv/infographic",
		Versions:  []string{"0.3.19", "0.4.19"},
		Advisory:  "SOCKET-2026-05-19-mini-shai-hulud-antv",
		Date:      "2026-05-19",
		Summary:   "Mini Shai-Hulud-linked npm compromise; npm deprecated message flags these versions as published with a compromised key.",
	},

	// --- TrapDoor crypto-stealer campaign 2026-05-24 (npm + PyPI) ---
	//
	// Cross-ecosystem campaign documented by Socket (2026-05-24). The
	// npm packages run a postinstall hook that executes a shared
	// trap-core.js payload (developer-secret harvesting, AWS/GitHub
	// credential validation, persistence via .cursorrules / CLAUDE.md /
	// git + shell hooks). The PyPI packages execute on import,
	// downloading attacker-hosted JavaScript from ddjidd564.github.io
	// and running it through `node -e`. Campaign marker: P-2024-001.
	//
	// The verification harness split the campaign into:
	//   - 12 packages with exact OSV versions (5 npm @ 1.0.12,
	//     7 PyPI @ 0.1.0/0.1.1) -- the exact-version entries below.
	//   - 16 npm packages OSV carries as range-only (introduced:0)
	//     because npm security-held the whole package; every version
	//     is malicious. These were excluded at v0.18.4 because the
	//     matcher could not evaluate ranges. The matcher now can (npm
	//     semver), so they are listed below as range-only entries
	//     (Ranges: trapdoorWholePackageRange) rather than embedding
	//     OSV's ~197k-record npm range corpus, which would bloat the
	//     binary roughly 7x for no extra campaign coverage.
	//   - 6 crates.io names with no OSV record and a 404 on the
	//     registry; crates.io is out of manual intel until exact
	//     versions are confirmed or a behavioral Rust rule lands.
	//
	// Source: https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates
	{
		Ecosystem: EcosystemNPM,
		Name:      "build-scripts-utils",
		Versions:  []string{"1.0.12"},
		Advisory:  trapdoorAdvisory,
		Date:      "2026-05-24",
		Summary:   "TrapDoor campaign npm package; postinstall trap-core.js credential-stealer with persistence. Confirmed malicious at 1.0.12 (OSV MAL-2026-4276).",
		IOCs:      trapdoorNPMIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "dev-env-bootstrapper",
		Versions:  []string{"1.0.12"},
		Advisory:  trapdoorAdvisory,
		Date:      "2026-05-24",
		Summary:   "TrapDoor campaign npm package; postinstall trap-core.js credential-stealer with persistence. Confirmed malicious at 1.0.12 (OSV MAL-2026-4277).",
		IOCs:      trapdoorNPMIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "llm-context-compressor",
		Versions:  []string{"1.0.12"},
		Advisory:  trapdoorAdvisory,
		Date:      "2026-05-24",
		Summary:   "TrapDoor campaign npm package; postinstall trap-core.js credential-stealer with persistence. Confirmed malicious at 1.0.12 (OSV MAL-2026-4278).",
		IOCs:      trapdoorNPMIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "prompt-engineering-toolkit",
		Versions:  []string{"1.0.12"},
		Advisory:  trapdoorAdvisory,
		Date:      "2026-05-24",
		Summary:   "TrapDoor campaign npm package; postinstall trap-core.js credential-stealer with persistence. Confirmed malicious at 1.0.12 (OSV MAL-2026-4282).",
		IOCs:      trapdoorNPMIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "token-usage-tracker",
		Versions:  []string{"1.0.12"},
		Advisory:  trapdoorAdvisory,
		Date:      "2026-05-24",
		Summary:   "TrapDoor campaign npm package; postinstall trap-core.js credential-stealer with persistence. Confirmed malicious at 1.0.12 (OSV MAL-2026-4283).",
		IOCs:      trapdoorNPMIOCs,
	},
	{
		Ecosystem: EcosystemPyPI,
		Name:      "cryptowallet-safety",
		Versions:  []string{"0.1.0"},
		Advisory:  trapdoorAdvisory,
		Date:      "2026-05-24",
		Summary:   "TrapDoor campaign PyPI package; import-time remote-JS execution via node -e from ddjidd564.github.io. Confirmed malicious at 0.1.0 (OSV MAL-2026-4259).",
		IOCs:      trapdoorPyPIIOCs,
	},
	{
		Ecosystem: EcosystemPyPI,
		Name:      "data-pipeline-check",
		Versions:  []string{"0.1.0", "0.1.1"},
		Advisory:  trapdoorAdvisory,
		Date:      "2026-05-24",
		Summary:   "TrapDoor campaign PyPI package; import-time remote-JS execution via node -e from ddjidd564.github.io. Confirmed malicious at 0.1.0 and 0.1.1 (OSV MAL-2026-4271).",
		IOCs:      trapdoorPyPIIOCs,
	},
	{
		Ecosystem: EcosystemPyPI,
		Name:      "defi-risk-scanner",
		Versions:  []string{"0.1.0"},
		Advisory:  trapdoorAdvisory,
		Date:      "2026-05-24",
		Summary:   "TrapDoor campaign PyPI package; import-time remote-JS execution via node -e from ddjidd564.github.io. Confirmed malicious at 0.1.0 (OSV MAL-2026-4260).",
		IOCs:      trapdoorPyPIIOCs,
	},
	{
		Ecosystem: EcosystemPyPI,
		Name:      "env-loader-cli",
		Versions:  []string{"0.1.0", "0.1.1"},
		Advisory:  trapdoorAdvisory,
		Date:      "2026-05-24",
		Summary:   "TrapDoor campaign PyPI package; import-time remote-JS execution via node -e from ddjidd564.github.io. Confirmed malicious at 0.1.0 and 0.1.1 (OSV MAL-2026-4272).",
		IOCs:      trapdoorPyPIIOCs,
	},
	{
		Ecosystem: EcosystemPyPI,
		Name:      "eth-security-auditor",
		Versions:  []string{"0.1.0"},
		Advisory:  trapdoorAdvisory,
		Date:      "2026-05-24",
		Summary:   "TrapDoor campaign PyPI package; import-time remote-JS execution via node -e from ddjidd564.github.io. Confirmed malicious at 0.1.0 (OSV MAL-2026-4261).",
		IOCs:      trapdoorPyPIIOCs,
	},
	{
		Ecosystem: EcosystemPyPI,
		Name:      "git-config-sync",
		Versions:  []string{"0.1.0", "0.1.1"},
		Advisory:  trapdoorAdvisory,
		Date:      "2026-05-24",
		Summary:   "TrapDoor campaign PyPI package; import-time remote-JS execution via node -e from ddjidd564.github.io. Confirmed malicious at 0.1.0 and 0.1.1 (OSV MAL-2026-4273).",
		IOCs:      trapdoorPyPIIOCs,
	},
	{
		Ecosystem: EcosystemPyPI,
		Name:      "solidity-build-guard",
		Versions:  []string{"0.1.0"},
		Advisory:  trapdoorAdvisory,
		Date:      "2026-05-24",
		Summary:   "TrapDoor campaign PyPI package; import-time remote-JS execution via node -e from ddjidd564.github.io. Confirmed malicious at 0.1.0 (OSV MAL-2026-4262).",
		IOCs:      trapdoorPyPIIOCs,
	},

	// TrapDoor npm packages npm security-held in their entirety: OSV
	// records each as introduced:0 (every version malicious). Carried
	// as range-only entries so the npm range-capable matcher flags any
	// installed version. Confirmed by the verification harness (each
	// cites its OSV MAL- id).
	{
		Ecosystem: EcosystemNPM,
		Name:      "async-pipeline-builder",
		Ranges:    trapdoorWholePackageRange,
		Advisory:  trapdoorAdvisory,
		Date:      "2026-05-24",
		Summary:   "TrapDoor campaign npm package; whole package malicious (npm security-held, every version). Confirmed via OSV MAL-2026-4275 (introduced:0).",
		IOCs:      trapdoorNPMIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "chain-key-validator",
		Ranges:    trapdoorWholePackageRange,
		Advisory:  trapdoorAdvisory,
		Date:      "2026-05-24",
		Summary:   "TrapDoor campaign npm package; whole package malicious (npm security-held, every version). Confirmed via OSV MAL-2026-4202 (introduced:0).",
		IOCs:      trapdoorNPMIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "crypto-credential-scanner",
		Ranges:    trapdoorWholePackageRange,
		Advisory:  trapdoorAdvisory,
		Date:      "2026-05-24",
		Summary:   "TrapDoor campaign npm package; whole package malicious (npm security-held, every version). Confirmed via OSV MAL-2026-4203 (introduced:0).",
		IOCs:      trapdoorNPMIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "defi-env-auditor",
		Ranges:    trapdoorWholePackageRange,
		Advisory:  trapdoorAdvisory,
		Date:      "2026-05-24",
		Summary:   "TrapDoor campaign npm package; whole package malicious (npm security-held, every version). Confirmed via OSV MAL-2026-4204 (introduced:0).",
		IOCs:      trapdoorNPMIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "defi-threat-scanner",
		Ranges:    trapdoorWholePackageRange,
		Advisory:  trapdoorAdvisory,
		Date:      "2026-05-24",
		Summary:   "TrapDoor campaign npm package; whole package malicious (npm security-held, every version). Confirmed via OSV MAL-2026-4205 (introduced:0).",
		IOCs:      trapdoorNPMIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "deployment-key-auditor",
		Ranges:    trapdoorWholePackageRange,
		Advisory:  trapdoorAdvisory,
		Date:      "2026-05-24",
		Summary:   "TrapDoor campaign npm package; whole package malicious (npm security-held, every version). Confirmed via OSV MAL-2026-4206 (introduced:0).",
		IOCs:      trapdoorNPMIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "eth-wallet-sentinel",
		Ranges:    trapdoorWholePackageRange,
		Advisory:  trapdoorAdvisory,
		Date:      "2026-05-24",
		Summary:   "TrapDoor campaign npm package; whole package malicious (npm security-held, every version). Confirmed via OSV MAL-2026-4207 (introduced:0).",
		IOCs:      trapdoorNPMIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "mnemonic-safety-check",
		Ranges:    trapdoorWholePackageRange,
		Advisory:  trapdoorAdvisory,
		Date:      "2026-05-24",
		Summary:   "TrapDoor campaign npm package; whole package malicious (npm security-held, every version). Confirmed via OSV MAL-2026-4208 (introduced:0).",
		IOCs:      trapdoorNPMIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "model-switch-router",
		Ranges:    trapdoorWholePackageRange,
		Advisory:  trapdoorAdvisory,
		Date:      "2026-05-24",
		Summary:   "TrapDoor campaign npm package; whole package malicious (npm security-held, every version). Confirmed via OSV MAL-2026-4279 (introduced:0).",
		IOCs:      trapdoorNPMIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "node-setup-helpers",
		Ranges:    trapdoorWholePackageRange,
		Advisory:  trapdoorAdvisory,
		Date:      "2026-05-24",
		Summary:   "TrapDoor campaign npm package; whole package malicious (npm security-held, every version). Confirmed via OSV MAL-2026-4280 (introduced:0).",
		IOCs:      trapdoorNPMIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "project-init-tools",
		Ranges:    trapdoorWholePackageRange,
		Advisory:  trapdoorAdvisory,
		Date:      "2026-05-24",
		Summary:   "TrapDoor campaign npm package; whole package malicious (npm security-held, every version). Confirmed via OSV MAL-2026-4281 (introduced:0).",
		IOCs:      trapdoorNPMIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "solidity-deploy-guard",
		Ranges:    trapdoorWholePackageRange,
		Advisory:  trapdoorAdvisory,
		Date:      "2026-05-24",
		Summary:   "TrapDoor campaign npm package; whole package malicious (npm security-held, every version). Confirmed via OSV MAL-2026-4218 (introduced:0).",
		IOCs:      trapdoorNPMIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "wallet-backup-verifier",
		Ranges:    trapdoorWholePackageRange,
		Advisory:  trapdoorAdvisory,
		Date:      "2026-05-24",
		Summary:   "TrapDoor campaign npm package; whole package malicious (npm security-held, every version). Confirmed via OSV MAL-2026-4250 (introduced:0).",
		IOCs:      trapdoorNPMIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "wallet-security-checker",
		Ranges:    trapdoorWholePackageRange,
		Advisory:  trapdoorAdvisory,
		Date:      "2026-05-24",
		Summary:   "TrapDoor campaign npm package; whole package malicious (npm security-held, every version). Confirmed via OSV MAL-2026-4219 (introduced:0).",
		IOCs:      trapdoorNPMIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "web3-secrets-detector",
		Ranges:    trapdoorWholePackageRange,
		Advisory:  trapdoorAdvisory,
		Date:      "2026-05-24",
		Summary:   "TrapDoor campaign npm package; whole package malicious (npm security-held, every version). Confirmed via OSV MAL-2026-4220 (introduced:0).",
		IOCs:      trapdoorNPMIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "workspace-config-loader",
		Ranges:    trapdoorWholePackageRange,
		Advisory:  trapdoorAdvisory,
		Date:      "2026-05-24",
		Summary:   "TrapDoor campaign npm package; whole package malicious (npm security-held, every version). Confirmed via OSV MAL-2026-4284 (introduced:0).",
		IOCs:      trapdoorNPMIOCs,
	},

	// --- Red Hat / Miasma 2026-06-01 npm compromise (@redhat-cloud-services) ---
	//
	// Campaign documented by Aikido (2026-06-01): a compromised Red Hat
	// developer account pushed malicious orphan commits to the
	// @redhat-cloud-services repositories, which published malicious
	// versions across 32 packages via GitHub Actions OIDC
	// trusted-publishing abuse (a CI workflow requests an `id-token:
	// write` token and publishes with it). Each malicious version
	// declares `"preinstall": "node index.js"` and ships an obfuscated
	// ~4.2 MB credential-stealing payload ("Miasma", a Mini Shai-Hulud
	// derivative).
	//
	// Coverage note: Aikido's report headlines "96 malicious versions
	// across 32 packages" but its body enumerates 63 specific
	// package@version tuples (the 32 packages below). Those 63 are the
	// only versions we can verify, so they are the only ones listed.
	// We deliberately do NOT synthesise the ~33 unenumerated versions
	// and do NOT widen to a range-only whole-package match: the
	// legitimate @redhat-cloud-services packages have many clean
	// releases, so a guessed range would false-positive real installs.
	// A neighbour version (e.g. chrome@2.3.0) must stay clean. If the
	// full list is later published, extend the Versions slices here.
	//
	// Source: https://www.aikido.dev/blog/red-hat-npm-packages-compromised-credential-stealing-worm
	{
		Ecosystem: EcosystemNPM,
		Name:      "@redhat-cloud-services/chrome",
		Versions:  []string{"2.3.1", "2.3.2"},
		Advisory:  miasmaAdvisory,
		Date:      "2026-06-01",
		Summary:   miasmaSummary,
		IOCs:      miasmaIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "@redhat-cloud-services/compliance-client",
		Versions:  []string{"4.0.3", "4.0.4"},
		Advisory:  miasmaAdvisory,
		Date:      "2026-06-01",
		Summary:   miasmaSummary,
		IOCs:      miasmaIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "@redhat-cloud-services/config-manager-client",
		Versions:  []string{"5.0.4", "5.0.5"},
		Advisory:  miasmaAdvisory,
		Date:      "2026-06-01",
		Summary:   miasmaSummary,
		IOCs:      miasmaIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "@redhat-cloud-services/entitlements-client",
		Versions:  []string{"4.0.11", "4.0.12"},
		Advisory:  miasmaAdvisory,
		Date:      "2026-06-01",
		Summary:   miasmaSummary,
		IOCs:      miasmaIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "@redhat-cloud-services/eslint-config-redhat-cloud-services",
		Versions:  []string{"3.2.1", "3.2.2"},
		Advisory:  miasmaAdvisory,
		Date:      "2026-06-01",
		Summary:   miasmaSummary,
		IOCs:      miasmaIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "@redhat-cloud-services/frontend-components",
		Versions:  []string{"7.7.2", "7.7.3"},
		Advisory:  miasmaAdvisory,
		Date:      "2026-06-01",
		Summary:   miasmaSummary,
		IOCs:      miasmaIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "@redhat-cloud-services/frontend-components-advisor-components",
		Versions:  []string{"3.8.2"},
		Advisory:  miasmaAdvisory,
		Date:      "2026-06-01",
		Summary:   miasmaSummary,
		IOCs:      miasmaIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "@redhat-cloud-services/frontend-components-config",
		Versions:  []string{"6.11.3", "6.11.4"},
		Advisory:  miasmaAdvisory,
		Date:      "2026-06-01",
		Summary:   miasmaSummary,
		IOCs:      miasmaIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "@redhat-cloud-services/frontend-components-config-utilities",
		Versions:  []string{"4.11.2", "4.11.3"},
		Advisory:  miasmaAdvisory,
		Date:      "2026-06-01",
		Summary:   miasmaSummary,
		IOCs:      miasmaIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "@redhat-cloud-services/frontend-components-notifications",
		Versions:  []string{"6.9.2", "6.9.3"},
		Advisory:  miasmaAdvisory,
		Date:      "2026-06-01",
		Summary:   miasmaSummary,
		IOCs:      miasmaIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "@redhat-cloud-services/frontend-components-remediations",
		Versions:  []string{"4.9.2", "4.9.3"},
		Advisory:  miasmaAdvisory,
		Date:      "2026-06-01",
		Summary:   miasmaSummary,
		IOCs:      miasmaIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "@redhat-cloud-services/frontend-components-testing",
		Versions:  []string{"1.2.1", "1.2.2"},
		Advisory:  miasmaAdvisory,
		Date:      "2026-06-01",
		Summary:   miasmaSummary,
		IOCs:      miasmaIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "@redhat-cloud-services/frontend-components-translations",
		Versions:  []string{"4.4.1", "4.4.2"},
		Advisory:  miasmaAdvisory,
		Date:      "2026-06-01",
		Summary:   miasmaSummary,
		IOCs:      miasmaIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "@redhat-cloud-services/frontend-components-utilities",
		Versions:  []string{"7.4.1", "7.4.2"},
		Advisory:  miasmaAdvisory,
		Date:      "2026-06-01",
		Summary:   miasmaSummary,
		IOCs:      miasmaIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "@redhat-cloud-services/hcc-feo-mcp",
		Versions:  []string{"0.3.1", "0.3.2"},
		Advisory:  miasmaAdvisory,
		Date:      "2026-06-01",
		Summary:   miasmaSummary,
		IOCs:      miasmaIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "@redhat-cloud-services/hcc-kessel-mcp",
		Versions:  []string{"0.3.1", "0.3.2"},
		Advisory:  miasmaAdvisory,
		Date:      "2026-06-01",
		Summary:   miasmaSummary,
		IOCs:      miasmaIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "@redhat-cloud-services/hcc-pf-mcp",
		Versions:  []string{"0.6.1", "0.6.2"},
		Advisory:  miasmaAdvisory,
		Date:      "2026-06-01",
		Summary:   miasmaSummary,
		IOCs:      miasmaIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "@redhat-cloud-services/host-inventory-client",
		Versions:  []string{"5.0.3", "5.0.4"},
		Advisory:  miasmaAdvisory,
		Date:      "2026-06-01",
		Summary:   miasmaSummary,
		IOCs:      miasmaIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "@redhat-cloud-services/insights-client",
		Versions:  []string{"4.0.4", "4.0.5"},
		Advisory:  miasmaAdvisory,
		Date:      "2026-06-01",
		Summary:   miasmaSummary,
		IOCs:      miasmaIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "@redhat-cloud-services/integrations-client",
		Versions:  []string{"6.0.4", "6.0.5"},
		Advisory:  miasmaAdvisory,
		Date:      "2026-06-01",
		Summary:   miasmaSummary,
		IOCs:      miasmaIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "@redhat-cloud-services/javascript-clients-shared",
		Versions:  []string{"2.0.8", "2.0.9"},
		Advisory:  miasmaAdvisory,
		Date:      "2026-06-01",
		Summary:   miasmaSummary,
		IOCs:      miasmaIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "@redhat-cloud-services/notifications-client",
		Versions:  []string{"6.1.4", "6.1.5"},
		Advisory:  miasmaAdvisory,
		Date:      "2026-06-01",
		Summary:   miasmaSummary,
		IOCs:      miasmaIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "@redhat-cloud-services/patch-client",
		Versions:  []string{"4.0.4", "4.0.5"},
		Advisory:  miasmaAdvisory,
		Date:      "2026-06-01",
		Summary:   miasmaSummary,
		IOCs:      miasmaIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "@redhat-cloud-services/quickstarts-client",
		Versions:  []string{"4.0.11", "4.0.12"},
		Advisory:  miasmaAdvisory,
		Date:      "2026-06-01",
		Summary:   miasmaSummary,
		IOCs:      miasmaIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "@redhat-cloud-services/rbac-client",
		Versions:  []string{"9.0.3", "9.0.4"},
		Advisory:  miasmaAdvisory,
		Date:      "2026-06-01",
		Summary:   miasmaSummary,
		IOCs:      miasmaIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "@redhat-cloud-services/remediations-client",
		Versions:  []string{"4.0.4", "4.0.5"},
		Advisory:  miasmaAdvisory,
		Date:      "2026-06-01",
		Summary:   miasmaSummary,
		IOCs:      miasmaIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "@redhat-cloud-services/rule-components",
		Versions:  []string{"4.7.2", "4.7.3"},
		Advisory:  miasmaAdvisory,
		Date:      "2026-06-01",
		Summary:   miasmaSummary,
		IOCs:      miasmaIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "@redhat-cloud-services/sources-client",
		Versions:  []string{"3.0.10", "3.0.11"},
		Advisory:  miasmaAdvisory,
		Date:      "2026-06-01",
		Summary:   miasmaSummary,
		IOCs:      miasmaIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "@redhat-cloud-services/topological-inventory-client",
		Versions:  []string{"3.0.10", "3.0.11"},
		Advisory:  miasmaAdvisory,
		Date:      "2026-06-01",
		Summary:   miasmaSummary,
		IOCs:      miasmaIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "@redhat-cloud-services/tsc-transform-imports",
		Versions:  []string{"1.2.2"},
		Advisory:  miasmaAdvisory,
		Date:      "2026-06-01",
		Summary:   miasmaSummary,
		IOCs:      miasmaIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "@redhat-cloud-services/types",
		Versions:  []string{"3.6.1", "3.6.2", "3.6.4"},
		Advisory:  miasmaAdvisory,
		Date:      "2026-06-01",
		Summary:   miasmaSummary,
		IOCs:      miasmaIOCs,
	},
	{
		Ecosystem: EcosystemNPM,
		Name:      "@redhat-cloud-services/vulnerabilities-client",
		Versions:  []string{"2.1.8", "2.1.9"},
		Advisory:  miasmaAdvisory,
		Date:      "2026-06-01",
		Summary:   miasmaSummary,
		IOCs:      miasmaIOCs,
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
