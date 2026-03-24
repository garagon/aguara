// Package incident provides detection and cleanup of compromised Python
// packages, malicious .pth files, and persistence artifacts.
package incident

// CompromisedPackage describes a known-bad package+version combination.
type CompromisedPackage struct {
	Name     string   `json:"name"`
	Versions []string `json:"versions"`
	Advisory string   `json:"advisory"`
	Date     string   `json:"date"`
	Summary  string   `json:"summary"`
}

// KnownCompromised is the embedded list of known compromised packages.
// Updated with each Aguara release.
var KnownCompromised = []CompromisedPackage{
	{
		Name:     "litellm",
		Versions: []string{"1.82.7", "1.82.8"},
		Advisory: "PYSEC-2026-litellm",
		Date:     "2026-03-24",
		Summary:  "Malicious .pth file exfiltrates credentials (SSH, cloud, K8s) and installs backdoor with systemd persistence",
	},
}

// IsCompromised checks if a package name+version is in the known-bad list.
func IsCompromised(name, version string) *CompromisedPackage {
	for i := range KnownCompromised {
		if KnownCompromised[i].Name != name {
			continue
		}
		for _, v := range KnownCompromised[i].Versions {
			if v == version {
				return &KnownCompromised[i]
			}
		}
	}
	return nil
}
