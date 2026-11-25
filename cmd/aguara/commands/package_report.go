package commands

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/garagon/aguara/internal/incident"
	"github.com/garagon/aguara/internal/output"
	"github.com/garagon/aguara/internal/types"
)

// packageFingerprintKey is the partialFingerprints key of package check
// results. It differs from the content key (aguara/v1) because package
// findings are never baselineable.
const packageFingerprintKey = "aguara/package/v1"

// packageDocsURI documents package checks on the default branch.
const packageDocsURI = "https://github.com/garagon/aguara/blob/main/README.md#packages-and-lockfiles"

// packageRule documents the SARIF rule of one package finding class.
type packageRule struct {
	name, description, remediation string
}

// packageRules maps finding kinds to their SARIF rules. The rule ID is
// CHECK_ and the upper-cased kind; it identifies the class of finding, and
// the package, version and advisories are in the result.
var packageRules = map[string]packageRule{
	incident.KindCompromisedPackage: {
		name:        "Known malicious package",
		description: "A dependency version resolved by a lockfile, dependency file or installed tree is covered by a malicious-package advisory in Aguara's threat intelligence.",
		remediation: "Remove or replace the package version without installing it, and rotate credentials that environments and CI runs which installed it could reach.",
	},
	incident.KindCachedPackage: {
		name:        "Known malicious package in a package cache",
		description: "A package-manager cache holds a package version covered by a malicious-package advisory.",
		remediation: "Purge the cached package (aguara clean --purge-caches) so a later install cannot reuse it.",
	},
	incident.KindCachedArtifact: {
		name:        "Cached file named like a malicious release",
		description: "A cached file's name matches the name and version of a release covered by a malicious-package advisory.",
		remediation: "Inspect and purge the cached file (aguara clean --purge-caches).",
	},
	incident.KindPthExecutable: {
		name:        "Python .pth file with executable code",
		description: "A .pth file in an installed Python environment contains executable code, which Python runs at every interpreter start.",
		remediation: "Remove the .pth file; legitimate .pth files contain only directory paths.",
	},
	incident.KindPthOversized: {
		name:        "Python .pth file larger than the inspection limit",
		description: "A .pth file is larger than the part Aguara inspects, which is itself abnormal.",
		remediation: "Inspect the file manually; legitimate .pth files contain only a few directory paths.",
	},
	incident.KindPersistenceArtifact: {
		name:        "Known backdoor persistence artifact",
		description: "A file that a known malicious package installs for persistence exists on the host.",
		remediation: "Quarantine the file (aguara clean) and rotate credentials the host held.",
	},
	incident.KindUnresolvedInclude: {
		name:        "Requirements include not checked",
		description: "A requirements file includes another file that Aguara did not read, so the pins in it were not checked.",
		remediation: "Make the included file readable inside the checked directory, or check it where it is.",
	},
}

// packageRuleID is the SARIF rule ID of a package finding.
func packageRuleID(f incident.Finding) string {
	kind := f.Kind
	if kind == "" {
		kind = "finding"
	}
	return "CHECK_" + strings.ToUpper(kind)
}

// packageFingerprint identifies a package finding across runs: its class,
// the package identity and the file it was found in for package findings,
// or the class, file and title for the others. Lines and advisory lists are
// left out so an edit above the entry or a new advisory for the same
// release does not reopen the alert.
func packageFingerprint(f incident.Finding, uri string) string {
	h := sha256.New()
	if f.Package != "" {
		fmt.Fprintf(h, "%s\x00%s\x00%s\x00%s\x00%s", f.Kind, f.Ecosystem, f.Package, f.Version, uri)
	} else {
		fmt.Fprintf(h, "%s\x00%s\x00%s", f.Kind, uri, f.Title)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// packageSARIFResults converts package findings into SARIF results located
// relative to base. A finding outside base (a global environment, a file in
// the home directory) has no repository location, so it becomes a warning
// notification instead of a result.
func packageSARIFResults(findings []incident.Finding, base string) ([]output.SARIFExternalResult, []output.SARIFNotification) {
	var results []output.SARIFExternalResult
	var notes []output.SARIFNotification
	for _, f := range findings {
		id := packageRuleID(f)
		sev, ok := packageSeverity(f.Severity)
		if !ok {
			continue
		}
		uri := sourceRelativeURI(base, f.Path)
		if uri == "" {
			notes = append(notes, output.SARIFNotification{
				Level:   "warning",
				RuleID:  id,
				Message: fmt.Sprintf("%s (%s finding outside the analyzed source root, so it is not reported as a result)", f.Title, strings.ToUpper(f.Severity)),
			})
			continue
		}
		rule := packageRules[f.Kind]
		if rule.name == "" {
			rule = packageRule{name: "Package check finding", description: f.Title, remediation: f.Remediation}
		}
		props := map[string]any{"check_severity": strings.ToUpper(f.Severity)}
		if f.Kind != "" {
			props["kind"] = f.Kind
		}
		if f.Ecosystem != "" {
			props["ecosystem"] = f.Ecosystem
		}
		if f.Package != "" {
			props["package"] = f.Package
		}
		if f.Version != "" {
			props["version"] = f.Version
		}
		if len(f.AdvisoryIDs) > 0 {
			props["advisory_ids"] = f.AdvisoryIDs
		}
		if f.Detail != "" {
			props["detail"] = f.Detail
		}
		if f.Remediation != "" {
			props["remediation"] = f.Remediation
		}
		results = append(results, output.SARIFExternalResult{
			RuleID:          id,
			RuleName:        rule.name,
			RuleDescription: rule.description,
			Remediation:     rule.remediation,
			Category:        "supply-chain",
			HelpURI:         packageDocsURI,
			Severity:        sev,
			Message:         f.Title,
			URI:             uri,
			Line:            f.Line,
			FingerprintKey:  packageFingerprintKey,
			Fingerprint:     packageFingerprint(f, uri),
			Properties:      props,
		})
	}
	return results, notes
}

// displayLocation renders a package finding's path relative to root when
// it lies inside, with ":line" when the line is known, the same way content
// finding paths are shown.
func displayLocation(root string, f incident.Finding) string {
	if f.Path == "" {
		return ""
	}
	p := displayPath(root, f.Path)
	if f.Line > 0 {
		return fmt.Sprintf("%s:%d", p, f.Line)
	}
	return p
}

// writePackageFindingsMarkdown writes the package findings table of the
// check and audit Markdown reports.
func writePackageFindingsMarkdown(w io.Writer, findings []incident.Finding, root string) {
	if len(findings) == 0 {
		return
	}
	fmt.Fprintf(w, "| Severity | Finding | Location |\n")
	fmt.Fprintf(w, "|:--------:|---------|----------|\n")
	for _, f := range findings {
		sev, _ := packageSeverity(f.Severity)
		loc := displayLocation(root, f)
		if loc != "" {
			loc = "`" + output.EscapeMarkdown(loc) + "`"
		}
		fmt.Fprintf(w, "| %s | %s | %s |\n", output.SeverityEmoji(sev), output.EscapeMarkdown(f.Title), loc)
	}
	fmt.Fprintln(w)
	for _, f := range findings {
		if f.Remediation != "" && strings.EqualFold(f.Severity, incident.SevCritical) {
			fmt.Fprintf(w, "> %s\n\n", output.EscapeMarkdown(f.Remediation))
		}
	}
}

// packageSeverityCounts tallies package findings by mapped severity.
func packageSeverityCounts(findings []incident.Finding) map[types.Severity]int {
	counts := map[types.Severity]int{}
	for _, f := range findings {
		if sev, ok := packageSeverity(f.Severity); ok {
			counts[sev]++
		}
	}
	return counts
}
