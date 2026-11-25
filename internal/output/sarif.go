package output

import (
	"encoding/json"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"strings"

	"github.com/garagon/aguara/internal/baseline"
	"github.com/garagon/aguara/internal/rulemeta"
	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/types"
)

// ToolVersion is the aguara version reported in SARIF output.
var ToolVersion = "dev"

const (
	// sarifSchemaURI is the OASIS SARIF 2.1.0 schema (errata 01), the
	// location that resolves.
	sarifSchemaURI = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
	// RuleCatalogURI is the public rule catalog that every built-in rule's
	// helpUri points at.
	RuleCatalogURI = "https://github.com/garagon/aguara/blob/main/RULES.md"
	// SourceRootBaseID is the uriBaseId of artifact URIs that are relative
	// to the root of the git work tree containing the scan target.
	SourceRootBaseID = "%SRCROOT%"
	// cweTaxonomyName names the CWE taxonomy in runs[].taxonomies.
	cweTaxonomyName = "CWE"
)

// SecuritySeverity returns the GitHub code scanning `security-severity`
// score for a severity. GitHub ranks a score over 9.0 as critical, 7.0 to
// 8.9 as high, 4.0 to 6.9 as medium and 0.1 to 3.9 as low, and treats 0.0
// as no security severity; each level maps to a value inside its band.
func SecuritySeverity(sev types.Severity) string {
	switch sev {
	case types.SeverityCritical:
		return "9.5"
	case types.SeverityHigh:
		return "8.0"
	case types.SeverityMedium:
		return "5.5"
	case types.SeverityLow:
		return "2.0"
	default:
		return "0.0"
	}
}

// SARIFFormatter outputs findings in SARIF 2.1.0 format for GitHub Code
// Scanning. The zero value produces a self-contained report; Options adds
// rule documentation, repository-relative locations and invocation details.
type SARIFFormatter struct {
	Options SARIFOptions
}

// SARIFOptions configures a SARIF run beyond what a ScanResult carries.
type SARIFOptions struct {
	// Catalog supplies rule metadata (description, remediation, CWE) by
	// rule ID. A rule missing from it is described from its findings.
	Catalog map[string]rulemeta.Rule
	// BuiltinRules lists the IDs whose helpUri points at the public rule
	// catalog. Custom rules are not documented there and get no helpUri.
	// Nil treats every rule in Catalog as built-in.
	BuiltinRules map[string]bool
	// Category, when set, becomes runs[0].automationDetails.id so GitHub
	// keeps several uploads for one commit apart. A trailing "/" is added
	// when missing, the form GitHub reads as a category with no run ID.
	Category string
	// URIPrefix is the slash-separated path, relative to the source root,
	// of the directory content finding paths are relative to. Empty keeps
	// the finding paths as they are.
	URIPrefix string
	// InWorkTree marks artifact URIs as relative to the git work tree root
	// (uriBaseId %SRCROOT%). False means URIs are relative to the scan
	// target and carry no base.
	InWorkTree bool
	// Commit and Catalog identity are reported in tool.driver.properties.
	Commit        string
	CatalogDigest *types.CatalogInfo
	// Invocation describes how the run ended. Nil reports a successful
	// execution with no exit code.
	Invocation *SARIFInvocation
	// Properties are merged into runs[0].properties.
	Properties map[string]any
}

// SARIFInvocation is runs[0].invocations[0]. Notifications are tool
// execution notifications: problems that did not stop the run but that a
// consumer should see, or the reason a run did not complete.
type SARIFInvocation struct {
	// ExecutionSuccessful is true when the tool finished its analysis,
	// whether or not findings reached a gate.
	ExecutionSuccessful bool
	// ExitCode is the process exit code: 0 completed with no gate
	// tripped, 1 completed and a gate tripped, 2 the run failed or was
	// misused. Negative omits it.
	ExitCode int
	// ExitCodeDescription says why the process exits with ExitCode.
	ExitCodeDescription string
	Notifications       []SARIFNotification
}

// SARIFNotification is one tool execution notification.
type SARIFNotification struct {
	// Level is "error", "warning" or "note".
	Level   string
	Message string
	// RuleID optionally names the rule the notification is about.
	RuleID string
	// URI and Line optionally locate it (URI relative like results).
	URI  string
	Line int
}

// SARIFExternalResult is a result that does not come from a content scan
// finding, such as a package check finding. The caller chooses a stable
// rule ID per finding class and a fingerprint that survives runs.
type SARIFExternalResult struct {
	RuleID          string
	RuleName        string
	RuleDescription string
	Remediation     string
	Category        string
	CWE             []string
	// HelpURI documents the rule; empty omits helpUri.
	HelpURI  string
	Severity types.Severity
	Message  string
	// URI is relative to the source root (see SARIFOptions.InWorkTree),
	// slash-separated. Line is 1-based; zero means the whole file.
	URI            string
	Line           int
	FingerprintKey string
	Fingerprint    string
	Properties     map[string]any
}

// SARIF exit code meanings, recorded on every invocation.
var sarifExitCodeMeanings = map[string]string{
	"0": "completed; no gate tripped",
	"1": "completed; findings or the audit decision reached a --fail-on or --fail-on-decision gate",
	"2": "the command failed or was used incorrectly; results may be missing",
}

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool               sarifTool                        `json:"tool"`
	Invocations        []sarifInvocation                `json:"invocations"`
	AutomationDetails  *sarifAutomationDetails          `json:"automationDetails,omitempty"`
	OriginalURIBaseIDs map[string]sarifArtifactLocation `json:"originalUriBaseIds,omitempty"`
	Taxonomies         []sarifToolComponent             `json:"taxonomies,omitempty"`
	Results            []sarifResult                    `json:"results"`
	Properties         map[string]any                   `json:"properties,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string         `json:"name"`
	Version        string         `json:"version"`
	InformationURI string         `json:"informationUri"`
	Rules          []sarifRule    `json:"rules"`
	Properties     map[string]any `json:"properties,omitempty"`
}

type sarifToolComponent struct {
	Name           string       `json:"name"`
	Organization   string       `json:"organization,omitempty"`
	InformationURI string       `json:"informationUri,omitempty"`
	ShortDesc      sarifMessage `json:"shortDescription"`
	Taxa           []sarifTaxon `json:"taxa"`
}

type sarifTaxon struct {
	ID      string `json:"id"`
	HelpURI string `json:"helpUri,omitempty"`
}

type sarifRule struct {
	ID               string              `json:"id"`
	Name             string              `json:"name"`
	ShortDescription sarifMessage        `json:"shortDescription"`
	FullDescription  *sarifMessage       `json:"fullDescription,omitempty"`
	Help             *sarifHelp          `json:"help,omitempty"`
	HelpURI          string              `json:"helpUri,omitempty"`
	DefaultConfig    sarifDefaultConfig  `json:"defaultConfiguration"`
	Relationships    []sarifRelationship `json:"relationships,omitempty"`
	Properties       sarifRuleProperties `json:"properties"`
}

type sarifRelationship struct {
	Target sarifDescriptorRef `json:"target"`
	Kinds  []string           `json:"kinds"`
}

type sarifDescriptorRef struct {
	ID            string                `json:"id"`
	Index         int                   `json:"index"`
	ToolComponent *sarifToolComponentID `json:"toolComponent,omitempty"`
}

type sarifToolComponentID struct {
	Name  string `json:"name"`
	Index int    `json:"index"`
}

type sarifDefaultConfig struct {
	Level string `json:"level"`
}

type sarifRuleProperties struct {
	Tags             []string `json:"tags,omitempty"`
	SecuritySeverity string   `json:"security-severity,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifHelp struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

type sarifAutomationDetails struct {
	ID string `json:"id"`
}

type sarifInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	ExitCode                   *int                `json:"exitCode,omitempty"`
	ExitCodeDescription        string              `json:"exitCodeDescription,omitempty"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications"`
	Properties                 map[string]any      `json:"properties,omitempty"`
}

type sarifNotification struct {
	Level      string                 `json:"level"`
	Message    sarifMessage           `json:"message"`
	Descriptor *sarifNotificationRule `json:"associatedRule,omitempty"`
	Locations  []sarifLocation        `json:"locations,omitempty"`
}

type sarifNotificationRule struct {
	ID string `json:"id"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	BaselineState       string            `json:"baselineState,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI         string        `json:"uri,omitempty"`
	URIBaseID   string        `json:"uriBaseId,omitempty"`
	Description *sarifMessage `json:"description,omitempty"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
}

func (f *SARIFFormatter) Format(w io.Writer, result *scanner.ScanResult) error {
	return WriteSARIF(w, result, nil, f.Options)
}

// WriteSARIF writes one SARIF run holding the external results followed by
// the content findings of scan (which may be nil), with rules in order of
// first use. One run per file keeps GitHub from rejecting the upload for
// repeating a tool and category.
func WriteSARIF(w io.Writer, scan *scanner.ScanResult, external []SARIFExternalResult, opts SARIFOptions) error {
	b := newSARIFBuilder(opts)
	for _, ext := range external {
		b.addExternal(ext)
	}
	if scan != nil {
		for _, finding := range scan.Findings {
			b.addFinding(finding)
		}
	}

	props := map[string]any{}
	if scan != nil {
		props["duration_ms"] = scan.Duration.Milliseconds()
		props["riskScore"] = types.RoundScore(scan.RiskScore)
		props["files_scanned"] = scan.FilesScanned
		props["verdict"] = scan.Verdict
		props["verdict_label"] = scan.Verdict.String()
		if scan.Suppressed != nil {
			props["suppressed"] = scan.Suppressed
		}
		if scan.Baseline != nil {
			props["baseline"] = scan.Baseline
		}
	}
	for k, v := range opts.Properties {
		props[k] = v
	}

	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name:           "aguara",
			Version:        ToolVersion,
			InformationURI: "https://github.com/garagon/aguara",
			Rules:          b.rules,
			Properties:     b.driverProperties(),
		}},
		Invocations: []sarifInvocation{b.invocation()},
		Results:     b.results,
		Taxonomies:  b.taxonomies(),
	}
	if len(props) > 0 {
		run.Properties = props
	}
	if cat := strings.TrimSpace(opts.Category); cat != "" {
		if !strings.HasSuffix(cat, "/") {
			cat += "/"
		}
		run.AutomationDetails = &sarifAutomationDetails{ID: cat}
	}
	if opts.InWorkTree {
		run.OriginalURIBaseIDs = map[string]sarifArtifactLocation{
			SourceRootBaseID: {Description: &sarifMessage{Text: "The root of the git work tree that contains the scan target. Artifact URIs are relative to it."}},
		}
	}

	log := sarifLog{
		Schema:  sarifSchemaURI,
		Version: "2.1.0",
		Runs:    []sarifRun{run},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

type sarifBuilder struct {
	opts      SARIFOptions
	ruleIndex map[string]int
	rules     []sarifRule
	results   []sarifResult
	cwes      []string
	cweIndex  map[string]int
}

func newSARIFBuilder(opts SARIFOptions) *sarifBuilder {
	return &sarifBuilder{
		opts:      opts,
		ruleIndex: map[string]int{},
		rules:     []sarifRule{},
		results:   []sarifResult{},
		cweIndex:  map[string]int{},
	}
}

// ruleDoc is what a rule descriptor is built from.
type ruleDoc struct {
	id, name, category, description, remediation, helpURI string
	cwe                                                   []string
	severity                                              types.Severity
	// explainable is true for catalog rules, which `aguara explain`
	// documents.
	explainable bool
}

func (b *sarifBuilder) ensureRule(doc ruleDoc) int {
	if idx, ok := b.ruleIndex[doc.id]; ok {
		return idx
	}
	idx := len(b.rules)
	b.ruleIndex[doc.id] = idx

	tags := []string{doc.category, "security"}
	var relationships []sarifRelationship
	for _, cwe := range doc.cwe {
		number := strings.TrimPrefix(cwe, "CWE-")
		tags = append(tags, "external/cwe/cwe-"+number)
		relationships = append(relationships, sarifRelationship{
			Target: sarifDescriptorRef{
				ID:            number,
				Index:         b.cweTaxon(number),
				ToolComponent: &sarifToolComponentID{Name: cweTaxonomyName, Index: 0},
			},
			Kinds: []string{"relevant"},
		})
	}

	rule := sarifRule{
		ID:               doc.id,
		Name:             doc.name,
		ShortDescription: sarifMessage{Text: doc.name},
		HelpURI:          doc.helpURI,
		DefaultConfig:    sarifDefaultConfig{Level: severityToLevel(doc.severity)},
		Relationships:    relationships,
		Properties: sarifRuleProperties{
			Tags:             tags,
			SecuritySeverity: SecuritySeverity(doc.severity),
		},
	}
	full := doc.description
	if full == "" {
		full = doc.name
	}
	rule.FullDescription = &sarifMessage{Text: full}
	rule.Help = &sarifHelp{Text: helpText(doc), Markdown: helpMarkdown(doc)}
	b.rules = append(b.rules, rule)
	return idx
}

// cweTaxon returns the index of the CWE taxon, adding it on first use.
func (b *sarifBuilder) cweTaxon(number string) int {
	if idx, ok := b.cweIndex[number]; ok {
		return idx
	}
	b.cweIndex[number] = len(b.cwes)
	b.cwes = append(b.cwes, number)
	return b.cweIndex[number]
}

func (b *sarifBuilder) taxonomies() []sarifToolComponent {
	if len(b.cwes) == 0 {
		return nil
	}
	taxa := make([]sarifTaxon, 0, len(b.cwes))
	for _, number := range b.cwes {
		taxa = append(taxa, sarifTaxon{ID: number, HelpURI: "https://cwe.mitre.org/data/definitions/" + number + ".html"})
	}
	return []sarifToolComponent{{
		Name:           cweTaxonomyName,
		Organization:   "MITRE",
		InformationURI: "https://cwe.mitre.org/",
		ShortDesc:      sarifMessage{Text: "The MITRE Common Weakness Enumeration"},
		Taxa:           taxa,
	}}
}

func (b *sarifBuilder) helpURIFor(id string) string {
	if b.opts.BuiltinRules != nil {
		if b.opts.BuiltinRules[id] {
			return RuleCatalogURI
		}
		return ""
	}
	if _, ok := b.opts.Catalog[id]; ok {
		return RuleCatalogURI
	}
	return ""
}

func (b *sarifBuilder) addFinding(finding scanner.Finding) {
	doc := ruleDoc{
		id:          finding.RuleID,
		name:        finding.RuleName,
		category:    finding.Category,
		description: finding.Description,
		remediation: finding.Remediation,
		helpURI:     b.helpURIFor(finding.RuleID),
		// The first finding of a rule is its most severe one: findings
		// arrive sorted by severity, highest first.
		severity:    finding.Severity,
		explainable: true,
	}
	if meta, ok := b.opts.Catalog[finding.RuleID]; ok {
		if meta.Description != "" {
			doc.description = meta.Description
		}
		if meta.Remediation != "" {
			doc.remediation = meta.Remediation
		}
		if doc.name == "" {
			doc.name = meta.Name
		}
		doc.cwe = meta.CWE
	}
	idx := b.ensureRule(doc)

	r := sarifResult{
		RuleID:    finding.RuleID,
		RuleIndex: idx,
		Level:     severityToLevel(finding.Severity),
		Message:   sarifMessage{Text: finding.RuleName + ": " + finding.MatchedText},
		Locations: []sarifLocation{b.location(b.contentURI(finding.FilePath), finding.Line, finding.Column)},
	}
	// Emit a stable fingerprint for baselineable findings so
	// GitHub code-scanning (and external baseline tooling) can
	// de-dupe across runs. Sensitive / credential-leak findings are
	// non-baselineable and intentionally carry no fingerprint. The
	// fingerprint uses the finding's own path, not the artifact URI, so
	// it matches baseline files whatever the URI base.
	if baseline.Baselineable(finding) {
		r.PartialFingerprints = map[string]string{
			baseline.FingerprintKey: string(baseline.ComputeFingerprint(finding)),
		}
	}
	switch finding.BaselineState {
	case baseline.StateBaselined:
		r.BaselineState = "unchanged"
	case baseline.StateNew, baseline.StateNonBaselineable:
		r.BaselineState = "new"
	}
	props := map[string]any{"severity": finding.Severity.String()}
	if finding.InCodeBlock {
		props["in_code_block"] = true
	}
	if finding.Confidence > 0 {
		props["confidence"] = types.RoundConfidence(finding.Confidence)
		// SARIF rank convention: 0-100 scale
		props["rank"] = types.RoundScore(finding.Confidence * 100)
	}
	if len(finding.AlsoMatched) > 0 {
		props["also_matched"] = finding.AlsoMatched
	}
	if finding.BaselineState != "" {
		props["baseline_state"] = finding.BaselineState
	}
	r.Properties = props
	b.results = append(b.results, r)
}

func (b *sarifBuilder) addExternal(ext SARIFExternalResult) {
	idx := b.ensureRule(ruleDoc{
		id:          ext.RuleID,
		name:        ext.RuleName,
		category:    ext.Category,
		description: ext.RuleDescription,
		remediation: ext.Remediation,
		helpURI:     ext.HelpURI,
		cwe:         ext.CWE,
		severity:    ext.Severity,
	})
	r := sarifResult{
		RuleID:    ext.RuleID,
		RuleIndex: idx,
		Level:     severityToLevel(ext.Severity),
		Message:   sarifMessage{Text: ext.Message},
		Locations: []sarifLocation{b.location(ext.URI, ext.Line, 0)},
	}
	if ext.Fingerprint != "" {
		key := ext.FingerprintKey
		if key == "" {
			key = baseline.FingerprintKey
		}
		r.PartialFingerprints = map[string]string{key: ext.Fingerprint}
	}
	props := map[string]any{"severity": ext.Severity.String()}
	for k, v := range ext.Properties {
		props[k] = v
	}
	r.Properties = props
	b.results = append(b.results, r)
}

// contentURI is the artifact URI of a content finding path.
func (b *sarifBuilder) contentURI(p string) string {
	p = filepath.ToSlash(p)
	if b.opts.URIPrefix == "" {
		return p
	}
	return path.Join(b.opts.URIPrefix, p)
}

func (b *sarifBuilder) location(uri string, line, column int) sarifLocation {
	loc := sarifLocation{PhysicalLocation: sarifPhysicalLocation{
		ArtifactLocation: sarifArtifactLocation{URI: uri},
	}}
	if b.opts.InWorkTree {
		loc.PhysicalLocation.ArtifactLocation.URIBaseID = SourceRootBaseID
	}
	// A region needs a line; a column is reported only when the finding
	// has one, never invented.
	region := &sarifRegion{StartLine: max(line, 1)}
	if column > 0 {
		region.StartColumn = column
	}
	loc.PhysicalLocation.Region = region
	return loc
}

func (b *sarifBuilder) driverProperties() map[string]any {
	props := map[string]any{}
	if b.opts.Commit != "" {
		props["commit"] = b.opts.Commit
	}
	if b.opts.CatalogDigest != nil {
		props["catalog"] = b.opts.CatalogDigest
	}
	if len(props) == 0 {
		return nil
	}
	return props
}

func (b *sarifBuilder) invocation() sarifInvocation {
	inv := sarifInvocation{
		ExecutionSuccessful:        true,
		ToolExecutionNotifications: []sarifNotification{},
		Properties:                 map[string]any{"exit_code_meanings": sarifExitCodeMeanings},
	}
	in := b.opts.Invocation
	if in == nil {
		return inv
	}
	inv.ExecutionSuccessful = in.ExecutionSuccessful
	if in.ExitCode >= 0 {
		code := in.ExitCode
		inv.ExitCode = &code
	}
	inv.ExitCodeDescription = in.ExitCodeDescription
	for _, n := range in.Notifications {
		level := n.Level
		if level == "" {
			level = "warning"
		}
		sn := sarifNotification{Level: level, Message: sarifMessage{Text: n.Message}}
		if n.RuleID != "" {
			sn.Descriptor = &sarifNotificationRule{ID: n.RuleID}
		}
		if n.URI != "" {
			sn.Locations = []sarifLocation{b.location(n.URI, n.Line, 0)}
		}
		inv.ToolExecutionNotifications = append(inv.ToolExecutionNotifications, sn)
	}
	return inv
}

// helpText is help.text: the rule's description and remediation as plain
// text.
func helpText(doc ruleDoc) string {
	var parts []string
	if doc.description != "" {
		parts = append(parts, doc.description)
	}
	if doc.remediation != "" {
		parts = append(parts, "Remediation: "+doc.remediation)
	}
	if len(parts) == 0 {
		return doc.name
	}
	return strings.Join(parts, "\n\n")
}

// helpMarkdown is help.markdown: description, remediation, CWE links and
// where to read more.
func helpMarkdown(doc ruleDoc) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "**%s** (`%s`, %s, %s)\n\n", doc.name, doc.id, doc.severity.String(), doc.category)
	if doc.description != "" {
		sb.WriteString(doc.description + "\n\n")
	}
	if doc.remediation != "" {
		sb.WriteString("**Remediation:** " + doc.remediation + "\n\n")
	}
	if len(doc.cwe) > 0 {
		links := make([]string, 0, len(doc.cwe))
		for _, cwe := range doc.cwe {
			links = append(links, fmt.Sprintf("[%s](https://cwe.mitre.org/data/definitions/%s.html)", cwe, strings.TrimPrefix(cwe, "CWE-")))
		}
		sb.WriteString("**Weakness:** " + strings.Join(links, ", ") + "\n\n")
	}
	switch {
	case doc.explainable && doc.helpURI != "":
		fmt.Fprintf(&sb, "Run `aguara explain %s` for the rule's details, or see the [rule catalog](%s).", doc.id, doc.helpURI)
	case doc.explainable:
		fmt.Fprintf(&sb, "Run `aguara explain %s` for the rule's details.", doc.id)
	case doc.helpURI != "":
		fmt.Fprintf(&sb, "See the [documentation](%s).", doc.helpURI)
	}
	return strings.TrimRight(sb.String(), "\n")
}

func severityToLevel(sev scanner.Severity) string {
	switch sev {
	case scanner.SeverityCritical:
		return "error"
	case scanner.SeverityHigh:
		return "warning"
	case scanner.SeverityMedium, scanner.SeverityLow:
		return "note"
	case scanner.SeverityInfo:
		return "none"
	default:
		return "none"
	}
}
