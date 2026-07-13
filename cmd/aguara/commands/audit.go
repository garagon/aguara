package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/garagon/aguara/internal/baseline"
	"github.com/garagon/aguara/internal/incident"
	"github.com/garagon/aguara/internal/output"
	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/types"
	"github.com/spf13/cobra"
)

var (
	flagAuditPath          string
	flagAuditCI            bool
	flagAuditFailOn        string
	flagAuditFresh         bool
	flagAuditAllowStale    bool
	flagAuditBaseline      string
	flagAuditWriteBaseline string
	flagAuditInsecure      bool
	flagAuditVerbose       bool
)

var auditCmd = &cobra.Command{
	Use:     "audit [path]",
	GroupID: groupScan,
	Short:   "Run scan + check together and produce a single verdict",
	Example: `  aguara audit .               Package check + content scan, one verdict
  aguara audit . --ci          CI gate: exit 1 on critical, no color
  aguara audit . --verbose     List every content finding (no cap)
  aguara audit . --fresh       Refresh threat intel first (network opt-in)`,
	Long: `Audit a project: run the supply-chain check (compromised packages /
persistence artifacts) and the content scan (rule-based detection of
prompt injection, credential leaks, etc.) together, and report a
single combined verdict.

Default audits stay offline -- they use the same embedded threat intel
the standalone 'aguara check' uses. Pass --fresh to refresh from Aguara's
signed advisory bundle (verified before use) before the audit. Pass --ci
to fail-on critical with no color (the default for unattended CI runs).`,
	Args: cobra.MaximumNArgs(1),
	RunE: runAudit,
}

func init() {
	auditCmd.Flags().StringVar(&flagAuditPath, "path", "", "Path to audit (also accepted as a positional argument; defaults to '.')")
	auditCmd.Flags().BoolVar(&flagAuditCI, "ci", false, "CI mode: --fail-on critical, no color")
	auditCmd.Flags().StringVar(&flagAuditFailOn, "fail-on", "", "Exit code 1 when findings reach this severity (critical, warning, info)")
	auditCmd.Flags().BoolVar(&flagAuditFresh, "fresh", false, "Refresh threat intel from Aguara's signed advisory bundle before the audit (network opt-in)")
	auditCmd.Flags().BoolVar(&flagAuditInsecure, "insecure-intel", false, "Skip advisory-bundle signature verification (also requires AGUARA_INSECURE_INTEL=1; mirrors / air-gapped / tests only; manifest + blob digests are still checked)")
	auditCmd.Flags().BoolVar(&flagAuditAllowStale, "allow-stale", false, "If --fresh fails, fall back to previously verified local intel (errors if none is cached)")
	auditCmd.Flags().StringVar(&flagAuditBaseline, "baseline", "", "Gate scan findings only on those NOT in this baseline file (package findings always gate; fails closed if missing/malformed)")
	auditCmd.Flags().StringVar(&flagAuditWriteBaseline, "write-baseline", "", "Write the scan findings as a baseline to this file (skips sensitive findings); package findings still gate")
	auditCmd.Flags().BoolVar(&flagAuditVerbose, "verbose", false, "List every content finding instead of capping at 10")
	// Runtime errors (ErrThresholdExceeded after the verdict
	// computes "fail", --fresh network failures) should not
	// trigger Cobra's flag-usage block. The verdict line plus the
	// JSON sub-results are already enough to act on; printing
	// --help on top of those makes the CI log read as command
	// misuse. See scan.go for the same rationale.
	auditCmd.SilenceUsage = true
	rootCmd.AddCommand(auditCmd)
}

// AuditResult is the combined output of `aguara audit`. Both
// sub-results retain their full shape so JSON consumers can drill
// into either side; the verdict + summary fields are convenience
// for terminal output and CI gates.
type AuditResult struct {
	Target  string                `json:"target"`
	Check   *incident.CheckResult `json:"check"`
	Scan    *scanner.ScanResult   `json:"scan"`
	Verdict AuditVerdict          `json:"verdict"`
	Triage  AuditTriage           `json:"triage"`
	Handoff AuditAgentHandoff     `json:"agent_handoff"`
	Plan    AuditActionPlan       `json:"action_plan"`
	Intel   incident.IntelSummary `json:"intel"`
}

// AuditVerdict is the single-line summary the CLI prints under
// the two sub-result sections.
type AuditVerdict struct {
	Status            string `json:"status"` // "pass" | "fail"
	CheckCriticals    int    `json:"check_criticals"`
	CheckWarnings     int    `json:"check_warnings"`
	CheckInfos        int    `json:"check_infos"`
	ScanCriticals     int    `json:"scan_criticals"`
	ScanHighs         int    `json:"scan_highs"`
	ScanMediums       int    `json:"scan_mediums"`
	ScanLows          int    `json:"scan_lows"`
	ScanInfos         int    `json:"scan_infos"`
	ThresholdExceeded bool   `json:"threshold_exceeded"`
}

// AuditTriage translates the raw findings and CI gate into a product-level
// decision a human reviewer or agent workflow can act on. It is additive JSON:
// exit codes, verdict.status, and threshold_exceeded remain the compatibility
// contract for machines that already consume audit output.
type AuditTriage struct {
	Decision             string              `json:"decision"` // "proceed" | "review" | "stop"
	Summary              string              `json:"summary"`
	Reasons              []AuditTriageReason `json:"reasons"`
	RecommendedNextSteps []string            `json:"recommended_next_steps"`
}

type AuditTriageReason struct {
	Kind     string `json:"kind"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// AuditAgentHandoff translates the triage decision into guidance for AI coding
// agents and other automation that might otherwise install, test, build, or run
// project-defined commands immediately after cloning a repository.
type AuditAgentHandoff struct {
	Status         string   `json:"status"` // "allowed" | "review_only" | "blocked"
	Summary        string   `json:"summary"`
	AllowedActions []string `json:"allowed_actions"`
	BlockedActions []string `json:"blocked_actions"`
}

// AuditActionPlan is a compact machine-readable contract for agents and
// wrappers that need booleans instead of prose before they decide whether to
// install dependencies, run tests, execute CI, or only inspect the repository.
type AuditActionPlan struct {
	TrustState             string   `json:"trust_state"` // "allowed" | "review_only" | "blocked"
	CanInstallDependencies bool     `json:"can_install_dependencies"`
	CanExecuteProjectCode  bool     `json:"can_execute_project_code"`
	CanRunCI               bool     `json:"can_run_ci"`
	CanUseRepoAgentConfig  bool     `json:"can_use_repo_agent_config"`
	CanEditFiles           bool     `json:"can_edit_files"`
	CanExplainFindings     bool     `json:"can_explain_findings"`
	Priority               []string `json:"priority"`
	NextCommands           []string `json:"next_commands"`
}

func runAudit(cmd *cobra.Command, args []string) error {
	if flagAuditBaseline != "" && flagAuditWriteBaseline != "" {
		return fmt.Errorf("--baseline and --write-baseline are mutually exclusive")
	}
	applyAuditCIDefaults()

	target := flagAuditPath
	if target == "" && len(args) == 1 {
		target = args[0]
	}
	if target == "" {
		target = "."
	}

	// audit's --fresh / --allow-stale flags mirror onto the
	// check-side globals so resolveCheckIntel reads the right
	// intent. Restoring them on exit keeps the two surfaces from
	// leaking state across commands in long-lived test runs.
	prevFresh, prevAllowStale, prevInsecure := flagCheckFresh, flagCheckAllowStale, flagCheckInsecure
	flagCheckFresh, flagCheckAllowStale, flagCheckInsecure = flagAuditFresh, flagAuditAllowStale, flagAuditInsecure
	defer func() {
		flagCheckFresh, flagCheckAllowStale, flagCheckInsecure = prevFresh, prevAllowStale, prevInsecure
	}()

	// 1. Build the same check plan `aguara check` would build
	// for `target`. audit reuses buildCheckPlan + runCheckPlan
	// so a Go / Rust / .NET monorepo audit reports the same
	// `check.ecosystems` slice as a standalone `aguara check`
	// against the same path.
	plan, err := buildCheckPlan(nil, target)
	if err != nil {
		return err
	}
	intelOverride, err := resolveCheckIntel(cmd.Context(), plan.intelEcosystems())
	if err != nil {
		return err
	}
	checkResult, err := runCheckPlan(plan, intelOverride)
	if err != nil {
		return fmt.Errorf("audit: check phase: %w", err)
	}
	// Set age/stale once on the check result; the AuditResult copies this
	// IntelSummary and the nested Check pointer shares it, so JSON and
	// terminal stay consistent.
	applyIntelFreshness(&checkResult.Intel, time.Now().UTC())

	// 2. Run the content scan.
	scanResult, err := auditRunScan(cmd, target)
	if err != nil {
		return fmt.Errorf("audit: scan phase: %w", err)
	}

	// 3. Compose result + verdict.
	result := &AuditResult{
		Target: target,
		Check:  checkResult,
		Scan:   scanResult,
		Intel:  checkResult.Intel,
	}

	// Baseline applies to the SCAN side only; package (check) findings
	// always gate exactly as today. Output keeps every scan finding (3A)
	// plus a baseline summary; the verdict tallies only the post-baseline
	// scan gate set, so we swap the scan findings for the verdict
	// computation and restore the full list before emitting.
	scanGate := scanResult.Findings
	switch {
	case flagAuditWriteBaseline != "":
		written, skipped, err := baseline.Write(flagAuditWriteBaseline, scanResult.Findings, Version)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "baseline: wrote %d fingerprint(s) to %s", written, flagAuditWriteBaseline)
		if skipped > 0 {
			fmt.Fprintf(os.Stderr, "; %d sensitive finding(s) skipped (remain non-baselineable)", skipped)
		}
		fmt.Fprintln(os.Stderr)
		// Establishing a scan baseline accepts all current scan findings,
		// so the scan side contributes nothing to the gate. The check
		// side still gates: package findings are never baselineable.
		scanGate = nil
	case flagAuditBaseline != "":
		set, err := baseline.Load(flagAuditBaseline)
		if err != nil {
			return err
		}
		var summary types.BaselineSummary
		scanGate, summary = baseline.Apply(scanResult.Findings, set, flagAuditBaseline)
		scanResult.Baseline = &summary
	}

	fullScan := scanResult.Findings
	scanResult.Findings = scanGate
	verdict, vErr := computeAuditVerdict(result, flagAuditFailOn)
	scanResult.Findings = fullScan
	if vErr != nil {
		// An invalid --fail-on value must error rather than
		// silently disable the gate. scan / check both do the
		// same; audit must not be the one path where a typo
		// (--fail-on critcal) ships green.
		return vErr
	}
	result.Verdict = verdict
	result.Triage = computeAuditTriage(result)
	result.Handoff = computeAuditAgentHandoff(result.Triage)
	result.Plan = computeAuditActionPlan(result)

	// 4. Emit.
	if flagFormat == "json" {
		if err := writeAuditJSON(result); err != nil {
			return err
		}
	} else {
		if err := writeAuditTerminal(result); err != nil {
			return err
		}
	}

	if result.Verdict.ThresholdExceeded {
		return ErrThresholdExceeded
	}
	return nil
}

// applyAuditCIDefaults mirrors check / scan: --ci implies
// --fail-on critical (unless the user set --fail-on explicitly)
// and disables color. NO_COLOR also disables color so the flag
// interacts cleanly with CI runners that set it by convention.
func applyAuditCIDefaults() {
	if flagAuditCI {
		if flagAuditFailOn == "" {
			flagAuditFailOn = "critical"
		}
		flagNoColor = true
	}
	if os.Getenv("NO_COLOR") != "" {
		flagNoColor = true
	}
}

// auditRunScan invokes the scanner against the target path using
// the same helpers runScan uses. Kept as a thin shim so the audit
// command does not duplicate scanner-construction logic; if the
// scan pipeline grows new flags, audit picks them up automatically.
//
// Note we do NOT honour --severity for audit: the audit's job is
// to be a strict gate, so we always run with SeverityInfo and let
// the verdict / --fail-on threshold filter what matters.
func auditRunScan(cmd *cobra.Command, targetPath string) (*scanner.ScanResult, error) {
	cfg := loadScanConfig(cmd, targetPath)

	// .aguara.yml `baseline:` feeds audit's --baseline when unset and we
	// are not establishing a new baseline.
	if cfg.Baseline != "" && !cmd.Flags().Changed("baseline") && flagAuditWriteBaseline == "" {
		flagAuditBaseline = cfg.Baseline
	}

	compiled, err := loadAndCompileRules(cfg)
	if err != nil {
		return nil, err
	}

	s, store := buildScanner(compiled, cfg, scanner.SeverityInfo)
	sp := startSpinnerIfTerminal(s, "Auditing content...")

	ctx, cancel := contextWithInterrupt()
	defer cancel()

	result, err := executeScan(ctx, s, targetPath)
	stopSpinner(sp)
	if err != nil {
		return nil, err
	}
	result.RulesLoaded = len(compiled)
	result.Target = targetPath

	if store != nil {
		if err := store.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: saving state: %v\n", err)
		}
	}

	if !flagNoRedact {
		types.RedactSensitiveFindings(result.Findings)
	}
	return result, nil
}

// computeAuditVerdict tallies per-section severities and decides
// whether the --fail-on threshold trips. The threshold mapping
// between audit's vocabulary (critical / warning / info) and
// scan's numeric Severity is intentionally simple:
//
//	critical -> check critical, scan critical
//	warning  -> check warning,  scan high
//	info     -> check info,     scan info
//
// A finer-grained mapping (e.g. warning matches medium) would
// surprise users who expect "warning" to mean "the loudest of the
// non-critical buckets" in both vocabularies. The simple mapping
// also means a single --fail-on flag is unambiguous in CI logs.
func computeAuditVerdict(result *AuditResult, threshold string) (AuditVerdict, error) {
	v := AuditVerdict{Status: "pass"}

	for _, f := range result.Check.Findings {
		switch strings.ToUpper(f.Severity) {
		case incident.SevCritical:
			v.CheckCriticals++
		case incident.SevWarning:
			v.CheckWarnings++
		case incident.SevInfo:
			v.CheckInfos++
		}
	}
	for _, f := range result.Scan.Findings {
		switch f.Severity {
		case scanner.SeverityCritical:
			v.ScanCriticals++
		case scanner.SeverityHigh:
			v.ScanHighs++
		case scanner.SeverityMedium:
			v.ScanMediums++
		case scanner.SeverityLow:
			v.ScanLows++
		case scanner.SeverityInfo:
			v.ScanInfos++
		}
	}

	// Tri-state Status (#110). Previously the verdict was binary
	// pass / fail, which collapsed "no findings at all" and
	// "findings exist but no gate is enforced" into the same
	// "pass" output. Dashboards that read only `verdict.status`
	// would see green even when `check_criticals > 0`.
	//
	// The states now are:
	//   pass     -> zero findings on either side
	//   findings -> at least one finding, but the gate (--ci /
	//               --fail-on) was either not set or not crossed.
	//               exit code stays 0 so default `aguara audit` runs
	//               do not surprise users with non-zero exits.
	//   fail     -> gate was set and the threshold was crossed.
	//               exit code is non-zero via ErrThresholdExceeded.
	//
	// The threshold logic below upgrades "findings" to "fail" when
	// the gate trips; the exit-code path is unchanged so existing
	// CI integrations that read ThresholdExceeded keep behaving.
	totalFindings := v.CheckCriticals + v.CheckWarnings + v.CheckInfos +
		v.ScanCriticals + v.ScanHighs + v.ScanMediums + v.ScanLows + v.ScanInfos
	if totalFindings > 0 {
		v.Status = "findings"
	}

	if threshold == "" {
		return v, nil
	}
	switch strings.ToUpper(strings.TrimSpace(threshold)) {
	case "CRITICAL":
		if v.CheckCriticals > 0 || v.ScanCriticals > 0 {
			v.ThresholdExceeded = true
		}
	case "WARNING":
		if v.CheckCriticals > 0 || v.CheckWarnings > 0 ||
			v.ScanCriticals > 0 || v.ScanHighs > 0 {
			v.ThresholdExceeded = true
		}
	case "INFO":
		// Any finding at all trips the gate, including INFO
		// on either side. The earlier shape silently dropped
		// INFO findings, so a custom INFO-only rule could
		// have passed `--fail-on info` cleanly. That broke the
		// "lowest threshold" contract; the explicit InfoCount
		// fields above feed this gate now.
		if v.CheckCriticals+v.CheckWarnings+v.CheckInfos > 0 ||
			v.ScanCriticals+v.ScanHighs+v.ScanMediums+v.ScanLows+v.ScanInfos > 0 {
			v.ThresholdExceeded = true
		}
	default:
		return v, fmt.Errorf("invalid --fail-on %q: choose critical, warning, or info", threshold)
	}
	if v.ThresholdExceeded {
		v.Status = "fail"
	}
	return v, nil
}

func computeAuditTriage(result *AuditResult) AuditTriage {
	t := AuditTriage{
		Decision: "proceed",
		Summary:  "No package or content findings require review before proceeding.",
		RecommendedNextSteps: []string{
			"Proceed with normal review, install, CI, or agent handoff.",
		},
	}
	if result == nil || result.Check == nil || result.Scan == nil {
		return t
	}

	addReason := func(kind, severity, message string) {
		t.Reasons = append(t.Reasons, AuditTriageReason{
			Kind:     kind,
			Severity: severity,
			Message:  message,
		})
	}

	if result.Verdict.ThresholdExceeded {
		addReason("gate_exceeded", "critical", "The configured audit gate was crossed.")
	}
	if result.Verdict.CheckCriticals > 0 {
		addReason("known_malicious_package", "critical", "A package in the resolved dependency evidence is known malicious.")
	}
	if result.Verdict.ScanCriticals > 0 {
		addReason("critical_content_finding", "critical", "Critical content findings are present in files this repository asks you to trust.")
	}
	if result.Scan.Baseline != nil && result.Scan.Baseline.Applied {
		s := result.Scan.Baseline
		switch {
		case s.GateCount > 0:
			addReason("baseline_new_findings", "warning", "A baseline was applied, but new or non-baselineable scan findings still remain.")
		case s.Baselined > 0:
			addReason("baseline_existing_findings", "info", "Existing scan findings were kept visible but did not gate this run because they are in the baseline.")
		}
	}

	switch {
	case hasCriticalTriageReason(t.Reasons):
		t.Decision = "stop"
		t.Summary = "Do not install, execute CI, or hand this repository to an agent until the critical findings are resolved."
		t.RecommendedNextSteps = []string{
			"Do not run package install scripts or project automation yet.",
			"Review the critical package and content findings first.",
			"Remove or replace known-malicious packages and inspect flagged trust surfaces.",
		}
	case hasAnyFindings(result):
		t.Decision = "review"
		t.Summary = "Findings are present; review them before installing, running CI, or handing this repository to an agent."
		t.RecommendedNextSteps = []string{
			"Review the findings and remediation guidance.",
			"Use aguara explain <rule> for the highest-impact content finding.",
			"Proceed only after the trust decision is understood.",
		}
		if len(t.Reasons) == 0 {
			addReason("findings_present", "warning", "Package or content findings are present below the stop threshold.")
		}
	}

	return t
}

func hasCriticalTriageReason(reasons []AuditTriageReason) bool {
	for _, r := range reasons {
		if strings.EqualFold(r.Severity, "critical") {
			return true
		}
	}
	return false
}

func hasAnyFindings(result *AuditResult) bool {
	return len(result.Check.Findings) > 0 || len(result.Scan.Findings) > 0
}

func computeAuditAgentHandoff(triage AuditTriage) AuditAgentHandoff {
	switch triage.Decision {
	case "stop":
		return AuditAgentHandoff{
			Status:  "blocked",
			Summary: "Do not hand this repository to an agent for execution yet.",
			AllowedActions: []string{
				"Inspect files and lockfiles.",
				"Explain Aguara findings.",
				"Propose remediation patches.",
			},
			BlockedActions: []string{
				"Do not run package install scripts.",
				"Do not run build, test, CI, or project automation.",
				"Do not execute project-defined agent hooks or tools.",
			},
		}
	case "review":
		return AuditAgentHandoff{
			Status:  "review_only",
			Summary: "Limit agent work to inspection and remediation until findings are reviewed.",
			AllowedActions: []string{
				"Inspect source, lockfiles, configs, and findings.",
				"Explain risk and propose patches.",
				"Edit files only when a reviewer approves the trust decision.",
			},
			BlockedActions: []string{
				"Do not run install, build, test, or project automation until review is complete.",
				"Do not accept agent or MCP configuration from this repository as trusted yet.",
			},
		}
	default:
		return AuditAgentHandoff{
			Status:  "allowed",
			Summary: "No audit finding requires limiting agent handoff.",
			AllowedActions: []string{
				"Proceed with normal agent workflow under the repository owner's policy.",
			},
		}
	}
}

func computeAuditActionPlan(result *AuditResult) AuditActionPlan {
	plan := AuditActionPlan{
		TrustState:             "allowed",
		CanInstallDependencies: true,
		CanExecuteProjectCode:  true,
		CanRunCI:               true,
		CanUseRepoAgentConfig:  true,
		CanEditFiles:           true,
		CanExplainFindings:     true,
	}
	if result == nil {
		return plan
	}

	switch result.Handoff.Status {
	case "blocked":
		plan.TrustState = "blocked"
		plan.CanInstallDependencies = false
		plan.CanExecuteProjectCode = false
		plan.CanRunCI = false
		plan.CanUseRepoAgentConfig = false
	case "review_only":
		plan.TrustState = "review_only"
		plan.CanInstallDependencies = false
		plan.CanExecuteProjectCode = false
		plan.CanRunCI = false
		plan.CanUseRepoAgentConfig = false
	default:
		plan.TrustState = "allowed"
	}

	plan.Priority = auditActionPriority(result.Triage)
	plan.NextCommands = auditActionNextCommands(result)
	return plan
}

func auditActionPriority(triage AuditTriage) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range triage.Reasons {
		if seen[r.Kind] {
			continue
		}
		seen[r.Kind] = true
		out = append(out, r.Kind)
	}
	return out
}

func auditActionNextCommands(result *AuditResult) []string {
	if result == nil || result.Scan == nil {
		return nil
	}
	if rule := topScanRule(result.Scan.Findings); rule != "" {
		return []string{"aguara explain " + rule}
	}
	return nil
}

func writeAuditJSON(result *AuditResult) error {
	w := os.Stdout
	if flagOutput != "" {
		f, err := os.Create(flagOutput)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		w = f
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func writeAuditTerminal(result *AuditResult) error {
	st := output.NewStyle(flagNoColor)
	width := output.DetectWidth(os.Stdout)
	sep := st.Separator(width)

	fmt.Printf("\n%s\n", sep)
	fmt.Printf("  %s\n", st.Bold("AGUARA AUDIT"))
	fmt.Printf("  Target: %s\n", result.Target)
	fmt.Printf("%s\n", sep)

	fmt.Printf("\n%s\n", st.SectionHeader("PACKAGE CHECK", width))
	if len(result.Check.Findings) == 0 {
		fmt.Printf("\n  %s\n", st.OK("No known-compromised packages or persistence artifacts found."))
	} else {
		for _, f := range result.Check.Findings {
			label := string(f.Severity)
			fmt.Printf("\n  %s %s %s\n", st.SeverityIcon(label), st.SeverityLabel(fmt.Sprintf("%-8s", label)), f.Title)
			if f.Path != "" {
				fmt.Printf("             %s\n", st.Dim(f.Path))
			}
		}
	}

	fmt.Printf("\n%s\n", st.SectionHeader("CONTENT SCAN", width))
	if len(result.Scan.Findings) == 0 {
		fmt.Printf("\n  %s\n", st.OK("No content findings."))
	} else {
		// Cap the listing unless --verbose -- a noisy repo can dump
		// hundreds of low-severity findings into the audit output,
		// and showing all of them buries the verdict.
		const maxList = 10
		shown := 0
		fmt.Println()
		for _, f := range result.Scan.Findings {
			if !flagAuditVerbose && shown >= maxList {
				break
			}
			label := f.Severity.String()
			fmt.Printf("  %s %s %s %s\n",
				st.SeverityIcon(label),
				st.Bold(st.Cell(f.RuleID, 24)),
				st.Cell(f.RuleName, 36),
				st.Cyan(fmt.Sprintf("%s:%d", f.FilePath, f.Line)))
			shown++
		}
		if !flagAuditVerbose && len(result.Scan.Findings) > maxList {
			fmt.Printf("  %s\n", st.Dim(fmt.Sprintf("... +%d more (rerun with --verbose or use --format json)",
				len(result.Scan.Findings)-maxList)))
		}
	}

	// Provenance line, unified with `aguara check`. Suppressed under --ci
	// (stdout stays verdict + findings); a stale local cache still notes
	// to stderr inside printIntelFreshness.
	if !flagAuditCI {
		fmt.Println()
	}
	printIntelFreshness(result.Intel, flagAuditCI)

	// Green is reserved for a clean pass: FINDINGS exits 0 but still
	// means unresolved findings exist, so it renders yellow with the
	// medium-tier icon; FAIL is red with the critical icon.
	verdict := fmt.Sprintf("Verdict: %s", strings.ToUpper(result.Verdict.Status))
	counts := fmt.Sprintf("(check: %d critical / %d warning, scan: %d critical / %d high)",
		result.Verdict.CheckCriticals, result.Verdict.CheckWarnings,
		result.Verdict.ScanCriticals, result.Verdict.ScanHighs)
	var line string
	switch {
	case result.Verdict.ThresholdExceeded:
		line = st.SeverityIcon("CRITICAL") + " " + st.RedBold(verdict) + " " + counts
	case result.Verdict.Status == "findings":
		line = st.SeverityIcon("MEDIUM") + " " + st.Yellow(st.Bold(verdict)) + " " + counts
	default:
		line = st.Green(st.Bold("✔ "+verdict)) + " " + counts
	}

	fmt.Printf("\n%s\n  %s\n%s\n", sep, line, sep)

	if result.Triage.Decision != "" {
		var triageLine string
		switch result.Triage.Decision {
		case "stop":
			triageLine = st.SeverityIcon("CRITICAL") + " " + st.RedBold("Triage: STOP")
		case "review":
			triageLine = st.SeverityIcon("MEDIUM") + " " + st.Yellow(st.Bold("Triage: REVIEW"))
		default:
			triageLine = st.Green(st.Bold("✔ Triage: PROCEED"))
		}
		fmt.Printf("  %s\n", triageLine)
		if result.Triage.Summary != "" {
			fmt.Printf("  %s\n", st.Dim(result.Triage.Summary))
		}
		if len(result.Triage.RecommendedNextSteps) > 0 {
			fmt.Printf("  %s\n", st.Dim("Next: "+result.Triage.RecommendedNextSteps[0]))
		}
	}

	if result.Handoff.Status != "" {
		var handoffLine string
		switch result.Handoff.Status {
		case "blocked":
			handoffLine = st.SeverityIcon("CRITICAL") + " " + st.RedBold("Agent handoff: BLOCKED")
		case "review_only":
			handoffLine = st.SeverityIcon("MEDIUM") + " " + st.Yellow(st.Bold("Agent handoff: REVIEW ONLY"))
		default:
			handoffLine = st.Green(st.Bold("✔ Agent handoff: ALLOWED"))
		}
		fmt.Printf("  %s\n", handoffLine)
		if result.Handoff.Summary != "" {
			fmt.Printf("  %s\n", st.Dim(result.Handoff.Summary))
		}
		if len(result.Handoff.AllowedActions) > 0 {
			fmt.Printf("  %s\n", st.Dim("Allowed: "+result.Handoff.AllowedActions[0]))
		}
		if len(result.Handoff.BlockedActions) > 0 {
			fmt.Printf("  %s\n", st.Dim("Blocked: "+result.Handoff.BlockedActions[0]))
		}
	}

	if result.Plan.TrustState != "" {
		execStatus := "yes"
		installStatus := "yes"
		if !result.Plan.CanExecuteProjectCode {
			execStatus = "no"
		}
		if !result.Plan.CanInstallDependencies {
			installStatus = "no"
		}
		fmt.Printf("  %s\n", st.Dim(fmt.Sprintf("Action plan: install=%s execute=%s trust_state=%s",
			installStatus, execStatus, result.Plan.TrustState)))
	}

	if rule := topScanRule(result.Scan.Findings); rule != "" {
		fmt.Printf("  %s\n", st.Dim("Next: aguara explain "+rule))
	}
	return nil
}

// topScanRule returns the rule behind the most severe content finding,
// for the Next hint after the verdict.
func topScanRule(findings []scanner.Finding) string {
	best := -1
	rule := ""
	for _, f := range findings {
		if int(f.Severity) > best {
			best = int(f.Severity)
			rule = f.RuleID
		}
	}
	return rule
}
