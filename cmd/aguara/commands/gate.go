package commands

import (
	"errors"
	"fmt"
	"strings"

	"github.com/garagon/aguara/internal/incident"
	"github.com/garagon/aguara/internal/types"
)

// failOnChoices is the --fail-on vocabulary shared by scan, check and audit.
const failOnChoices = "critical, high, medium, low or info (warning is an alias of high)"

// Exit codes. main maps ErrThresholdExceeded (and gate errors wrapping it)
// to exitGate and every other error to exitError.
const (
	exitOK    = 0
	exitGate  = 1
	exitError = 2
)

// exitCodesHelp is the "Exit codes" section of a command's --help. gateLine
// describes exit code 1 for that command ("" for commands that never gate).
func exitCodesHelp(gateLine string) string {
	s := "\n\nExit codes:\n  0  The command completed"
	if gateLine != "" {
		s += " and no gate tripped; findings may still be present"
	}
	s += ".\n"
	if gateLine != "" {
		s += "  " + gateLine + "\n"
	}
	return s + "  2  The command failed or was used incorrectly (an invalid flag or value,\n" +
		"     an unreadable target, invalid rule configuration, an incomplete scan).\n" +
		"     Treat it as a failed check, never as a clean result."
}

// parseFailOn reads a --fail-on value: one of the five severities, or
// warning, which keeps its earlier meaning on every command (HIGH for
// content findings, WARNING and above for package findings).
func parseFailOn(value string) (types.Severity, error) {
	v := strings.ToLower(strings.TrimSpace(value))
	if v == "warning" {
		return types.SeverityHigh, nil
	}
	sev, err := types.ParseSeverity(v)
	if err != nil {
		return types.SeverityInfo, fmt.Errorf("invalid --fail-on %q: choose %s", value, failOnChoices)
	}
	return sev, nil
}

// packageSeverity maps a check finding severity onto the five levels:
// CRITICAL stays CRITICAL, WARNING is HIGH and INFO is INFO. Unknown
// severities (from a newer intel format) never reach a gate.
func packageSeverity(s string) (types.Severity, bool) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case incident.SevCritical:
		return types.SeverityCritical, true
	case incident.SevWarning:
		return types.SeverityHigh, true
	case incident.SevInfo:
		return types.SeverityInfo, true
	default:
		return types.SeverityInfo, false
	}
}

// gateError is returned when a gate trips. It wraps ErrThresholdExceeded so
// the process exits 1, and says what tripped the gate.
type gateError struct{ msg string }

func (e *gateError) Error() string { return e.msg }
func (e *gateError) Unwrap() error { return ErrThresholdExceeded }

// exitCodeFor is the process exit code an error from a command produces.
func exitCodeFor(err error) int {
	switch {
	case err == nil:
		return exitOK
	case errors.Is(err, ErrThresholdExceeded):
		return exitGate
	default:
		return exitError
	}
}

// severityCounts renders "2 CRITICAL, 1 HIGH" for the findings at or above
// threshold, highest first.
func severityCounts(counts map[types.Severity]int) string {
	var parts []string
	for sev := types.SeverityCritical; sev >= types.SeverityInfo; sev-- {
		if n := counts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	return strings.Join(parts, ", ")
}

func pluralize(n int, one, many string) string {
	return fmt.Sprintf("%d %s", n, plural(n, one, many))
}

// thresholdTrip describes a tripped severity gate.
type thresholdTrip struct {
	threshold types.Severity
	value     string // the value as given ("warning", "high")
	source    string // "--fail-on", "--ci", ".aguara.yml fail_on"
	// what lists the counted findings with their severities:
	// "3 findings (2 CRITICAL, 1 HIGH)".
	what      string
	baselined int
}

func (t thresholdTrip) err() error {
	msg := fmt.Sprintf("%s: %s at or above %s; threshold %s from %s",
		ErrThresholdExceeded.Error(), t.what, t.threshold,
		strings.ToLower(strings.TrimSpace(t.value)), t.source)
	if t.baselined > 0 {
		msg += fmt.Sprintf("; %s not counted", pluralize(t.baselined, "baselined finding", "baselined findings"))
	}
	return &gateError{msg: msg}
}

// scanFailOnSource names where scan's --fail-on value came from.
func scanFailOnSource(flagChanged bool) string {
	switch {
	case flagChanged:
		return "--fail-on"
	case flagFailOnSource != "":
		return flagFailOnSource
	case flagCI:
		return "--ci"
	default:
		return "--fail-on"
	}
}

// scanGate gates scan findings at flagFailOn. findings is the gate set
// (after a baseline); baselined is how many findings the baseline kept out
// of it, for the message.
func scanGate(findings []types.Finding, baselined int, source string) error {
	if flagFailOn == "" {
		return nil
	}
	threshold, err := parseFailOn(flagFailOn)
	if err != nil {
		return err
	}
	counts := map[types.Severity]int{}
	n := 0
	for _, f := range findings {
		if f.Severity >= threshold {
			counts[f.Severity]++
			n++
		}
	}
	if n == 0 {
		return nil
	}
	return thresholdTrip{
		threshold: threshold, value: flagFailOn, source: source,
		what:      fmt.Sprintf("%s (%s)", pluralize(n, "finding", "findings"), severityCounts(counts)),
		baselined: baselined,
	}.err()
}

// packageGateCounts counts the package findings at or above threshold,
// by their own labels (CRITICAL, WARNING, INFO).
func packageGateCounts(findings []incident.Finding, threshold types.Severity) (int, string) {
	labels := map[string]int{}
	n := 0
	for _, f := range findings {
		sev, ok := packageSeverity(f.Severity)
		if !ok || sev < threshold {
			continue
		}
		labels[strings.ToUpper(strings.TrimSpace(f.Severity))]++
		n++
	}
	var parts []string
	for _, label := range []string{incident.SevCritical, incident.SevWarning, incident.SevInfo} {
		if c := labels[label]; c > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", c, label))
		}
	}
	return n, strings.Join(parts, ", ")
}

// checkGate gates package findings at threshold, read with the five-level
// vocabulary and packageSeverity.
func checkGate(result *incident.CheckResult, threshold, source string) error {
	if threshold == "" {
		return nil
	}
	thr, err := parseFailOn(threshold)
	if err != nil {
		return err
	}
	n, counts := packageGateCounts(result.Findings, thr)
	if n == 0 {
		return nil
	}
	return thresholdTrip{
		threshold: thr, value: threshold, source: source,
		what: fmt.Sprintf("%s (%s)", pluralize(n, "package finding", "package findings"), counts),
	}.err()
}

// ciFailOnSource names where a check or audit --fail-on came from.
func ciFailOnSource(flagChanged, ci bool) string {
	if !flagChanged && ci {
		return "--ci"
	}
	return "--fail-on"
}

// gateDescription is the SARIF exitCodeDescription for a gate outcome.
func gateDescription(err error, threshold string) string {
	switch {
	case err != nil:
		return err.Error()
	case strings.TrimSpace(threshold) == "":
		return "completed; no --fail-on gate was set"
	default:
		return fmt.Sprintf("completed; no finding reached the %s threshold", strings.ToLower(strings.TrimSpace(threshold)))
	}
}

// Audit triage decisions, ordered by how much they restrict the next step.
var auditDecisionRank = map[string]int{"proceed": 0, "review": 1, "stop": 2}

// parseFailOnDecision reads --fail-on-decision: review or stop.
func parseFailOnDecision(value string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(value))
	switch v {
	case "":
		return "", nil
	case "review", "stop":
		return v, nil
	default:
		return "", fmt.Errorf("invalid --fail-on-decision %q: choose review or stop", value)
	}
}

// decisionGate trips when the triage decision is at least threshold.
func decisionGate(triage AuditTriage, threshold string) error {
	if threshold == "" || auditDecisionRank[triage.Decision] < auditDecisionRank[threshold] {
		return nil
	}
	msg := fmt.Sprintf("audit decision gate: triage decision is %s, at or above --fail-on-decision %s", triage.Decision, threshold)
	if kinds := auditActionPriority(triage); len(kinds) > 0 {
		msg += " (reasons: " + strings.Join(kinds, ", ") + ")"
	}
	return &gateError{msg: msg}
}

// joinGateErrors combines the severity gate and the decision gate of one
// run into a single error that still exits 1.
func joinGateErrors(errs ...error) error {
	var msgs []string
	for _, err := range errs {
		if err != nil {
			msgs = append(msgs, err.Error())
		}
	}
	switch len(msgs) {
	case 0:
		return nil
	case 1:
		for _, err := range errs {
			if err != nil {
				return err
			}
		}
	}
	return &gateError{msg: strings.Join(msgs, "; ")}
}
