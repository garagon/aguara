package commands

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/garagon/aguara/internal/packagecheck"
)

// A project whose only dependency evidence is a format Aguara does not
// parse must not be cleared for installation, even though the package
// check found nothing: it never checked those packages.
func TestAuditDoesNotProceedWhenNoDependencyEvidenceCouldBeEvaluated(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cases := map[string]string{
		"deno.lock":       denoLockFixture,
		"gems.locked":     gemsLockedFixture,
		"packages.config": packagesConfigFixture,
		"paket.lock":      paketLockFixture,
		"pubspec.lock":    "packages:\n  http:\n    version: \"1.2.0\"\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			dir := projectWith(t, map[string]string{name: content, "README.md": "# app\n"})
			result := auditToFile(t, dir)
			require.Equal(t, "pass", result.Verdict.Status, "no finding was produced; the verdict keeps its meaning")
			require.Equal(t, "review", result.Triage.Decision)
			requireTriageReason(t, result.Triage, "dependency_evidence_not_evaluated")
			for _, r := range result.Triage.Reasons {
				if r.Kind == "dependency_evidence_not_evaluated" {
					require.Contains(t, r.Message, name, "the reason must name the unsupported file")
				}
			}
			require.Contains(t, result.Triage.RecommendedNextSteps[0], name)
			require.Equal(t, "review_only", result.Handoff.Status)
			require.Contains(t, result.Handoff.Summary, "could not evaluate")
			require.Equal(t, "review_only", result.Plan.TrustState)
			require.False(t, result.Plan.CanInstallDependencies)
			require.False(t, result.Plan.CanExecuteProjectCode)
			require.False(t, result.Plan.CanRunCI)
			require.Contains(t, result.Plan.Priority, "dependency_evidence_not_evaluated")
			require.Len(t, result.Coverage.UnsupportedEvidence, 1)
			require.Empty(t, result.Coverage.PackageEvidence)
		})
	}
}

// The case that started this work: a uv.lock pinning a version present
// in the embedded intelligence. Python lockfiles are parsed now, so the
// pin is a CRITICAL finding, triage stops, and --ci fails the run.
func TestAuditStopsOnMaliciousUVLockPin(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := projectWith(t, map[string]string{"uv.lock": uvLockWithKnownMaliciousVersion, "README.md": "# app\n"})

	result := auditToFile(t, dir)
	require.Equal(t, "stop", result.Triage.Decision)
	requireTriageReason(t, result.Triage, "known_malicious_package")
	require.Equal(t, 1, result.Verdict.CheckCriticals)
	require.Equal(t, "blocked", result.Plan.TrustState)
	require.False(t, result.Plan.CanInstallDependencies)
	require.Empty(t, result.Coverage.UnsupportedEvidence, "uv.lock was read, so it is not unsupported evidence")
	require.Len(t, result.Coverage.PackageEvidence, 1)
	require.Equal(t, "uv.lock", result.Coverage.PackageEvidence[0].Source)

	err := runCLI(t, "audit", dir, "--ci", "--format", "json", "-o", filepath.Join(t.TempDir(), "a.json"))
	require.ErrorIs(t, err, ErrThresholdExceeded)
}

// Evaluating some dependency files does not clear installation: the
// action plan covers the whole repository, so an install would also pull
// the packages in the files nothing checked.
func TestAuditNamesPartiallyEvaluatedDependencyEvidence(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := projectWith(t, map[string]string{
		"package-lock.json":  packageLockFixture,
		"worker/gems.locked": gemsLockedFixture,
	})
	result := auditToFile(t, dir)
	require.Equal(t, "pass", result.Verdict.Status)
	require.Equal(t, "review", result.Triage.Decision)
	require.Equal(t, "Some dependency files could not be evaluated, so the audit cannot clear dependency installation.", result.Triage.Summary)
	requireTriageReason(t, result.Triage, "partial_dependency_coverage")
	for _, r := range result.Triage.Reasons {
		if r.Kind == "partial_dependency_coverage" {
			require.Equal(t, "warning", r.Severity)
			require.Contains(t, r.Message, "worker/gems.locked")
		}
	}
	require.Equal(t, []string{
		"Review the dependencies pinned in worker/gems.locked before installing them; this audit did not check them.",
		"Do not install dependencies on the strength of this audit.",
	}, result.Triage.RecommendedNextSteps)
	require.Equal(t, "review_only", result.Handoff.Status)
	require.Equal(t, "review_only", result.Plan.TrustState)
	require.False(t, result.Plan.CanInstallDependencies)
	require.Len(t, result.Coverage.PackageEvidence, 1, "the evaluated lockfile is still reported")
}

// A project with no dependency files at all keeps today's package-side
// behavior: nothing to evaluate is not unevaluated evidence.
func TestAuditWithoutDependencyFilesStillProceeds(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := projectWith(t, map[string]string{"SKILL.md": "# helper\nSummarize the file.\n"})
	result := auditToFile(t, dir)
	require.Equal(t, "proceed", result.Triage.Decision)
	require.True(t, result.Plan.CanInstallDependencies)
	require.Empty(t, result.Coverage.UnsupportedEvidence)
}

// Findings already under review keep their decision; the unevaluated
// files are added to the reasons and next steps.
func TestAuditReviewFindingsAlsoNameUnevaluatedEvidence(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := projectWith(t, map[string]string{
		"packages.config":       packagesConfigFixture,
		".claude/settings.json": `{"permissions":{"allow":["Bash(*)"]}}`,
	})
	result := auditToFile(t, dir)
	require.Equal(t, "review", result.Triage.Decision)
	requireTriageReason(t, result.Triage, "dependency_evidence_not_evaluated")
	require.Contains(t, strings.Join(result.Triage.RecommendedNextSteps, "\n"), "packages.config")
	require.False(t, result.Plan.CanInstallDependencies)
}

// Triage messages name the unsupported files but cut long lists; the
// full list stays in coverage.unsupported_evidence.
func TestUnsupportedEvidenceNamesCapsLongLists(t *testing.T) {
	var evidence []packagecheck.UnsupportedEvidence
	for _, dir := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		evidence = append(evidence, packagecheck.UnsupportedEvidence{
			Path: filepath.Join("/repo", dir, "packages.config"),
		})
	}
	require.Equal(t,
		"a/packages.config, b/packages.config, c/packages.config, d/packages.config, e/packages.config, and 2 more listed in coverage.unsupported_evidence",
		unsupportedEvidenceNames(evidence, "/repo"))
}

func TestAuditTerminalNamesUnevaluatedDependencyFiles(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := projectWith(t, map[string]string{"deno.lock": denoLockFixture})
	out := readReport(t, "audit", dir)
	require.Contains(t, out, "Coverage: no supported dependency evidence was read")
	require.Contains(t, out, "Not evaluated: deno.lock (dependency file Aguara cannot parse")
	require.Contains(t, out, "No packages were checked")
	require.Contains(t, out, "Triage: REVIEW")
	require.Contains(t, out, "install=no")
	require.NotContains(t, out, "✔ Verdict")
}
