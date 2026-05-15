package rulecatalog_test

import (
	"errors"
	"testing"

	"github.com/garagon/aguara/internal/rulecatalog"
	"github.com/garagon/aguara/internal/rulemeta"
	"github.com/stretchr/testify/require"
)

// TestBuildIncludesYAMLAndAnalyzerRules locks the central contract:
// every catalog source (pattern rules + ci-trust + pkgmeta + jsrisk
// + nlp + toxicflow) must surface through Build. A regression in
// any analyzer's RuleMetadata() loses one of these assertions and
// fails loud, rather than silently breaking `aguara explain` for
// the affected analyzer.
func TestBuildIncludesYAMLAndAnalyzerRules(t *testing.T) {
	cat, err := rulecatalog.Build(rulecatalog.Options{})
	require.NoError(t, err)
	require.NotEmpty(t, cat)

	ids := make(map[string]rulemeta.Rule, len(cat))
	for _, r := range cat {
		ids[r.ID] = r
	}

	// One representative ID per analyzer.
	want := map[string]string{
		"JS_DNS_TXT_EXFIL_001":  rulemeta.AnalyzerJSRisk,
		"GHA_PWN_REQUEST_001":   rulemeta.AnalyzerCITrust,
		"NPM_LIFECYCLE_GIT_001": rulemeta.AnalyzerPkgMeta,
		"TOXIC_001":             rulemeta.AnalyzerToxicFlow,
		"TOXIC_CROSS_001":       rulemeta.AnalyzerToxicFlow,
		"NLP_HIDDEN_INSTRUCTION": rulemeta.AnalyzerNLP,
		"AGENT_PERSISTENCE_001": rulemeta.AnalyzerJSRisk,
		// And one pattern rule from the YAML catalog (analyzer
		// stays empty for these).
		"PROMPT_INJECTION_001": rulemeta.AnalyzerPattern,
	}
	for id, analyzer := range want {
		rec, ok := ids[id]
		require.Truef(t, ok, "catalog must include %s", id)
		require.Equalf(t, analyzer, rec.Analyzer, "analyzer for %s", id)
		require.NotEmptyf(t, rec.Severity, "%s severity must be set", id)
		require.NotEmptyf(t, rec.Category, "%s category must be set", id)
	}
}

func TestBuildSortsByID(t *testing.T) {
	cat, err := rulecatalog.Build(rulecatalog.Options{})
	require.NoError(t, err)
	for i := 1; i < len(cat); i++ {
		require.LessOrEqualf(t, cat[i-1].ID, cat[i].ID,
			"catalog must be sorted by ID; %d=%s came before %d=%s", i-1, cat[i-1].ID, i, cat[i].ID)
	}
}

func TestBuildCategoryFilter(t *testing.T) {
	// --category filter applies to BOTH YAML rules and analyzer
	// rules. Use "supply-chain" because ci-trust + pkgmeta + most
	// jsrisk records share that category, so the filter has
	// substantial output to assert against.
	cat, err := rulecatalog.Build(rulecatalog.Options{Category: "supply-chain"})
	require.NoError(t, err)
	require.NotEmpty(t, cat)
	for _, r := range cat {
		require.Equal(t, "supply-chain", r.Category)
	}
}

func TestBuildCategoryFilterCaseInsensitive(t *testing.T) {
	upper, err := rulecatalog.Build(rulecatalog.Options{Category: "SUPPLY-CHAIN"})
	require.NoError(t, err)
	lower, err := rulecatalog.Build(rulecatalog.Options{Category: "supply-chain"})
	require.NoError(t, err)
	require.Equal(t, len(lower), len(upper), "category filter must be case-insensitive")
}

func TestBuildDisableRuleFiltersAnalyzerRules(t *testing.T) {
	// --disable-rule must drop analyzer-emitted rules just like
	// it drops YAML rules. Before this consolidation a user
	// running `aguara list-rules --disable-rule JS_DNS_TXT_EXFIL_001`
	// would see the rule anyway because list-rules only knew
	// about YAML; this regression test locks the new behaviour.
	cat, err := rulecatalog.Build(rulecatalog.Options{
		DisableRuleIDs: []string{"JS_DNS_TXT_EXFIL_001"},
	})
	require.NoError(t, err)
	for _, r := range cat {
		require.NotEqual(t, "JS_DNS_TXT_EXFIL_001", r.ID,
			"--disable-rule must remove analyzer rules from the catalog")
	}
}

func TestFindByIDResolvesAnalyzerRule(t *testing.T) {
	rec, err := rulecatalog.FindByID(rulecatalog.Options{}, "JS_DNS_TXT_EXFIL_001")
	require.NoError(t, err)
	require.Equal(t, "JS_DNS_TXT_EXFIL_001", rec.ID)
	require.Equal(t, rulemeta.AnalyzerJSRisk, rec.Analyzer)
}

func TestFindByIDResolvesYAMLRule(t *testing.T) {
	rec, err := rulecatalog.FindByID(rulecatalog.Options{}, "PROMPT_INJECTION_001")
	require.NoError(t, err)
	require.Equal(t, "PROMPT_INJECTION_001", rec.ID)
	require.Equal(t, rulemeta.AnalyzerPattern, rec.Analyzer)
}

func TestFindByIDCaseInsensitive(t *testing.T) {
	rec, err := rulecatalog.FindByID(rulecatalog.Options{}, "js_dns_txt_exfil_001")
	require.NoError(t, err)
	require.Equal(t, "JS_DNS_TXT_EXFIL_001", rec.ID)
}

func TestFindByIDMissingReturnsErrRuleNotFound(t *testing.T) {
	// CLI maps ErrRuleNotFound to a clean "rule X not found"
	// message. Other errors (load failure, malformed YAML) keep
	// surfacing as wrapped errors so the user can diagnose them.
	_, err := rulecatalog.FindByID(rulecatalog.Options{}, "DEFINITELY_NOT_A_RULE_999")
	require.Error(t, err)
	require.True(t, errors.Is(err, rulecatalog.ErrRuleNotFound),
		"missing rule must wrap ErrRuleNotFound (not the generic os.ErrNotExist)")
}

func TestFindByIDBuildErrorDistinctFromNotFound(t *testing.T) {
	// Codex P3 round 3: when --rules points at a directory that
	// does not exist, Build returns an error wrapping
	// os.ErrNotExist (because LoadFromDir fails). The CLI must
	// NOT collapse that into "rule not found" -- the underlying
	// config typo would be hidden. Test: a missing custom-rules
	// dir produces an error that is NOT ErrRuleNotFound, so
	// explain.go's mapping (which only maps ErrRuleNotFound)
	// surfaces the real error.
	_, err := rulecatalog.FindByID(rulecatalog.Options{
		CustomRulesDir: "/definitely/not/a/real/dir/" + t.Name(),
	}, "PROMPT_INJECTION_001")
	require.Error(t, err)
	require.False(t, errors.Is(err, rulecatalog.ErrRuleNotFound),
		"a missing custom-rules dir must NOT be mapped as ErrRuleNotFound; the CLI would mask the real error otherwise")
}

func TestAnalyzerMetadataMatchesEmittedSeverityAndCategory(t *testing.T) {
	// Codex P2 round 2: the catalog metadata MUST match what the
	// analyzers actually emit on Finding.Severity / Finding.Category.
	// Without this lock, `list-rules --category X` shows rules the
	// scanner reports under a different category, and triage
	// agents calibrating to severity disagree with scan output.
	//
	// Source of truth (kept here as comments so a regression is
	// debuggable from the test row alone):
	//
	//   toxicflow.go / crossfile.go append findings with
	//     Severity = types.SeverityHigh, Category = "toxic-flow".
	//   nlp/injection.go checkDangerousCombos:
	//     NLP_CRED_EXFIL_COMBO -> CRITICAL + "exfiltration".
	//   rugpull.go: RUGPULL_001 -> CRITICAL + "rug-pull".
	type want struct {
		Severity string
		Category string
	}
	cases := map[string]want{
		"TOXIC_001":             {Severity: "HIGH", Category: "toxic-flow"},
		"TOXIC_002":             {Severity: "HIGH", Category: "toxic-flow"},
		"TOXIC_003":             {Severity: "HIGH", Category: "toxic-flow"},
		"TOXIC_CROSS_001":       {Severity: "HIGH", Category: "toxic-flow"},
		"TOXIC_CROSS_002":       {Severity: "HIGH", Category: "toxic-flow"},
		"TOXIC_CROSS_003":       {Severity: "HIGH", Category: "toxic-flow"},
		"NLP_CRED_EXFIL_COMBO":  {Severity: "CRITICAL", Category: "exfiltration"},
		"RUGPULL_001":           {Severity: "CRITICAL", Category: "rug-pull"},
	}
	for id, w := range cases {
		rec, err := rulecatalog.FindByID(rulecatalog.Options{}, id)
		require.NoErrorf(t, err, "%s must be in the catalog", id)
		require.Equalf(t, w.Severity, rec.Severity,
			"%s severity must match the analyzer emit-site", id)
		require.Equalf(t, w.Category, rec.Category,
			"%s category must match the analyzer emit-site", id)
	}
}

func TestBuildOverridesDisableAndSeverityYAMLOnly(t *testing.T) {
	// Catalog-level test for the override path the aguara public
	// API wires to. The scanner's rules.ApplyOverrides only
	// operates on YAML compiled rules, so the catalog mirrors
	// that contract: Overrides DROP / REMAP YAML rules but DO
	// NOT touch analyzer rules. A divergence would mean a policy
	// UI built on ListRules disagrees with what the scanner
	// emits for analyzer findings.

	// YAML rule -- Disabled drops it from the listing.
	disabled, err := rulecatalog.Build(rulecatalog.Options{
		Overrides: map[string]rulecatalog.Override{
			"PROMPT_INJECTION_001": {Disabled: true},
		},
	})
	require.NoError(t, err)
	for _, r := range disabled {
		require.NotEqual(t, "PROMPT_INJECTION_001", r.ID,
			"Overrides{Disabled:true} must drop YAML rules")
	}

	// YAML rule -- Severity is remapped.
	remapped, err := rulecatalog.Build(rulecatalog.Options{
		Overrides: map[string]rulecatalog.Override{
			"PROMPT_INJECTION_001": {Severity: "low"},
		},
	})
	require.NoError(t, err)
	var got string
	for _, r := range remapped {
		if r.ID == "PROMPT_INJECTION_001" {
			got = r.Severity
			break
		}
	}
	require.Equal(t, "LOW", got, "Overrides{Severity: ...} must upper-case + apply to YAML rules")

	// Analyzer rule -- Disabled is IGNORED. The scanner does not
	// apply RuleOverrides to analyzer findings, so the catalog
	// must not pretend it does. Users who want to suppress an
	// analyzer rule should use WithDisabledRules instead.
	notDropped, err := rulecatalog.Build(rulecatalog.Options{
		Overrides: map[string]rulecatalog.Override{
			"JS_DNS_TXT_EXFIL_001": {Disabled: true},
		},
	})
	require.NoError(t, err)
	var found bool
	for _, r := range notDropped {
		if r.ID == "JS_DNS_TXT_EXFIL_001" {
			found = true
			require.Equal(t, "HIGH", r.Severity,
				"analyzer rule severity must NOT be touched by Overrides; scanner does not apply them to analyzer findings")
			break
		}
	}
	require.True(t, found,
		"analyzer rule must survive Overrides{Disabled:true}; the scanner does not honour overrides for analyzer findings, so the catalog must not either")
}

func TestEveryAnalyzerEmittedIDHasCatalogEntry(t *testing.T) {
	// Belt-and-suspenders contract: the set of analyzer rule IDs
	// that the codebase declares as constants must be a subset of
	// the catalog. Specifically the rule IDs that the analyzer
	// public consts (RuleObfuscation etc.) expose must each be
	// findable. Tests the "co-locate metadata with the analyzer"
	// invariant -- if someone adds a new const without a matching
	// RuleMetadata() entry, this test fails.
	emitted := []string{
		// jsrisk public consts (internal/engine/jsrisk/jsrisk.go).
		"JS_OBF_001", "JS_DAEMON_001", "JS_CI_SECRET_HARVEST_001",
		"JS_PROC_MEM_OIDC_001", "AGENT_PERSISTENCE_001", "JS_DNS_TXT_EXFIL_001",
		// ci-trust public consts.
		"GHA_PWN_REQUEST_001", "GHA_CACHE_001", "GHA_OIDC_001", "GHA_CHECKOUT_001",
		// pkgmeta public consts.
		"NPM_LIFECYCLE_GIT_001", "NPM_OPTIONAL_GIT_001", "NPM_PUBLISH_SURFACE_001",
		// nlp injection-analyzer emit sites.
		"NLP_HIDDEN_INSTRUCTION", "NLP_CODE_MISMATCH", "NLP_HEADING_MISMATCH",
		"NLP_AUTHORITY_CLAIM", "NLP_CRED_EXFIL_COMBO", "NLP_OVERRIDE_DANGEROUS",
		// toxicflow emit sites (single-file + cross-file).
		"TOXIC_001", "TOXIC_002", "TOXIC_003",
		"TOXIC_CROSS_001", "TOXIC_CROSS_002", "TOXIC_CROSS_003",
		// rug-pull analyzer (only fires with --monitor / WithStateDir).
		"RUGPULL_001",
	}
	for _, id := range emitted {
		_, err := rulecatalog.FindByID(rulecatalog.Options{}, id)
		require.NoErrorf(t, err, "analyzer-emitted ID %s must be in the catalog", id)
	}
}
