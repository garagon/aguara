package rulecatalog_test

import (
	"errors"
	"os"
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

func TestFindByIDMissingReturnsErrNotExist(t *testing.T) {
	// CLI maps os.ErrNotExist to a clean "rule X not found"
	// message. Other errors (load failure, malformed YAML) keep
	// surfacing as wrapped errors.
	_, err := rulecatalog.FindByID(rulecatalog.Options{}, "DEFINITELY_NOT_A_RULE_999")
	require.Error(t, err)
	require.True(t, errors.Is(err, os.ErrNotExist),
		"missing rule must wrap os.ErrNotExist for the CLI's error-mapping path")
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
	}
	for _, id := range emitted {
		_, err := rulecatalog.FindByID(rulecatalog.Options{}, id)
		require.NoErrorf(t, err, "analyzer-emitted ID %s must be in the catalog", id)
	}
}
