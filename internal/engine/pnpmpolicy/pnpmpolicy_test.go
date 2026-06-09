package pnpmpolicy

import (
	"context"
	"testing"
	"time"

	"github.com/garagon/aguara/internal/scanner"
)

// ids runs the analyzer over content presented as `name` and returns the
// set of rule IDs emitted.
func ids(t *testing.T, name, src string) map[string]bool {
	t.Helper()
	a := New()
	f, err := a.Analyze(context.Background(), &scanner.Target{RelPath: name, Content: []byte(src)})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	got := make(map[string]bool, len(f))
	for _, x := range f {
		got[x.RuleID] = true
	}
	return got
}

func fires(t *testing.T, name, src, id string) bool {
	t.Helper()
	return ids(t, name, src)[id]
}

const target = "pnpm-workspace.yaml"

func TestTruePositives(t *testing.T) {
	cases := []struct {
		name, src, want string
	}{
		{"dangerous builds", "dangerouslyAllowAllBuilds: true\n", RuleDangerousBuilds},
		{"strict dep builds off", "strictDepBuilds: false\n", RuleStrictDepBuildsDisabled},
		{"exotic subdeps off", "blockExoticSubdeps: false\n", RuleExoticSubdepsDisabled},
		{"trust lockfile on", "trustLockfile: true\n", RuleTrustLockfile},
		{"min release age disabled", "minimumReleaseAge: 0\n", RuleMinReleaseAgeDisabled},
		{
			"min release age non-strict (with explicit positive age)",
			"minimumReleaseAge: 1440\nminimumReleaseAgeStrict: false\n",
			RuleMinReleaseAgeNonStrict,
		},
		{"trust policy explicitly off", "trustPolicy: off\n", RuleTrustPolicyOff},
		{"legacy v10 setting", "onlyBuiltDependencies:\n  - esbuild\n", RuleLegacyBuildPolicy},
		{"allow builds pending (null placeholder)", "allowBuilds:\n  sharp:\n", RuleBuildApprovalPending},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !fires(t, target, c.src, c.want) {
				t.Fatalf("expected %s to fire on:\n%s", c.want, c.src)
			}
		})
	}
}

func TestFalsePositives(t *testing.T) {
	cases := []struct {
		name, file, src string
	}{
		// Wrong filename: never a target even with a tripping value.
		{"not pnpm-workspace.yaml", "config.yaml", "dangerouslyAllowAllBuilds: true\n"},
		{"random yaml", "docker-compose.yml", "trustLockfile: true\n"},
		// Safe explicit values.
		{"dangerous builds false", target, "dangerouslyAllowAllBuilds: false\n"},
		{"strict dep builds true", target, "strictDepBuilds: true\n"},
		{"block exotic subdeps true", target, "blockExoticSubdeps: true\n"},
		{"trust lockfile false", target, "trustLockfile: false\n"},
		{"min release age at default", target, "minimumReleaseAge: 1440\n"},
		{"min release age positive", target, "minimumReleaseAge: 720\n"},
		{"trust policy no-downgrade", target, "trustPolicy: no-downgrade\n"},
		// Absence is the (secure) default: never a finding.
		{"empty file", target, ""},
		{"unrelated settings only", target, "packages:\n  - 'packages/*'\n"},
		// allowBuilds with explicit decisions: nothing pending.
		{"allow builds decided", target, "allowBuilds:\n  esbuild: true\n  sharp: false\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ids(t, c.file, c.src); len(got) != 0 {
				t.Fatalf("expected no findings, got %v on:\n%s", got, c.src)
			}
		})
	}
}

// TestKebabCaseKeysIgnored: pnpm silently IGNORES kebab-case keys in
// pnpm-workspace.yaml (ground truth: pnpm 11.5.2, 2026-06-09 -- `pnpm
// config list` does not load them and install emits no warning; kebab
// is the .npmrc spelling, not the workspace-file spelling). A kebab key
// therefore leaves the secure default in effect and must NOT fire.
func TestKebabCaseKeysIgnored(t *testing.T) {
	for _, src := range []string{
		"dangerously-allow-all-builds: true\n",
		"block-exotic-subdeps: false\n",
		"trust-lockfile: true\n",
		"minimum-release-age: 0\n",
		"strict-dep-builds: false\n",
		"trust-policy: off\n",
		"only-built-dependencies:\n  - esbuild\n",
		"allow-builds:\n  sharp:\n",
	} {
		if got := ids(t, target, src); len(got) != 0 {
			t.Fatalf("kebab-case key is ignored by pnpm and must not fire, got %v on:\n%s", got, src)
		}
	}
}

// TestMergeKeysResolved: a setting supplied through a YAML merge key
// (`<<: *anchor`) is applied by pnpm, so the analyzer must see it.
func TestMergeKeysResolved(t *testing.T) {
	src := `presets:
  unsafe: &unsafe
    dangerouslyAllowAllBuilds: true
config:
  <<: *unsafe
`
	// The merge happens inside `config:`, not at the root, so the root
	// has no dangerous setting. Verify a root-level merge instead.
	rootMerge := `defaults: &d
  dangerouslyAllowAllBuilds: true
<<: *d
`
	if !fires(t, target, rootMerge, RuleDangerousBuilds) {
		t.Fatalf("root-level merge key must surface the merged dangerous setting")
	}
	// A nested merge under a non-pnpm key must NOT leak as a root setting.
	if fires(t, target, src, RuleDangerousBuilds) {
		t.Fatal("a merge under an unrelated key must not be read as a root setting")
	}
}

// TestMergeBombTerminates: a fan-out / self-referential merge must not
// cause exponential or unbounded work. A crafted untrusted
// pnpm-workspace.yaml should be analyzed in well under a second.
func TestMergeBombTerminates(t *testing.T) {
	// Self-referential anchor plus a fan-out merge sequence that would
	// blow up if the same node were re-expanded per branch per depth.
	src := `base: &b
  dangerouslyAllowAllBuilds: true
  <<: [*b, *b, *b, *b]
<<: [*b, *b, *b, *b]
`
	done := make(chan map[string]bool, 1)
	go func() { done <- ids(t, target, src) }()
	select {
	case got := <-done:
		// And it must still resolve the merged setting correctly.
		if !got[RuleDangerousBuilds] {
			t.Fatal("merge bomb terminated but lost the merged dangerous setting")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("merge expansion did not terminate; possible exponential blowup")
	}
}

// TestExplicitKeyWinsOverMerge: an explicit safe value overrides a
// merged unsafe one (YAML merge precedence), so no finding fires.
func TestExplicitKeyWinsOverMerge(t *testing.T) {
	src := `defaults: &d
  dangerouslyAllowAllBuilds: true
<<: *d
dangerouslyAllowAllBuilds: false
`
	if fires(t, target, src, RuleDangerousBuilds) {
		t.Fatal("explicit dangerouslyAllowAllBuilds: false must win over the merged true")
	}
}

// TestKebabDoesNotShadowCamel: a kebab key is a separate, ignored key,
// so it never overrides the camelCase value pnpm actually loads -- in
// either direction.
func TestKebabDoesNotShadowCamel(t *testing.T) {
	// Merged camel true (loaded by pnpm) + explicit kebab false
	// (ignored by pnpm) -> the dangerous setting IS in effect -> fire.
	stillDangerous := `defaults: &d
  dangerouslyAllowAllBuilds: true
<<: *d
dangerously-allow-all-builds: false
`
	if !fires(t, target, stillDangerous, RuleDangerousBuilds) {
		t.Fatal("ignored kebab false must not mask the merged camelCase true pnpm loads")
	}
	// Explicit camel false + kebab true -> pnpm loads only the safe
	// false -> no finding.
	safe := "dangerouslyAllowAllBuilds: false\ndangerously-allow-all-builds: true\n"
	if fires(t, target, safe, RuleDangerousBuilds) {
		t.Fatal("ignored kebab true must not override the explicit camelCase false")
	}
}

// TestDuplicateCamelKeyLastWins: duplicate camelCase keys resolve to the
// later value, mirroring how a YAML loader applies duplicates.
func TestDuplicateCamelKeyLastWins(t *testing.T) {
	if !fires(t, target, "dangerouslyAllowAllBuilds: false\ndangerouslyAllowAllBuilds: true\n", RuleDangerousBuilds) {
		t.Fatal("later duplicate true must win over earlier false")
	}
	if fires(t, target, "dangerouslyAllowAllBuilds: true\ndangerouslyAllowAllBuilds: false\n", RuleDangerousBuilds) {
		t.Fatal("later duplicate false must win over earlier true")
	}
}

// TestUnrecognizedSpellingNotFlagged: only the exact camelCase spelling
// pnpm honors in pnpm-workspace.yaml matches; any other spelling is a
// key pnpm ignores there and must not produce a finding.
func TestUnrecognizedSpellingNotFlagged(t *testing.T) {
	for _, src := range []string{
		"dangerouslyallowallbuilds: true\n",     // no camel boundaries
		"BlockExoticSubdeps: false\n",           // wrong leading case
		"DANGEROUSLY_ALLOW_ALL_BUILDS: true\n",  // underscores
		"dangerously--allow-all-builds: true\n", // malformed hyphenation
		"dangerously-allow-all-builds-: true\n", // trailing hyphen
		"-block-exotic-subdeps: false\n",        // leading hyphen
	} {
		if got := ids(t, target, src); len(got) != 0 {
			t.Fatalf("unrecognized key spelling must not fire, got %v on:\n%s", got, src)
		}
	}
}

// TestQuotedFalseNotFlagged: the spec's FP discipline requires that an
// explicit intent-to-disable ("false") is never read as an opt-in.
func TestQuotedFalseNotFlagged(t *testing.T) {
	for _, src := range []string{
		"dangerouslyAllowAllBuilds: \"false\"\n",
		"dangerouslyAllowAllBuilds: no\n",
		"dangerouslyAllowAllBuilds: off\n",
	} {
		if fires(t, target, src, RuleDangerousBuilds) {
			t.Fatalf("a disable value must not fire HIGH:\n%s", src)
		}
	}
}

// TestBooleanMatchesPnpmLoader locks the boolean model to pnpm's actual
// config loader (js-yaml, YAML 1.1), where yes/no/on/off ARE booleans.
// This deliberately differs from gopkg.in/yaml.v3 (which resolves
// yes/off as strings): trusting the v3 tag here would diverge from pnpm
// and miss real opt-ins like `dangerouslyAllowAllBuilds: yes`. A value
// that is not a recognized boolean token is left un-evaluated.
func TestBooleanMatchesPnpmLoader(t *testing.T) {
	// yes/on resolve to true -> a truthy danger flag fires.
	for _, v := range []string{"yes", "on", "true"} {
		if !fires(t, target, "dangerouslyAllowAllBuilds: "+v+"\n", RuleDangerousBuilds) {
			t.Fatalf("dangerouslyAllowAllBuilds: %s must fire (resolves true)", v)
		}
	}
	// no/off resolve to false -> a flag whose UNSAFE value is false fires.
	for _, v := range []string{"no", "off", "false"} {
		if !fires(t, target, "strictDepBuilds: "+v+"\n", RuleStrictDepBuildsDisabled) {
			t.Fatalf("strictDepBuilds: %s must fire (resolves false, the unsafe value)", v)
		}
	}
	// A non-boolean token is ambiguous and not evaluated.
	if got := ids(t, target, "dangerouslyAllowAllBuilds: maybe\n"); len(got) != 0 {
		t.Fatalf("a non-boolean token must not be evaluated, got %v", got)
	}
}

// TestQuotedZeroIsExplicitOptOut: a quoted "0" for minimumReleaseAge is
// still an explicit 0 by intent, so it fires the disabled rule.
func TestQuotedZeroIsExplicitOptOut(t *testing.T) {
	if !fires(t, target, "minimumReleaseAge: \"0\"\n", RuleMinReleaseAgeDisabled) {
		t.Fatal("minimumReleaseAge: \"0\" is an explicit opt-out and must fire")
	}
}

// TestNonStrictRequiresExplicitPositiveAge locks the spec's FP-discipline
// rule: minimumReleaseAgeStrict: false on its own may just be declaring
// the v11 compatibility default, so it must NOT fire without an explicit
// positive minimumReleaseAge in the same file.
func TestNonStrictRequiresExplicitPositiveAge(t *testing.T) {
	if fires(t, target, "minimumReleaseAgeStrict: false\n", RuleMinReleaseAgeNonStrict) {
		t.Fatal("minimumReleaseAgeStrict: false alone must not fire (could be the v11 default)")
	}
	if fires(t, target, "minimumReleaseAge: 0\nminimumReleaseAgeStrict: false\n", RuleMinReleaseAgeNonStrict) {
		t.Fatal("minimumReleaseAge: 0 is not a positive age; non-strict must not fire")
	}
	if !fires(t, target, "minimumReleaseAge: 1440\nminimumReleaseAgeStrict: false\n", RuleMinReleaseAgeNonStrict) {
		t.Fatal("explicit positive age + non-strict must fire")
	}
}

// TestLegacyIsInfoNotHigh confirms a v10 setting is reported as a
// migration nudge (INFO), never as a HIGH vulnerability.
func TestLegacyIsInfoNotHigh(t *testing.T) {
	a := New()
	f, err := a.Analyze(context.Background(), &scanner.Target{
		RelPath: target,
		Content: []byte("neverBuiltDependencies:\n  - fsevents\n"),
	})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(f) != 1 {
		t.Fatalf("want 1 finding, got %d", len(f))
	}
	if f[0].RuleID != RuleLegacyBuildPolicy {
		t.Fatalf("want %s, got %s", RuleLegacyBuildPolicy, f[0].RuleID)
	}
	if f[0].Severity.String() != "INFO" {
		t.Fatalf("legacy finding must be INFO, got %s", f[0].Severity.String())
	}
}

// TestDynamicValueNotEvaluated: a ${ENV} interpolation is not a concrete
// opt-out, so minimumReleaseAge: ${AGE} must not fire the disabled rule.
func TestDynamicValueNotEvaluated(t *testing.T) {
	if fires(t, target, "minimumReleaseAge: ${AGE}\n", RuleMinReleaseAgeDisabled) {
		t.Fatal("dynamic minimumReleaseAge must not be evaluated as 0")
	}
}

// TestMalformedYAMLNoPanic: a syntactically broken file yields no
// findings and does not panic.
func TestMalformedYAMLNoPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("analyzer panicked on malformed YAML: %v", r)
		}
	}()
	if got := ids(t, target, "trustLockfile: true\n  : : broken\n\t- nope\n"); len(got) != 0 {
		t.Fatalf("malformed YAML should yield no findings, got %v", got)
	}
}

// TestFindingPointsAtField checks the finding carries the field's line
// and source text, which is the whole point of the yaml.Node parser.
func TestFindingPointsAtField(t *testing.T) {
	a := New()
	src := "packages:\n  - 'packages/*'\ndangerouslyAllowAllBuilds: true\n"
	f, err := a.Analyze(context.Background(), &scanner.Target{RelPath: target, Content: []byte(src)})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(f) != 1 {
		t.Fatalf("want 1 finding, got %d", len(f))
	}
	if f[0].Line != 3 {
		t.Fatalf("want line 3, got %d", f[0].Line)
	}
	if f[0].MatchedText != "dangerouslyAllowAllBuilds: true" {
		t.Fatalf("unexpected matched text: %q", f[0].MatchedText)
	}
}
