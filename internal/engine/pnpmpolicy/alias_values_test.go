package pnpmpolicy

import (
	"context"
	"testing"

	"github.com/garagon/aguara/internal/scanner"
	"gopkg.in/yaml.v3"
)

func TestAliasPolicyValues(t *testing.T) {
	cases := []struct {
		name, src, rule string
		want            bool
	}{
		{"dangerous", "x: &safe true\ndangerouslyAllowAllBuilds: *safe\n", RuleDangerousBuilds, true},
		{"misleading true", "x: &true false\ndangerouslyAllowAllBuilds: *true\n", RuleDangerousBuilds, false},
		{"strict", "x: &yes false\nstrictDepBuilds: *yes\n", RuleStrictDepBuildsDisabled, true},
		{"exotic", "x: &yes false\nblockExoticSubdeps: *yes\n", RuleExoticSubdepsDisabled, true},
		{"lockfile", "x: &no true\ntrustLockfile: *no\n", RuleTrustLockfile, true},
		{"zero age", "x: &age 0\nminimumReleaseAge: *age\n", RuleMinReleaseAgeDisabled, true},
		{"misleading zero", "x: &0 1440\nminimumReleaseAge: *0\n", RuleMinReleaseAgeDisabled, false},
		{"strict age", "a: &age 1440\ns: &strict false\nminimumReleaseAge: *age\nminimumReleaseAgeStrict: *strict\n", RuleMinReleaseAgeNonStrict, true},
		{"off", "x: &policy off\ntrustPolicy: *policy\n", RuleTrustPolicyOff, true},
		{"misleading off", "x: &off no-downgrade\ntrustPolicy: *off\n", RuleTrustPolicyOff, false},
		{"pending", "x: &pending null\nallowBuilds:\n  sharp: *pending\n", RuleBuildApprovalPending, true},
		{"mapping", "x: &builds {sharp: null}\nallowBuilds: *builds\n", RuleBuildApprovalPending, true},
		{"decided", "x: &pending false\nallowBuilds:\n  sharp: *pending\n", RuleBuildApprovalPending, false},
		{"legacy presence", "x: &old []\nonlyBuiltDependencies: *old\n", RuleLegacyBuildPolicy, true},
		{"merged value", "x: &choice true\ny: &settings {dangerouslyAllowAllBuilds: *choice}\n<<: *settings\n", RuleDangerousBuilds, true},
		{"explicit safe wins", "x: &choice true\ny: &settings {dangerouslyAllowAllBuilds: *choice}\n<<: *settings\ndangerouslyAllowAllBuilds: false\n", RuleDangerousBuilds, false},
		{"alias safe overrides", "x: &choice false\ny: &settings {dangerouslyAllowAllBuilds: true}\n<<: *settings\ndangerouslyAllowAllBuilds: *choice\n", RuleDangerousBuilds, false},
		{"dynamic", "x: &0 '${AGE}'\nminimumReleaseAge: *0\n", RuleMinReleaseAgeDisabled, false},
		{"mapping named true", "x: &true {}\ndangerouslyAllowAllBuilds: *true\n", RuleDangerousBuilds, false},
		{"sequence named off", "x: &off []\ntrustPolicy: *off\n", RuleTrustPolicyOff, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := fires(t, target, tc.src, tc.rule); got != tc.want {
				t.Fatalf("%s present = %v, want %v", tc.rule, got, tc.want)
			}
		})
	}
}

func TestAliasFindingLocation(t *testing.T) {
	src := "x: &setting true\ndangerouslyAllowAllBuilds: *setting\n"
	fs, err := New().Analyze(context.Background(), &scanner.Target{RelPath: target, Content: []byte(src)})
	if err != nil || len(fs) != 1 {
		t.Fatalf("findings %v, error %v", fs, err)
	}
	if fs[0].Line != 2 || fs[0].MatchedText != "dangerouslyAllowAllBuilds: *setting" {
		t.Fatalf("finding must point to policy use, got %+v", fs[0])
	}
}

func TestAliasResolutionBounds(t *testing.T) {
	cycle := &yaml.Node{Kind: yaml.AliasNode, Value: "true"}
	cycle.Alias = cycle
	chain := &yaml.Node{Kind: yaml.ScalarNode, Value: "true"}
	for i := 0; i < maxMergeDepth+2; i++ {
		chain = &yaml.Node{Kind: yaml.AliasNode, Alias: chain, Value: "true"}
	}
	for _, input := range []*yaml.Node{nil, cycle, chain, {Kind: yaml.AliasNode, Value: "true"}} {
		got := resolveValue(input)
		if got == nil || got.Value != "" || isNull(got) {
			t.Fatalf("unresolved alias became a policy value: %+v", got)
		}
	}
}
