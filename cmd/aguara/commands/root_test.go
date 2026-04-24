package commands

import (
	"testing"
)

func TestIsCI(t *testing.T) {
	// Every CI env var the scanner recognizes, each covered by its own case.
	// Tests use t.Setenv so values are reverted automatically.
	cases := []struct {
		name string
		env  map[string]string
		want bool
	}{
		{"no env", nil, false},
		{"CI=true", map[string]string{"CI": "true"}, true},
		{"CI=1", map[string]string{"CI": "1"}, true},
		{"CI=false ignored", map[string]string{"CI": "false"}, false},
		{"CI=0 ignored", map[string]string{"CI": "0"}, false},
		{"CI= empty ignored", map[string]string{"CI": ""}, false},
		{"GITHUB_ACTIONS", map[string]string{"GITHUB_ACTIONS": "true"}, true},
		{"GITLAB_CI", map[string]string{"GITLAB_CI": "true"}, true},
		{"CIRCLECI", map[string]string{"CIRCLECI": "true"}, true},
		{"BUILDKITE", map[string]string{"BUILDKITE": "true"}, true},
		{"JENKINS_URL", map[string]string{"JENKINS_URL": "http://ci.example.com"}, true},
		{"TEAMCITY_VERSION", map[string]string{"TEAMCITY_VERSION": "2024.03"}, true},
		{"TRAVIS", map[string]string{"TRAVIS": "true"}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Clear every recognized signal first so a previously-set value
			// from the host doesn't leak into the case.
			for _, k := range []string{
				"CI", "GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI",
				"BUILDKITE", "JENKINS_URL", "TEAMCITY_VERSION", "TRAVIS",
			} {
				t.Setenv(k, "")
			}
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			if got := isCI(); got != tc.want {
				t.Errorf("isCI() = %v, want %v (env=%v)", got, tc.want, tc.env)
			}
		})
	}
}
