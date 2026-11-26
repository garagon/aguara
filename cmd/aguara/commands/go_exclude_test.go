package commands

import (
	"testing"

	"github.com/garagon/aguara/internal/incident"
	"github.com/stretchr/testify/require"
)

// A compromised version that go.mod both requires and excludes is still
// reported, and the finding says that go.mod excludes it, so the reader
// knows the go command ignores that requirement.
func TestGoFindingNamesTheExclusion(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AGUARA_NO_UPDATE_CHECK", "1")
	for name, files := range map[string]map[string]string{
		"go.mod only": {
			"go.mod": "module example.com/app\n\ngo 1.22\n\nrequire github.com/aquasecurity/trivy v0.69.4\n\nexclude github.com/aquasecurity/trivy v0.69.4\n",
		},
		"go.sum with tab-separated directives": {
			"go.mod": "module example.com/app\n\ngo 1.22\n\nrequire\tgithub.com/aquasecurity/trivy v0.69.4\n\nexclude(\n\tgithub.com/aquasecurity/trivy v0.69.4\n)\n",
			"go.sum": "github.com/aquasecurity/trivy v0.69.4/go.mod h1:BBBB=\n",
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := projectWith(t, files)
			check, err := gateCheck(t, dir)
			require.ErrorIs(t, err, ErrThresholdExceeded)
			var found *incident.Finding
			for i, f := range check.Findings {
				if f.Severity == incident.SevCritical {
					found = &check.Findings[i]
				}
			}
			require.NotNil(t, found, "the required version is reported")
			require.Contains(t, found.Title, "github.com/aquasecurity/trivy v0.69.4")
			require.Contains(t, found.Remediation, "go.mod also excludes")
		})
	}
}
