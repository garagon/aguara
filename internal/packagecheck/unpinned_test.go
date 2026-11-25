package packagecheck

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/garagon/aguara/internal/intel"
	"github.com/stretchr/testify/require"
)

// A requirement counts as unpinned only when nothing in the same target
// pins that name, and constraints never count: pip installs the pinned
// version (which was checked), and a constraint installs nothing.
func TestRunnerUnpinnedCountsOnlyUncoveredRequirements(t *testing.T) {
	root := t.TempDir()
	write := func(name, content string) {
		require.NoError(t, os.WriteFile(filepath.Join(root, name), []byte(content), 0o600))
	}
	write("requirements.txt", "Requests\nflask>=3\nclick==8.1.7\n-c constraints.txt\n")
	write("constraints.txt", "requests==2.31.0\nurllib3<2\n")

	targets, err := Discover(root, []string{intel.EcosystemPyPI})
	require.NoError(t, err)
	res, err := (&Runner{Matcher: intel.NewMatcher(intel.Snapshot{})}).Run(targets)
	require.NoError(t, err)
	byName := map[string]EcosystemResult{}
	for _, e := range res.Ecosystems {
		byName[e.Source] = e
	}
	// requests is pinned by the -c constraint; urllib3<2 is a constraint;
	// only flask>=3 is an unpinned requirement.
	require.Equal(t, 1, byName["requirements.txt"].Unpinned)
	require.Zero(t, byName["constraints.txt"].Unpinned)
}
