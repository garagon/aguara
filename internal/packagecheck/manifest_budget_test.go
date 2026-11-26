package packagecheck

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/garagon/aguara/internal/intel"
)

// Dependency manifests were decoded without the structure budgets the
// lockfiles have: a conda environment.yml made of one 4 MiB flow sequence
// reached about 535 MiB. Each one now runs its format's budget before it is
// decoded, and a manifest over it is reported unread, its dependencies
// unknown, with a failure that matches ErrBudget.
func TestManifestsRejectOverBudgetDocuments(t *testing.T) {
	wideJSON := func(section string) string {
		return `{"` + section + `":{"a":"1.0.0"},"x":[` + strings.Repeat("0,", maxContainerMembers) + `0]}`
	}
	deepXML := strings.Repeat("<ItemGroup>", maxXMLDepth+1) + strings.Repeat("</ItemGroup>", maxXMLDepth+1)
	for name, content := range map[string]string{
		"package.json":    wideJSON("dependencies"),
		"composer.json":   wideJSON("require"),
		"environment.yml": "dependencies: [" + strings.Repeat("a, ", maxCondaYAMLNodes/2) + "a]\n",
		"pyproject.toml":  "[project]\ndependencies = [" + strings.Repeat(`"a",`, maxTOMLExpressionNodes) + "]\n",
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, name)
			writeFile(t, path, content)
			m, ok := readManifestAt(path, root, nil, &discoveryBudget{})
			require.True(t, ok, "an over-budget manifest is still reported")
			require.True(t, m.Unreadable)
			require.True(t, m.Declares, "its dependencies are unknown")
			require.ErrorIs(t, m.Failure, ErrBudget)
		})
	}

	t.Run("Directory.Packages.props", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, filepath.Join(root, "Directory.Packages.props"), "<Project>"+deepXML+"</Project>")
		project := filepath.Join(root, "app.csproj")
		writeFile(t, project, `<Project><ItemGroup><PackageReference Include="A" /></ItemGroup></Project>`)
		_, err := ParseNuGet(Target{Ecosystem: intel.EcosystemNuGet, Path: project, Source: "csproj", Root: root})
		require.ErrorIs(t, err, ErrBudget)
	})
}

// Every count limit of the dependency-file parsers matches ErrBudget, so a
// caller can tell a file it did not evaluate from a malformed one.
func TestBudgetErrorsMatchErrBudget(t *testing.T) {
	for name, err := range map[string]error{
		"entries":    errEntryLimit("x"),
		"nodes":      checkJSONNodeBudget([]byte("["+strings.Repeat("[", maxStructuredNodes)), "x"),
		"members":    checkJSONNodeBudget([]byte("["+strings.Repeat("0,", maxContainerMembers)+"0]"), "x"),
		"yaml nodes": checkYAMLNodeBudgetLimit([]byte(strings.Repeat("- a\n", 10)), "x", 5),
		"xml depth":  checkXMLBudget([]byte(strings.Repeat("<a>", maxXMLDepth+1)), "x"),
		"toml":       checkTOMLNodeBudget([]byte("a = ["+strings.Repeat("1,", maxTOMLExpressionNodes)+"1]\n"), "x"),
	} {
		require.ErrorIs(t, err, ErrBudget, name)
	}
	require.False(t, errors.Is(errors.New("parse x: invalid JSON"), ErrBudget))
}
