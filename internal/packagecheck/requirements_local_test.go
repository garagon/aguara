package packagecheck

import (
	"path/filepath"
	"testing"

	"github.com/garagon/aguara/internal/intel"
	"github.com/stretchr/testify/require"
)

const pyprojectRequests = "[project]\nname = \"demo\"\nversion = \"1\"\ndependencies = [\"requests>=2\"]\n"

// Installing from a requirements file with a local entry builds that
// project and resolves its dependencies, so the manifest it installs is
// covered only if that same file (with its includes) pins them, whatever
// another file pins. A file with a local entry never covers a manifest
// itself, and -c pins count only for names the file requires.
func TestRequirementsCoverageWithLocalInstallsAndConstraints(t *testing.T) {
	for _, tc := range []struct {
		name    string
		files   map[string]string
		listed  []string
		detail  string
		unpinne map[string]int
	}{
		{name: "editable install beside a pinned file", files: map[string]string{
			"pyproject.toml": pyprojectRequests, "requirements-dev.txt": "-e .\npytest==8.2.0\n", "requirements.txt": "requests==2.31.0\n"},
			listed: []string{"pyproject.toml"}, detail: "requirements-dev.txt installs it as a local project and does not pin requests"},
		{name: "editable install that includes the pins", files: map[string]string{
			"pyproject.toml": pyprojectRequests, "requirements-dev.txt": "-e .\n-r requirements.txt\npytest==8.2.0\n", "requirements.txt": "requests==2.31.0\n"}},
		{name: "editable install with its pins and no other file", files: map[string]string{
			"pyproject.toml": pyprojectRequests, "requirements.txt": "-e .\nrequests==2.31.0\n"},
			listed: []string{"pyproject.toml"}, detail: "installs a local project"},
		{name: "path entry for a subproject", files: map[string]string{
			"pkg/pyproject.toml": pyprojectRequests, "requirements-dev.txt": "./pkg[dev]\n", "requirements.txt": "requests==2.31.0\n"},
			listed: []string{"pkg/pyproject.toml"}, detail: "requirements-dev.txt installs it as a local project"},
		{name: "file URL for a subproject, pinned", files: map[string]string{
			"pkg/pyproject.toml": pyprojectRequests, "requirements-dev.txt": "demo @ file:./pkg\n-r requirements.txt\n", "requirements.txt": "requests==2.31.0\n"}},
		{name: "editable install from a requirements directory, run from the root", files: map[string]string{
			"pyproject.toml": pyprojectRequests, "requirements/dev.txt": "-e .\n", "requirements.txt": "requests==2.31.0\n-r requirements/dev.txt\n"},
			listed: []string{"pyproject.toml"}, detail: "requirements.txt installs a local project"},
		{name: "constraints-only file", files: map[string]string{
			"pyproject.toml": pyprojectRequests, "requirements.txt": "-c constraints.txt\n", "constraints.txt": "requests==2.31.0\n"},
			listed: []string{"pyproject.toml"}, detail: "requirements.txt does not pin requests"},
		{name: "constraint pins a required name", files: map[string]string{
			"pyproject.toml": pyprojectRequests, "requirements.txt": "requests\n-c constraints.txt\n", "constraints.txt": "requests==2.31.0\n"}},
		{name: "constraint pins a name an include requires", files: map[string]string{
			"pyproject.toml": pyprojectRequests, "requirements.txt": "-r base.txt\n-c constraints.txt\n", "base.txt": "requests\n", "constraints.txt": "requests==2.31.0\n"}},
		// Local entries that are not a project directory inside the checked
		// directory install something whose dependencies nothing pins.
		{name: "local wheel", files: map[string]string{"requirements-dev.txt": "./dist/demo-1.0-py3-none-any.whl\n", "requirements.txt": "requests==2.31.0\n"},
			unpinne: map[string]int{"requirements-dev.txt": 1}},
		{name: "editable VCS checkout", files: map[string]string{"requirements.txt": "-e git+https://example.invalid/demo.git#egg=demo\nrequests==2.31.0\n"},
			unpinne: map[string]int{"requirements.txt": 1}},
		// Checked from app/, so the keys below are relative to it.
		{name: "project outside the checked directory", files: map[string]string{"app/requirements.txt": "-e ../..\nrequests==2.31.0\n", "pyproject.toml": pyprojectRequests},
			unpinne: map[string]int{"requirements.txt": 1}},
		{name: "editable project directory", files: map[string]string{"pyproject.toml": pyprojectRequests, "requirements.txt": "-e .\nrequests==2.31.0\n"},
			listed: []string{"pyproject.toml"}, unpinne: map[string]int{"requirements.txt": 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for name, content := range tc.files {
				writeFile(t, filepath.Join(root, filepath.FromSlash(name)), content)
			}
			checked := root
			if tc.name == "project outside the checked directory" {
				checked = filepath.Join(root, "app")
			}
			targets, err := Discover(checked, nil)
			require.NoError(t, err)
			found, err := DiscoverUnevaluated(checked, nil)
			require.NoError(t, err)
			run, err := (&Runner{Matcher: intel.NewMatcher(intel.Snapshot{})}).Run(targets)
			require.NoError(t, err)
			listed := ManifestsWithoutLockfile(checked, found.Manifests, CoveringLockfiles(targets, found.Unsupported), run.Requirements)
			var names []string
			for _, u := range listed {
				rel, err := filepath.Rel(checked, u.Path)
				require.NoError(t, err)
				names = append(names, filepath.ToSlash(rel))
				require.Contains(t, u.Detail, tc.detail)
			}
			require.Equal(t, tc.listed, names)
			for file, want := range tc.unpinne {
				found := false
				for _, e := range run.Ecosystems {
					if e.Path == filepath.Join(checked, filepath.FromSlash(file)) {
						require.Equal(t, want, e.Unpinned, "unpinned entries in %s", file)
						found = true
					}
				}
				require.True(t, found, "%s was read", file)
			}
		})
	}
}
