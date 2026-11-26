package packagecheck

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

type setupPyWant struct {
	known   bool
	names   []string // default names, sorted
	groups  []string // group names, sorted
	files   []string // dependency files named
	pins    []string
	declare bool
}

func sortedCopy(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	if out == nil {
		out = []string{}
	}
	return out
}

// setup.py is never run. Literal install_requires and extras_require
// lists (strings in a list or tuple, or a name bound only to such lists)
// are read; anything else leaves the names unknown. String literals that
// name a .txt or .in file are the files the script reads its
// dependencies from.
func TestParseSetupPyLiteralDependencies(t *testing.T) {
	for _, tc := range []struct {
		name, src string
		want      setupPyWant
	}{
		{"literal list", "from setuptools import setup\nsetup(name='demo', install_requires=['requests>=2', \"idna==3.7\"])\n",
			setupPyWant{known: true, names: []string{"idna", "requests"}, pins: []string{"idna 3.7"}, declare: true}},
		{"tuple with trailing comma", "setup(\n    install_requires=(\n        'a',\n        'b; python_version<\"3.8\"',\n    ),\n)\n",
			setupPyWant{known: true, names: []string{"a", "b"}, declare: true}},
		{"implicit concatenation", "setup(install_requires=['req' 'uests==2.0'])\n",
			setupPyWant{known: true, names: []string{"requests"}, pins: []string{"requests 2.0"}, declare: true}},
		{"name bound to a list", "REQS = ['requests>=2', 'idna']\nsetup(install_requires=REQS)\n",
			setupPyWant{known: true, names: []string{"idna", "requests"}, declare: true}},
		{"conditional assignments", "import sys\nif sys.platform == 'win32':\n    install_requires = ['pywin32']\nelse:\n    install_requires = ['uvloop']\nsetup(install_requires=install_requires)\n",
			setupPyWant{known: true, names: []string{"pywin32", "uvloop"}, declare: true}},
		{"bound list changed later", "REQS = ['a']\nREQS.append('b')\nsetup(install_requires=REQS)\n",
			setupPyWant{names: []string{}, declare: true}},
		{"bound list extended", "REQS = ['a']\nREQS += ['b']\nsetup(install_requires=REQS)\n",
			setupPyWant{names: []string{}, declare: true}},
		{"concatenated value", "setup(install_requires=['a'] + EXTRA)\n",
			setupPyWant{names: []string{"a"}, declare: true}},
		{"computed element", "setup(install_requires=['a', dep])\n",
			setupPyWant{names: []string{"a"}, declare: true}},
		{"f-string element", "V = '1.0'\nsetup(install_requires=[f'pkg=={V}'])\n",
			setupPyWant{names: []string{}, declare: true}},
		{"unbound name", "from meta import REQS\nsetup(install_requires=REQS)\n",
			setupPyWant{names: []string{}, declare: true}},
		{"extras literal", "setup(install_requires=['a'], extras_require={'dev': ['pytest'], \"docs\": ('sphinx',)})\n",
			setupPyWant{known: true, names: []string{"a"}, groups: []string{"pytest", "sphinx"}, declare: true}},
		{"extras computed beside a literal default", "setup(install_requires=['a'], extras_require=EXTRAS)\n",
			setupPyWant{known: true, names: []string{"a"}, declare: true}},
		{"only computed extras", "setup(extras_require=EXTRAS)\n",
			setupPyWant{names: []string{}, declare: true}},
		{"keyword unpacking", "import json\nfrom setuptools import setup\nsetup(**json.load(open('meta.json')))\n",
			setupPyWant{names: []string{}, declare: true}},
		{"reads requirements.txt", "with open('requirements.txt') as f:\n    reqs = f.read().splitlines()\nsetup(install_requires=reqs)\n",
			setupPyWant{names: []string{}, files: []string{"requirements.txt"}, declare: true}},
		{"joins a path", "import os\nhere = os.path.dirname(__file__)\nsetup(install_requires=read(os.path.join(here, 'requirements', 'base.txt')))\n",
			setupPyWant{names: []string{}, files: []string{"requirements/base.txt"}, declare: true}},
		{"path operator", "from pathlib import Path\nreqs = (Path(__file__).parent / \"requirements\" / \"main.in\").read_text()\nsetup(install_requires=reqs.split())\n",
			setupPyWant{names: []string{}, files: []string{"requirements/main.in"}, declare: true}},
		{"keywords only in text", "\"\"\"setup(install_requires=['x'])\"\"\"\n# install_requires=['y']\nsetup(name='z')\n",
			setupPyWant{known: true, names: []string{}}},
		{"shim", "from setuptools import setup\nsetup()\n", setupPyWant{known: true, names: []string{}}},
		{"comparison is not an assignment", "REQS = ['a']\nif REQS == ['b']:\n    pass\nsetup(install_requires=REQS)\n",
			setupPyWant{names: []string{}, declare: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info, err := parseSetupPyManifest([]byte(tc.src))
			require.NoError(t, err)
			require.Equal(t, tc.want.known, !info.unknown, "names known")
			require.Equal(t, sortedCopy(tc.want.names), sortedCopy(info.defaultNames))
			require.Equal(t, sortedCopy(tc.want.groups), sortedCopy(info.groupNames))
			require.Equal(t, sortedCopy(tc.want.files), sortedCopy(info.files))
			require.Equal(t, sortedCopy(tc.want.pins), sortedCopy(pinSummary(info.pins)))
			require.Equal(t, tc.want.declare, info.declares())
		})
	}
}

// pyproject.toml and setup.cfg name the files a dynamic dependency list
// is read from.
func TestManifestsNameTheirDependencyFiles(t *testing.T) {
	info, err := parsePyprojectManifest([]byte("[project]\nname = \"x\"\ndynamic = [\"dependencies\"]\n[tool.setuptools.dynamic]\ndependencies = {file = [\"requirements.txt\", \"requirements/extra.txt\"]}\n"))
	require.NoError(t, err)
	require.True(t, info.unknown)
	require.Equal(t, []string{"requirements.txt", "requirements/extra.txt"}, info.files)

	info, err = parsePyprojectManifest([]byte("[project]\nname = \"x\"\ndynamic = [\"dependencies\"]\n[tool.setuptools.dynamic.dependencies]\nfile = \"requirements.txt\"\n"))
	require.NoError(t, err)
	require.Equal(t, []string{"requirements.txt"}, info.files)

	info, err = parseSetupCfgManifest([]byte("[options]\ninstall_requires = file: requirements.txt, requirements/base.txt\n"))
	require.NoError(t, err)
	require.True(t, info.unknown)
	require.Equal(t, []string{"requirements.txt", "requirements/base.txt"}, info.files)
}

// A requirements file stands for a manifest whose dependency names cannot
// be read only when the manifest names it as their source; a pinned file
// the manifest does not name says nothing about what it installs.
func TestUnknownDependencyNamesNeedTheNamedFile(t *testing.T) {
	for _, tc := range []struct {
		name    string
		files   map[string]string
		covered bool
		detail  string
	}{
		{"setup.py literal list beside an unrelated pin", map[string]string{
			"setup.py": "from setuptools import setup\nsetup(name='demo', install_requires=['requests>=2'])\n", "requirements.txt": "black==24.1.0\n"},
			false, "requirements.txt does not pin requests"},
		{"setup.py literal list pinned", map[string]string{
			"setup.py": "from setuptools import setup\nsetup(name='demo', install_requires=['requests>=2'])\n", "requirements.txt": "requests==2.31.0\n"},
			true, ""},
		{"dynamic dependencies beside an unrelated pin", map[string]string{
			"pyproject.toml": "[project]\nname = \"demo\"\ndynamic = [\"dependencies\"]\n", "requirements.txt": "black==24.1.0\n"},
			false, "does not name requirements.txt as their source"},
		{"dynamic dependencies from the pinned file", map[string]string{
			"pyproject.toml":   "[project]\nname = \"demo\"\ndynamic = [\"dependencies\"]\n[tool.setuptools.dynamic]\ndependencies = {file = [\"requirements.txt\"]}\n",
			"requirements.txt": "requests==2.31.0\n"},
			true, ""},
		{"keyword unpacking beside an unrelated pin", map[string]string{
			"setup.py": "import json\nfrom setuptools import setup\nsetup(**json.load(open('meta.json')))\n", "requirements.txt": "black==24.1.0\n"},
			false, "does not name requirements.txt as their source"},
		{"setup.py reads the pinned file", map[string]string{
			"setup.py":         "with open('requirements.txt') as f:\n    reqs = f.read().splitlines()\nsetup(install_requires=reqs)\n",
			"requirements.txt": "requests==2.31.0\n"},
			true, ""},
		{"setup.py reads a file that is not fully pinned", map[string]string{
			"setup.py":         "with open('requirements.txt') as f:\n    reqs = f.read().splitlines()\nsetup(install_requires=reqs)\n",
			"requirements.txt": "requests==2.31.0\nflask\n"},
			false, "has entries without one exact version"},
		{"named file plus a literal it does not pin", map[string]string{
			"setup.py":         "setup(install_requires=open('requirements.txt').read().split() + ['flask'])\n",
			"requirements.txt": "requests==2.31.0\n"},
			false, "does not pin flask"},
		{"setup.cfg file: directive", map[string]string{
			"setup.cfg": "[options]\ninstall_requires = file: requirements.txt\n", "requirements.txt": "requests==2.31.0\n"},
			true, ""},
		{"pip-tools input compiles to the same stem", map[string]string{
			"requirements.in": "-r base.in\n", "base.in": "requests\n", "requirements.txt": "requests==2.31.0\n"},
			true, ""},
		{"pip-tools input beside another compiled name", map[string]string{
			"requirements.in": "-r base.in\n", "base.in": "requests\n", "requirements-lock.txt": "requests==2.31.0\n"},
			false, "does not name requirements-lock.txt as their source"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := manifestEntries(t, tc.files, nil)
			var entry UnsupportedEvidence
			listed := false
			for _, u := range got {
				if u.IsManifest() {
					entry, listed = u, true
				}
			}
			require.Equal(t, !tc.covered, listed, "%+v", got)
			if listed {
				require.Contains(t, entry.Detail, tc.detail)
			}
		})
	}
}
