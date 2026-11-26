package packagecheck

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/garagon/aguara/internal/intel"
	"github.com/stretchr/testify/require"
)

// Environment markers are checked against the PEP 508 marker grammar as
// pip 25.2 and 26.0 (packaging 25.0 and 26.0) parse it. The expected
// results were produced by packaging's own Marker() on each string.
func TestPEP508MarkerGrammar(t *testing.T) {
	for marker, ok := range map[string]bool{
		"python_version >= '3'":     true,
		`python_version>"3.8"`:      true,
		"python_version >= '3' and": false,
		"os_name == 'nt' or":        false,
		";":                         false,
		"and":                       false,
		"python_version":            false,
		"python_version >= '3' and sys_platform == 'linux'":           true,
		"(python_version >= '3' or os_name == 'nt') and extra == 'x'": true,
		"( python_version >= '3' )":                                   true,
		"python_version >= '3' and (os_name == 'nt'":                  false,
		"extra == 'test'":                               true,
		"extras == 'test'":                              true,
		"'linux' in sys_platform":                       true,
		"'linux' not in sys_platform":                   true,
		"'linux' not  in sys_platform":                  true,
		"'linux' notin sys_platform":                    false,
		"sys.platform == 'linux'":                       true,
		"os.name == 'nt'":                               true,
		"platform.python_implementation == 'CPython'":   true,
		"python_implementation == 'CPython'":            true,
		"platform_python_implementation == 'CPython'":   true,
		"implementation_name == 'cpython'":              true,
		"implementation_version >= '3'":                 true,
		"platform_release >= '5'":                       true,
		"platform_system == 'Linux'":                    true,
		"platform_version == '1'":                       true,
		"platform_machine == 'x86_64'":                  true,
		"python_full_version >= '3.8.1'":                true,
		"dependency_groups == 'x'":                      true,
		"python_versions >= '3'":                        false,
		"foo == 'bar'":                                  false,
		"'a' == 'b'":                                    true,
		"'a'=='b'":                                      true,
		"python_version>='3'and os_name=='nt'":          true,
		"python_version >= 3":                           false,
		"python_version = '3'":                          false,
		"python_version ~= '3.8'":                       true,
		"python_version === '3.8'":                      true,
		"python_version <> '3'":                         false,
		"python_version >= '3' or":                      false,
		"python_version >= '3' xor os_name == 'nt'":     false,
		"python_version >= '3' AND os_name == 'nt'":     false,
		"\tpython_version >= '3'\t":                     true,
		`python_version >= "3'`:                         false,
		"python_version >= ''":                          true,
		"(python_version >= '3')":                       true,
		"((python_version >= '3'))":                     true,
		"()":                                            false,
		"python_version >= '3' )":                       false,
		"python_version >= '3' ; os_name == 'nt'":       false,
		"python_version >= '3' # comment":               false,
		"python_version in '3.8 3.9'":                   true,
		"python_version not in '3.8 3.9'":               true,
		"python_version in'3.8'":                        true,
		"python_version >= '3' and not os_name == 'nt'": false,
		"python_version>='3'or(os_name=='nt')":          true,
		"python_version >= '3'and os_name == 'nt'":      true,
		"python_version >= '3' andos_name == 'nt'":      false,
	} {
		err := checkPEP508Marker(marker)
		require.Equalf(t, ok, err == nil, "marker %q: %v", marker, err)
	}
}

// Requirement spellings checked against what pip 25.2 and 26.0 build from
// the same line (InstallRequirement, parser only). A line pip accepts is
// read with no skipped line; a line pip rejects is skipped, but an exact
// pin at its start is still kept for matching.
func TestRequirementSpellingsAsPipReadsThem(t *testing.T) {
	const whl = "https://files.pythonhosted.org/packages/aa/bb/six-1.0-py2.py3-none-any.whl"
	for _, tc := range []struct {
		content string
		ref     string
		skipped bool
	}{
		// pip accepts these.
		{"six==1.0;", "six 1.0", false},
		{"six == 1.0 ;\t", "six 1.0", false},
		{"six===1.0 ;", "six 1.0", false},
		{"six[extra]==1.0;", "six 1.0", false},
		{"six (==1.0);", "six 1.0", false},
		{"six==1.0 \\\n;", "six 1.0", false},
		{"six==1.0; --hash=sha256:abc", "six 1.0", false},
		{whl + ";", "six 1.0", false},
		{whl + " ;", "six 1.0", false},
		{"six @ " + whl + " ;", "six 1.0", false},
		{"six==1.0,", "six 1.0", false},
		{"six===1.0,", "six 1.0", false},
		{"six (==1.0,)", "six 1.0", false},
		{"six==1.0, ;python_version>'3'", "six 1.0", false},
		{"six==1.0 ; ", "six 1.0", false},
		{"six==1.0, # c", "six 1.0", false},
		{"six==1.0,\t", "six 1.0", false},
		{"six (==1.0) ;", "six 1.0", false},
		{"six>=1.0,", "six (>=1.0,)", false},
		{"six[]==1.0", "six 1.0", false},
		// pip rejects these; the pin is kept.
		{"six==1.0,,", "six 1.0", true},
		{"six==1.0, ,", "six 1.0", true},
		{"six[extra,]==1.0", "six 1.0", true},
		{"six[,extra]==1.0", "six 1.0", true},
		{"six==1.0; python_version >= '3' and", "six 1.0", true},
		{"six==1.0;;", "six 1.0", true},
		{"six==1.0 ;; python_version>'3'", "six 1.0", true},
		{"six==1.0; os_name == 'nt' or", "six 1.0", true},
		// pip rejects these and they pin nothing.
		{"six ,==1.0", "", true},
		{"six==,1.0", "", true},
	} {
		t.Run(tc.content, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, filepath.Join(root, "requirements.txt"), tc.content+"\n")
			parsed, err := parseRequirementsTarget(Target{Ecosystem: intel.EcosystemPyPI, Path: filepath.Join(root, "requirements.txt"), Source: "requirements.txt", Root: root}, newRequirementsCache())
			require.NoError(t, err)
			want := []string{}
			if tc.ref != "" {
				want = []string{tc.ref}
			}
			require.Equal(t, want, refSummary(parsed.refs))
			require.Equal(t, tc.skipped, parsed.syntax != nil, "skipped line: %v", parsed.syntax)
		})
	}
}

// Property: whatever pip-valid (or pip-rejected) decoration surrounds an
// exact pin, the pin is matched. Decorations combine extras, specifier
// spellings, markers, trailing options, comments, continuations and
// white space.
func TestExactPinSurvivesEveryDecoration(t *testing.T) {
	m := intel.NewMatcher(intel.Snapshot{Records: []intel.Record{{
		ID: "MAL-DECOR", Ecosystem: intel.EcosystemPyPI, Name: "evil-pkg", Kind: intel.KindMalicious, Versions: []string{"1.0"},
	}}})
	names := []string{"evil-pkg", "Evil_Pkg"}
	extras := []string{"", "[a]", "[ a , b ]", "[]", "[a,]"}
	specs := []string{"==1.0", " == 1.0", "==1.0.0", "(==1.0)", " (== 1.0 )", "===1.0", "==1.0,", "== 1.0 ,", "(==1.0,)", "==1.0,,", "==1.0,!=2.0"}
	markers := []string{"", ";", " ;", " ; ", "; python_version >= '3'", ";python_version>'3'", " ; os_name == 'nt' and", ";;"}
	trails := []string{"", " --hash=sha256:00", " \\\n    --hash=sha256:00", " \\\n", "  # comment", "\t", " -r other.txt", " --frobnicate"}
	root := t.TempDir()
	path := filepath.Join(root, "requirements.txt")
	runner := &Runner{Matcher: m}
	cases := 0
	for i, name := range names {
		for _, extra := range extras {
			for k, spec := range specs {
				for _, marker := range markers {
					for j, trail := range trails {
						if extra != "" && (i+j+k)%3 != 0 {
							continue // keep the product to a few thousand lines
						}
						line := name + extra + spec + marker + trail
						if strings.Contains(marker, ";") && strings.HasPrefix(trail, " \\") && strings.HasSuffix(trail, "\n") {
							line = name + extra + spec + trail + marker
						}
						require.NoError(t, os.WriteFile(path, []byte(line+"\n"), 0o600))
						res, err := runner.Run([]Target{{Ecosystem: intel.EcosystemPyPI, Path: path, Source: "requirements.txt", Root: root}})
						require.NoError(t, err, "line %q", line)
						require.Lenf(t, res.Hits, 1, "line %q: the pin must be matched", line)
						cases++
					}
				}
			}
		}
	}
	require.Greater(t, cases, 1000, fmt.Sprint(cases))
}
