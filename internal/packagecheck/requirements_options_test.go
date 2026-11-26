package packagecheck

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/garagon/aguara/internal/intel"
	"github.com/stretchr/testify/require"
)

// Each case is checked against what pip 25.2 and pip 26.0 read from the
// same file with their own requirements-file parser (offline, parser
// only): which requirements it installs, which include it follows, and
// which lines it rejects. pip resolves an abbreviated long option as
// optparse does (an exact name, or a prefix of exactly one option), uses
// one parser for option lines and for the options after a requirement,
// ignores the options that do not apply to the line, and follows one
// include per line (-e before -r before -c, the first of each).
//
// Where pip rejects a line, Aguara skips that line and records it
// (syntaxLine); a requirement whose trailing options pip rejects is
// still read, since the requirement itself parsed.
func TestRequirementsOptionsResolveAsPipDoes(t *testing.T) {
	for _, tc := range []struct {
		content    string
		refs       []string
		syntaxLine int
		local      bool
	}{
		// Abbreviated long options pip accepts.
		{content: "--extra-index https://example.invalid/simple\nnum2words==0.5.15\n", refs: []string{"num2words 0.5.15"}},
		{content: "--index https://example.invalid/simple\nnum2words==0.5.15\n", refs: []string{"num2words 0.5.15"}},
		{content: "--find ./wheels\nnum2words==0.5.15\n", refs: []string{"num2words 0.5.15"}},
		{content: "--pref\nnum2words==0.5.15\n", refs: []string{"num2words 0.5.15"}},
		{content: "--use-f fast-deps\nnum2words==0.5.15\n", refs: []string{"num2words 0.5.15"}},
		{content: "--edit ./x\nnum2words==0.5.15\n", refs: []string{"num2words 0.5.15"}, local: true},
		{content: "--constr other.txt\nnum2words==0.5.15\n", refs: []string{"num2words 0.5.15", "six 1.0 [constraint]"}},
		{content: "--requirem other.txt\n", refs: []string{"six 1.0"}},
		{content: "--pypi https://example.invalid/simple\nnum2words==0.5.15\n", refs: []string{"num2words 0.5.15"}},
		{content: "--extra-index-url=https://example.invalid/simple -r other.txt\n", refs: []string{"six 1.0"}},
		{content: "--find ./x -r other.txt\n", refs: []string{"six 1.0"}},
		{content: "-r other.txt --pre\n", refs: []string{"six 1.0"}},
		{content: "--editable=./x\n", local: true},
		{content: "-e./x\n", local: true},
		{content: "-e ./x --config-settings a=b\n", local: true},
		{content: "-C foo=bar\nnum2words==0.5.15\n", refs: []string{"num2words 0.5.15"}},
		{content: "--hash=sha256:abc\nnum2words==0.5.15\n", refs: []string{"num2words 0.5.15"}},
		{content: "--no-binary=:all: --pre\nnum2words==0.5.15\n", refs: []string{"num2words 0.5.15"}},
		// pip 25.2 only (--global-option; --only names --only-binary
		// alone) and pip 26.0 only (--all-releases).
		{content: "--g x\nnum2words==0.5.15\n", refs: []string{"num2words 0.5.15"}},
		{content: "--only :all:\nnum2words==0.5.15\n", refs: []string{"num2words 0.5.15"}},
		{content: "--all :all:\nnum2words==0.5.15\n", refs: []string{"num2words 0.5.15"}},
		// Options after a requirement: read and ignored, includes too.
		{content: "num2words==0.5.15 -r other.txt\n", refs: []string{"num2words 0.5.15"}},
		{content: "num2words==0.5.15 --pre\n", refs: []string{"num2words 0.5.15"}},
		{content: "num2words==0.5.15 -e ./x\n", refs: []string{"num2words 0.5.15"}},
		{content: "num2words==0.5.15 -C foo=bar\n", refs: []string{"num2words 0.5.15"}},
		{content: "num2words==0.5.15 --g x\n", refs: []string{"num2words 0.5.15"}},
		{content: "num2words==0.5.15 --hash=sha256:abc --hash sha256:def\n", refs: []string{"num2words 0.5.15"}},
		{content: "num2words==0.5.15 --hash=sha256:abc -- --bogus\n", refs: []string{"num2words 0.5.15"}},
		// One include per line.
		{content: "-r other.txt -r other2.txt\n", refs: []string{"six 1.0"}},
		{content: "-c other.txt -r other2.txt\n", refs: []string{"idna 1.0"}},
		{content: "-c other.txt -c other2.txt\n", refs: []string{"six 1.0 [constraint]"}},
		{content: "-e ./x -r other.txt\n", local: true},
		// "--" ends the options; a lone "-" is an argument pip ignores; a
		// value-taking option takes the next word even when it starts with
		// "-".
		{content: "-- -r other.txt\n"},
		{content: "-\nnum2words==0.5.15\n", refs: []string{"num2words 0.5.15"}},
		{content: "--only-binary -r other.txt\n"},
		// Lines pip rejects: the line is skipped, the rest is read.
		{content: "--con other.txt\nnum2words==0.5.15\n", refs: []string{"num2words 0.5.15"}, syntaxLine: 1},
		{content: "--req other.txt\nnum2words==0.5.15\n", refs: []string{"num2words 0.5.15"}, syntaxLine: 1},
		{content: "--pre=1\nnum2words==0.5.15\n", refs: []string{"num2words 0.5.15"}, syntaxLine: 1},
		{content: "--no-require-hashes\nnum2words==0.5.15\n", refs: []string{"num2words 0.5.15"}, syntaxLine: 1},
		{content: "num2words==0.5.15\n--frobnicate\nsix==1.16.0\n", refs: []string{"num2words 0.5.15", "six 1.16.0"}, syntaxLine: 2},
		{content: "pkg==\nnum2words==0.5.15\n", refs: []string{"num2words 0.5.15"}, syntaxLine: 1},
		{content: "num2words==0.5.15 --unknown\n", refs: []string{"num2words 0.5.15"}, syntaxLine: 1},
		{content: "num2words==0.5.15 --install-option=x\n", refs: []string{"num2words 0.5.15"}, syntaxLine: 1},
		{content: "num2words==0.5.15 --hash\n", refs: []string{"num2words 0.5.15"}, syntaxLine: 1},
	} {
		t.Run(tc.content, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, filepath.Join(root, "other.txt"), "six==1.0\n")
			writeFile(t, filepath.Join(root, "other2.txt"), "idna==1.0\n")
			writeFile(t, filepath.Join(root, "requirements.txt"), tc.content)
			parsed, err := parseRequirementsTarget(Target{Ecosystem: intel.EcosystemPyPI, Path: filepath.Join(root, "requirements.txt"), Source: "requirements.txt", Root: root}, newRequirementsCache())
			require.NoError(t, err)
			want := tc.refs
			if want == nil {
				want = []string{}
			}
			require.Equal(t, want, refSummary(parsed.refs))
			require.Equal(t, tc.local, parsed.local, "local entry")
			if tc.syntaxLine == 0 {
				require.Nil(t, parsed.syntax, "no line is rejected")
				return
			}
			require.NotNil(t, parsed.syntax, "the rejected line is recorded")
			require.Equal(t, tc.syntaxLine, parsed.syntax.Line)
			require.Equal(t, 1, parsed.syntaxLines)
		})
	}
}

// pip's option table: every long option of the requirements-file
// parser in pip 25.2 and pip 26.0, which value-taking ones they are, and
// how prefixes resolve (exact name first, then a prefix of one option in
// either release).
func TestPipOptionPrefixes(t *testing.T) {
	for prefix, want := range map[string]string{
		"--extra-index": "--extra-index-url", "--index": "--index-url", "--in": "--index-url", "--i": "--index-url",
		"--find": "--find-links", "--f": "--find-links", "--pref": "--prefer-binary", "--use-f": "--use-feature",
		"--u": "--use-feature", "--edit": "--editable", "--ed": "--editable", "--constr": "--constraint",
		"--cons": "--constraint", "--conf": "--config-settings", "--requirem": "--requirement",
		"--require-": "--require-hashes", "--pre": "--pre", "--no-b": "--no-binary", "--no-i": "--no-index",
		"--h": "--hash", "--t": "--trusted-host", "--py": "--pypi-url", "--ex": "--extra-index-url",
		"--g": "--global-option", "--glob": "--global-option", "--only": "--only-binary", "--only-b": "--only-binary",
		"--only-f": "--only-final", "--a": "--all-releases", "--all": "--all-releases",
	} {
		opt, err := lookupPipLongOption(prefix)
		require.NoErrorf(t, err, "prefix %s", prefix)
		require.Equalf(t, want, opt.long, "prefix %s", prefix)
	}
	for _, prefix := range []string{"--req", "--requir", "--require", "--r", "--no", "--n", "--c", "--co", "--con", "--e", "--p", "--pr", "--", "--inst", "--no-r", "--frobnicate"} {
		_, err := lookupPipLongOption(prefix)
		require.Errorf(t, err, "prefix %s is ambiguous or unknown in pip", prefix)
	}
}

func TestRequirementsSyntaxErrorsInIncludesKeepTheRest(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "bad.txt"), "pkg==\nalso==2.0\n--frobnicate\n")
	writeFile(t, filepath.Join(root, "requirements.txt"), "good==1.0\n-r bad.txt\n")
	parsed, err := parseRequirementsTarget(Target{Ecosystem: intel.EcosystemPyPI, Path: filepath.Join(root, "requirements.txt"), Source: "requirements.txt", Root: root}, newRequirementsCache())
	require.NoError(t, err)
	require.Equal(t, []string{"also 2.0", "good 1.0"}, refSummary(parsed.refs))
	require.NotNil(t, parsed.syntax)
	require.Equal(t, filepath.Join(root, "bad.txt"), parsed.syntax.Path)
	require.Equal(t, 1, parsed.syntax.Line)
	require.Equal(t, 2, parsed.syntaxLines)

	refs, err := ParseRequirements(Target{Ecosystem: intel.EcosystemPyPI, Path: filepath.Join(root, "requirements.txt"), Source: "requirements.txt", Root: root})
	var syntax *RequirementsSyntaxError
	require.True(t, errors.As(err, &syntax), "ParseRequirements reports the skipped lines")
	require.Equal(t, []string{"also 2.0", "good 1.0"}, refSummary(refs), "with the entries that parsed")
	require.True(t, strings.Contains(err.Error(), "line 1"))
}
