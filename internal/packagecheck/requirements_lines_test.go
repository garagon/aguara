package packagecheck

import (
	"path/filepath"
	"testing"

	"github.com/garagon/aguara/internal/intel"
	"github.com/stretchr/testify/require"
)

// pip splits a requirements file with Python's str.splitlines(), which
// breaks lines on more than "\n". Every separator must end a line here
// too: otherwise a comment or an option value swallows a pin that pip
// installs, and the file looks clean.
var pythonLineSeparators = map[string]string{
	`\r`:     "\r",
	`\r\n`:   "\r\n",
	`\v`:     "\v",
	`\f`:     "\f",
	`\x1c`:   "\x1c",
	`\x1d`:   "\x1d",
	`\x1e`:   "\x1e",
	`U+0085`: "\u0085",
	`U+2028`: "\u2028",
	`U+2029`: "\u2029",
}

func parseRequirementsContent(t *testing.T, content string) ([]PackageRef, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "requirements.txt")
	writeFile(t, path, content)
	return ParseRequirements(Target{Ecosystem: intel.EcosystemPyPI, Path: path, Source: "requirements.txt"})
}

func requirePin(t *testing.T, refs []PackageRef, name, version string, msg string) {
	t.Helper()
	for _, r := range refs {
		if r.Name == name && r.Version == version {
			return
		}
	}
	t.Fatalf("%s: %s==%s not found in %v", msg, name, version, refSummary(refs))
}

func TestRequirementsSplitLinesLikePip(t *testing.T) {
	for label, sep := range pythonLineSeparators {
		t.Run(label, func(t *testing.T) {
			for _, content := range []string{
				"# a comment" + sep + "num2words==0.5.15\n",
				"--index-url https://pypi.org/simple" + sep + "num2words==0.5.15\n",
				"six==1.16.0 --hash=sha256:00" + sep + "num2words==0.5.15\n",
				"six==1.16.0" + sep + "num2words==0.5.15",
			} {
				refs, err := parseRequirementsContent(t, content)
				require.NoErrorf(t, err, "%q", content)
				requirePin(t, refs, "num2words", "0.5.15", label)
			}
		})
	}
}

func TestRequirementsContinuationAcrossPythonSeparators(t *testing.T) {
	for label, sep := range pythonLineSeparators {
		t.Run(label, func(t *testing.T) {
			// A backslash before any separator continues the line, as in pip.
			refs, err := parseRequirementsContent(t, "num2words==\\"+sep+"0.5.15"+sep+"-r \\"+sep+"missing.txt\n")
			require.NoError(t, err)
			requirePin(t, refs, "num2words", "0.5.15", label)
			require.Equal(t, 1, findRef(t, refs, "num2words").Line)
		})
	}
}

func TestRequirementsIncludeLinesSplitLikePip(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "inner.txt"), "num2words==0.5.15\n")
	writeFile(t, filepath.Join(root, "requirements.txt"), "# shared pins\v-r inner.txt\n")
	refs, err := ParseRequirements(Target{Ecosystem: intel.EcosystemPyPI, Path: filepath.Join(root, "requirements.txt"), Root: root})
	require.NoError(t, err)
	requirePin(t, refs, "num2words", "0.5.15", "include after \\v")
}

func TestRequirementsLineNumbersFollowPipSplitting(t *testing.T) {
	refs, err := parseRequirementsContent(t, "a==1\rb==2\r\nc==3\u2028d==4\n")
	require.NoError(t, err)
	for i, name := range []string{"a", "b", "c", "d"} {
		require.Equal(t, i+1, findRef(t, refs, name).Line, name)
	}
}

func TestRequirementsCodingDeclaration(t *testing.T) {
	// "+AAo-" is a newline and "+AD0APQ-" is "==" in UTF-7: pip, honouring
	// the declaration, reads a second requirement that UTF-8 hides in a
	// comment.
	hidden := "# -*- coding: utf-7 -*-\nsix==1.16.0 # +AAo-num2words+AD0APQ-0.5.15\n"
	refs, err := parseRequirementsContent(t, hidden)
	require.ErrorContains(t, err, "utf-7")
	require.Nil(t, refs)

	for _, content := range []string{
		"#!/usr/bin/env pip\n# coding=latin-1\nsix==1.16.0\n",
		"# vim: set fileencoding=cp1252 :\nsix==1.16.0\n",
		"#\rsix==1.16.0 # coding: utf-16\n",
		"# coding: no-such-codec\nsix==1.16.0\n",
	} {
		_, err := parseRequirementsContent(t, content)
		require.Errorf(t, err, "%q declares a non-UTF-8 encoding", content)
	}

	for _, content := range []string{
		"# -*- coding: utf-8 -*-\nsix==1.16.0\n",
		"# coding=UTF8\nsix==1.16.0\n",
		"# coding: ascii\nsix==1.16.0\n",
		"# coding: US_ASCII\nsix==1.16.0\n",
		"# coding: utf-8-sig\nsix==1.16.0\n",
		// Only the first two lines are declarations, and only when
		// they start with '#'.
		"six==1.16.0 # coding: utf-7\n",
		"six==1.16.0\nidna==3.20\n# coding: utf-7\n",
		// A UTF-8 byte-order mark wins over a declaration, as in pip.
		utf8BOM + "# coding: utf-7\nsix==1.16.0\n",
	} {
		refs, err := parseRequirementsContent(t, content)
		require.NoErrorf(t, err, "%q", content)
		requirePin(t, refs, "six", "1.16.0", content)
	}
}

func TestRequirementsRejectsNonUTF8Content(t *testing.T) {
	for _, content := range []string{
		"\xff\xfes\x00i\x00x\x00",      // UTF-16 LE with BOM
		"six==1.16.0\n\xe9tude==1.0\n", // Latin-1 byte
	} {
		_, err := parseRequirementsContent(t, content)
		require.Error(t, err)
	}
}
