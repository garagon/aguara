package pattern

import (
	"strings"
	"testing"

	"github.com/garagon/aguara/internal/scanner"
	"github.com/stretchr/testify/require"
)

func TestPrivilegeContextConservativeLimits(t *testing.T) {
	for _, content := range []string{
		"description: " + strings.Repeat("x", 2<<20) + " SETUID",
		"capabilities: {drop: [SETUID]}\nitems: [" + strings.Repeat("x,", 10001) + "]",
	} {
		target := &scanner.Target{RelPath: "config.yaml", Content: []byte(content)}
		require.Equal(t, content, privilegeWordContent(target, content))
	}
	content := "capabilities: {drop: [SETUID]}"
	target := &scanner.Target{
		RelPath: "config.yaml", Content: []byte(content),
		OriginalContent: []byte("\uff43apabilities: {drop: [SETUID]}"),
	}
	require.Equal(t, content, privilegeWordContent(target, content))
}

func TestPrivilegeCompactJSONPositions(t *testing.T) {
	content := `{"items":[` + strings.Repeat(`{"description":"SETUID and SETGID are removed","capabilities":{"drop":["SETUID"]}},`, 127) +
		`{"capabilities":{"drop":["SETUID"],"add":["SETGID"]}}]}`
	target := &scanner.Target{RelPath: "config.json", Content: []byte(content)}
	view := privilegeWordContent(target, content)
	require.Len(t, view, len(content))
	require.NotContains(t, view, "SETUID")
	require.Equal(t, 1, strings.Count(view, "SETGID"))
	require.Equal(t, strings.LastIndex(content, "SETGID"), strings.Index(view, "SETGID"))
}
