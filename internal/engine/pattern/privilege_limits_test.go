package pattern

import (
	"strings"
	"testing"

	"github.com/garagon/aguara/internal/scanner"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
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

func TestPrivilegePositionCursor(t *testing.T) {
	content := "\u03b1\u03b2: x\nnext: SETUID"
	lines := []int{0, 8}
	var cursor privilegePosition
	for _, tc := range []struct{ line, column, offset int }{
		{1, 1, 0}, {1, 3, 4}, {1, 5, 6}, {2, 1, 8}, {2, 7, 14},
	} {
		offset, ok := cursor.locate(&yaml.Node{Line: tc.line, Column: tc.column}, content, lines)
		require.True(t, ok)
		require.Equal(t, tc.offset, offset)
	}
	for _, node := range []yaml.Node{
		{Line: 1, Column: 1}, {Line: 2, Column: 1}, {Line: 0, Column: 1},
		{Line: 3, Column: 1}, {Line: 2, Column: 0}, {Line: 2, Column: 100},
	} {
		_, ok := cursor.locate(&node, content, lines)
		require.False(t, ok)
	}
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
