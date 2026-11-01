package kubeconfig

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const pod = `{"apiVersion":"v1","kind":"Pod","spec":{"containers":[{"name":"app","securityContext":{"capabilities":{"add":["SETUID","SETGID"]}}}]}}`

func TestPositionCursor(t *testing.T) {
	content := "\u03b1\u03b2: x\nnext: SETUID"
	lines := []int{0, 8}
	var cursor position
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

func TestIdentitySpans(t *testing.T) {
	for _, content := range []string{pod, "---\n" + pod, "---\r\n" + pod,
		strings.Replace(pod, `"name":"app"`, `"name":"caf\u00e9"`, 1),
		strings.Replace(pod, `"name":"app"`, `"name":"café"`, 1),
		strings.Replace(pod, `"SETUID"`, `"\u0053ETUID"`, 1)} {
		doc, err := Parse(context.Background(), content, ".yaml")
		require.NoError(t, err)
		require.NotNil(t, doc)
		result := doc.IdentityCapabilities()
		require.Equal(t, Supported, result.Status)
		require.Len(t, result.Grants, 1)
		grant := result.Grants[0]
		require.Equal(t, []string{"SETUID", "SETGID"}, grant.Capabilities)
		require.Equal(t, "spec.containers[0]", grant.Path)
		require.Len(t, grant.Spans, 2)
		for _, span := range grant.Spans {
			var decoded string
			require.NoError(t, yaml.Unmarshal([]byte(content[span.Start:span.End]), &decoded))
			require.Contains(t, grant.Capabilities, decoded)
		}
		require.Equal(t, 1+strings.Count(content[:grant.Spans[0].Start], "\n"), grant.Line)
	}
}

func TestBoundedParse(t *testing.T) {
	for _, size := range []int{MaxBytes - 1, MaxBytes, MaxBytes + 1} {
		content := pod + strings.Repeat(" ", size-len(pod))
		doc, err := Parse(context.Background(), content, ".json")
		require.NoError(t, err)
		require.Equal(t, size <= MaxBytes, doc != nil)
	}
	for _, content := range []string{
		"[" + strings.Repeat("x,", 10001) + "]",
		strings.Repeat("{x: ", 70) + "x" + strings.Repeat("}", 70),
		pod + "\n---\nx: [",
		"x: &a [SETUID]\n---\n" + pod,
		"x: {<<: {}}\n---\n" + pod,
		strings.Replace(pod, `"kind":"Pod"`, `"kind":"Pod","kind":"Pod"`, 1),
		"\ufeff" + pod,
		"x: value\u0085" + pod,
		"x: value\u2028" + pod,
		"x: value\u2029" + pod,
		"x: value\r" + pod,
	} {
		doc, err := Parse(context.Background(), content, ".yaml")
		require.NoError(t, err)
		require.Nil(t, doc)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Parse(ctx, pod, ".json")
	require.ErrorIs(t, err, context.Canceled)
	_, err = Parse(&cancelDuringParse{Context: context.Background(), remaining: 8}, pod, ".json")
	require.ErrorIs(t, err, context.Canceled)
}

func TestBoundedParseExactNodeAndDepthLimits(t *testing.T) {
	// A sequence uses one document node, one sequence node, and N scalars.
	for _, nodes := range []int{9999, 10000, 10001} {
		content := "[" + strings.TrimSuffix(strings.Repeat("x,", nodes-2), ",") + "]"
		doc, err := Parse(context.Background(), content, ".yaml")
		require.NoError(t, err)
		require.Equal(t, nodes <= 10000, doc != nil, "nodes=%d", nodes)
	}
	// The document is depth zero; a scalar under N nested lists is depth N+1.
	for _, depth := range []int{63, 64, 65} {
		content := strings.Repeat("[", depth-1) + "x" + strings.Repeat("]", depth-1)
		doc, err := Parse(context.Background(), content, ".yaml")
		require.NoError(t, err)
		require.Equal(t, depth <= 64, doc != nil, "depth=%d", depth)
	}
}

type cancelDuringParse struct {
	context.Context
	remaining int
}

func (c *cancelDuringParse) Err() error {
	c.remaining--
	if c.remaining <= 0 {
		return context.Canceled
	}
	return nil
}

func TestIdentityAtomicFallback(t *testing.T) {
	for _, tail := range []string{
		"description: |\n  example\n",
		strings.Replace(pod, `["SETUID","SETGID"]`, `["SETUID",true]`, 1),
		strings.Replace(pod, `"containers":[`, `"containers":null,"unused":[`, 1),
	} {
		doc, err := Parse(context.Background(), pod+"\n---\n"+tail, ".yaml")
		require.NoError(t, err)
		require.NotNil(t, doc)
		result := doc.IdentityCapabilities()
		require.Equal(t, Unsupported, result.Status)
		require.Empty(t, result.Grants)
		require.NotEmpty(t, result.Reason)
	}
}

func TestIdentityContainerIsolation(t *testing.T) {
	content := `apiVersion: v1
kind: Pod
spec:
  containers:
  - name: first
    securityContext:
      capabilities: {add: [SETUID]}
  - name: second
    securityContext:
      capabilities: {drop: [SETUID]}
  initContainers:
  - name: init
    securityContext:
      capabilities: {add: [SETGID]}
`
	doc, err := Parse(context.Background(), content, ".yaml")
	require.NoError(t, err)
	result := doc.IdentityCapabilities()
	require.Len(t, result.Grants, 2)
	require.Equal(t, "spec.containers[0]", result.Grants[0].Path)
	require.Equal(t, 7, result.Grants[0].Line)
	require.Equal(t, "spec.initContainers[0]", result.Grants[1].Path)
	require.Equal(t, 14, result.Grants[1].Line)
}
