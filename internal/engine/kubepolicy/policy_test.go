package kubepolicy

import (
	"context"
	"strings"
	"testing"

	"github.com/garagon/aguara/internal/scanner"
	"github.com/stretchr/testify/require"
)

func TestEvidenceAndLocations(t *testing.T) {
	content := "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - name: token-must-not-be-copied\n    securityContext:\n      capabilities: {add: ['SETUID', SETGID]} # unrelated-secret\n"
	for _, input := range []string{content, strings.ReplaceAll(content, "\n", "\r\n")} {
		findings, err := New().Analyze(context.Background(), &scanner.Target{RelPath: "config.yaml", Content: []byte(input)})
		require.NoError(t, err)
		require.Len(t, findings, 1)
		f := findings[0]
		require.Equal(t, 7, f.Line)
		require.Equal(t, 28, f.Column)
		require.Equal(t, "spec.containers[0].securityContext.capabilities.add: SETUID, SETGID", f.MatchedText)
		require.Empty(t, f.Context)
		require.NotContains(t, f.MatchedText, "secret")
		require.NotContains(t, f.MatchedText, "token")
	}
}

func TestCancellationAndNoIO(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := New().Analyze(ctx, &scanner.Target{RelPath: "pod.yaml"})
	require.ErrorIs(t, err, context.Canceled)
	findings, err := New().Analyze(context.Background(), &scanner.Target{
		Path: "/nonexistent/pod.yaml", RelPath: "pod.yaml",
		Content: []byte("apiVersion: v1\nkind: Pod\nspec: {}\n"),
	})
	require.NoError(t, err)
	require.Empty(t, findings)
}
