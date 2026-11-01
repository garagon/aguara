package scanner

import (
	"context"
	"sync"
	"testing"

	"github.com/garagon/aguara/internal/kubeconfig"
	"github.com/stretchr/testify/require"
)

const privilegePod = `{"apiVersion":"v1","kind":"Pod","spec":{"containers":[{"securityContext":{"capabilities":{"add":["SETUID"]}}}]}}`

func TestPrivilegeAnalysisSharedPerTarget(t *testing.T) {
	target := &Target{RelPath: "pod.json", Content: []byte(privilegePod)}
	first, err := target.PrivilegeAnalysis(context.Background())
	require.NoError(t, err)
	require.NotNil(t, first)
	require.Equal(t, kubeconfig.Supported, first.Identity.Status)
	require.Len(t, first.Identity.Grants, 1)
	require.Len(t, first.MaskedSpans, 1)
	ctx := &privilegeCountingContext{Context: context.Background()}
	again, err := target.PrivilegeAnalysis(ctx)
	require.NoError(t, err)
	require.Same(t, first, again)
	require.LessOrEqual(t, ctx.calls, 2, "a cached read must not traverse the YAML tree again")

	other := &Target{RelPath: "pod.json", Content: []byte(`{"capabilities":{"drop":["SETUID"]}}`)}
	result, err := other.PrivilegeAnalysis(context.Background())
	require.NoError(t, err)
	require.NotSame(t, first, result)
	require.Empty(t, result.Identity.Grants)
	require.Len(t, result.MaskedSpans, 1)
}

func TestPrivilegeAnalysisConcurrentReaders(t *testing.T) {
	target := &Target{RelPath: "pod.json", Content: []byte(privilegePod)}
	results := make([]*kubeconfig.PrivilegeAnalysis, 8)
	errors := make([]error, len(results))
	var wg sync.WaitGroup
	for i := range results {
		wg.Go(func() { results[i], errors[i] = target.PrivilegeAnalysis(context.Background()) })
	}
	wg.Wait()
	require.NotNil(t, results[0])
	for i := range results {
		require.NoError(t, errors[i])
		require.Same(t, results[0], results[i])
	}
}

func TestPrivilegeAnalysisCancellationDoesNotPoisonTarget(t *testing.T) {
	for _, during := range []bool{false, true} {
		target := &Target{RelPath: "pod.json", Content: []byte(privilegePod)}
		ctx := &privilegeCountingContext{Context: context.Background(), cancelAt: 1}
		if during {
			ctx.cancelAt = 8
		}
		result, err := target.PrivilegeAnalysis(ctx)
		require.ErrorIs(t, err, context.Canceled)
		require.Nil(t, result)
		result, err = target.PrivilegeAnalysis(context.Background())
		require.NoError(t, err)
		require.Equal(t, kubeconfig.Supported, result.Identity.Status)
		cancelled, cancel := context.WithCancel(context.Background())
		cancel()
		result, err = target.PrivilegeAnalysis(cancelled)
		require.ErrorIs(t, err, context.Canceled, "cached evidence must not hide cancellation")
		require.Nil(t, result)
	}
}

func TestPrivilegeAnalysisUnsupportedMemoAndSourceGuards(t *testing.T) {
	for _, target := range []*Target{
		{RelPath: "pod.json", Content: []byte(privilegePod + "[")},
		{RelPath: "README.md", Content: []byte(privilegePod)},
		{RelPath: "pod.json", Content: []byte(privilegePod), OriginalContent: []byte("different original")},
	} {
		result, err := target.PrivilegeAnalysis(context.Background())
		require.NoError(t, err)
		require.Nil(t, result)
		ctx := &privilegeCountingContext{Context: context.Background()}
		result, err = target.PrivilegeAnalysis(ctx)
		require.NoError(t, err)
		require.Nil(t, result)
		require.LessOrEqual(t, ctx.calls, 2)
	}
}

type privilegeCountingContext struct {
	context.Context
	calls, cancelAt int
}

func (c *privilegeCountingContext) Err() error {
	c.calls++
	if c.cancelAt > 0 && c.calls >= c.cancelAt {
		return context.Canceled
	}
	return nil
}
