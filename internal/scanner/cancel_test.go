package scanner_test

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/types"
)

type countingAccumulator struct{ accumulated atomic.Int32 }

func (c *countingAccumulator) Accumulate(string, string) { c.accumulated.Add(1) }
func (c *countingAccumulator) Finalize() []types.Finding { return nil }

type countingAnalyzer struct{ calls *atomic.Int32 }

func (countingAnalyzer) Name() string { return "after-cancel" }
func (a countingAnalyzer) Analyze(context.Context, *scanner.Target) ([]types.Finding, error) {
	a.calls.Add(1)
	return nil, nil
}

// The cross-file accumulator takes no context and reads the whole file, so
// it runs after the per-file analyzers and not at all once the scan is
// canceled. The analyzer stopped by the cancellation is the file's one
// failure; the analyzers after it are not run.
func TestCanceledScanSkipsRemainingWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	acc := &countingAccumulator{}
	var later atomic.Int32
	s := scanner.New(1)
	s.SetCrossFileAccumulator(acc)
	s.RegisterAnalyzer(cancelingAnalyzer{cancel: cancel})
	s.RegisterAnalyzer(countingAnalyzer{calls: &later})
	_, err := s.ScanTargets(ctx, []*scanner.Target{{RelPath: "a.md", Content: []byte("x")}})
	partial := requireIncomplete(t, err)
	require.Zero(t, acc.accumulated.Load(), "no accumulation after cancellation")
	require.Zero(t, later.Load(), "no analyzer runs after cancellation")
	require.Equal(t, []types.ScanFailure{{Path: "a.md", Stage: types.FailureStageAnalyze, Analyzer: "canceling", Reason: types.FailureReasonCanceled}}, partial.Errors)

	// A complete scan still accumulates every file.
	acc = &countingAccumulator{}
	s = scanner.New(2)
	s.SetCrossFileAccumulator(acc)
	r, err := s.ScanTargets(context.Background(), []*scanner.Target{{RelPath: "a.md", Content: []byte("x")}, {RelPath: "b.md", Content: []byte("y")}})
	require.NoError(t, err)
	require.Equal(t, 2, r.FilesScanned)
	require.Equal(t, int32(2), acc.accumulated.Load())
}
