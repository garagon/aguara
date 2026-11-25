package pattern

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

// bruteWindow reports whether some choice of one hit per pattern fits in
// within lines, and the smallest window start among such choices.
func bruteWindow(all [][]matchHit, within int) (bool, int) {
	best := -1
	var rec func(i, start, end int)
	rec = func(i, start, end int) {
		if i == len(all) {
			if end-start+1 <= within && (best < 0 || start < best) {
				best = start
			}
			return
		}
		for _, h := range all[i] {
			s, e := h.line, h.endLine
			if i > 0 {
				s, e = min(s, start), max(e, end)
			}
			rec(i+1, s, e)
		}
	}
	rec(0, 0, 0)
	return best >= 0, best
}

// randomHits returns ordered, non-overlapping hits like matchPattern does.
func randomHits(r *rand.Rand) []matchHit {
	var hits []matchHit
	line := 1 + r.Intn(3)
	for n := r.Intn(4) + 1; n > 0; n-- {
		span := 0
		if r.Intn(4) == 0 {
			span = r.Intn(3)
		}
		hits = append(hits, matchHit{line: line, endLine: line + span})
		line += span + r.Intn(6)
	}
	return hits
}

func TestWindowHitsMatchesBruteForce(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for iter := 0; iter < 20000; iter++ {
		all := make([][]matchHit, 1+r.Intn(3))
		for i := range all {
			all[i] = randomHits(r)
		}
		within := 1 + r.Intn(6)
		chosen := make([]matchHit, len(all))
		got := windowHits(all, within, chosen)
		want, wantStart := bruteWindow(all, within)
		require.Equal(t, want, got, "hits=%v within=%d", all, within)
		if !got {
			continue
		}
		start, end := chosen[0].line, chosen[0].endLine
		for i, h := range chosen {
			require.Contains(t, all[i], h)
			start, end = min(start, h.line), max(end, h.endLine)
		}
		require.LessOrEqual(t, end-start+1, within)
		require.Equal(t, wantStart, start, "earliest window, hits=%v within=%d", all, within)
	}
}
