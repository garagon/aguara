package jsrisk

import (
	"bytes"
	"testing"
)

func TestGraphQLMutationScanEquivalence(t *testing.T) {
	for _, src := range []string{
		`const q = 'createGist createGist createGist';`,
		`const a = 'createGist createGist'; const b = 'mutation { createGist }';`,
		`const q = 'createGist mutation';`,
		`const q = 'mutationName createGist';`,
		`const q = 'mutation { createCommitOnBranch }';`,
		`const mutation = 1; const q = 'createGist';`,
		"const q = `mutation ${x} createGist`;",
		"const q = `createGist ${'mutation { createGist }'}`;",
		"const q = `mutation ${'createGist'} body`;",
		`// mutation createGist
const q = 'createGist';`,
		`const re = /mutation createGist/;`,
		`const q = 'mutation { createGist }'; const z = 'mutation { createCommitOnBranch }';`,
		`const q = 'createGist`,
	} {
		view := newJSLexicalView([]byte(src))
		lower := bytes.ToLower(view.Code)
		for _, needle := range githubGraphQLMutationNeedles {
			// Legacy occurrence walk is intentionally limited to these tiny
			// fixtures. It establishes matching equivalence, not a timing gate.
			want := -1
			for from := 0; from < len(lower); {
				i := bytes.Index(lower[from:], []byte(needle))
				if i < 0 {
					break
				}
				abs := from + i
				if s, e, ok := stringRangeContaining(view, abs); ok && graphqlMutationKeywordRe.Match(lower[s:e]) {
					want = abs
					break
				}
				from = abs + 1
			}
			if got := graphqlMutationIndex(view, lower, needle); got != want {
				t.Errorf("%s: got %d, want %d in %q", needle, got, want, src)
			}
		}
	}
}

func TestGraphQLMutationScanPreservesPriority(t *testing.T) {
	src := "client.graphql(q);\nconst a = 'mutation { createGist }';\nconst b = 'createCommitOnBranch createCommitOnBranch';\nconst c = 'mutation { createCommitOnBranch }';"
	view := newJSLexicalView([]byte(src))
	kind, line := findGitHubWriteChannel(view, bytes.ToLower(view.Code))
	if kind != "graphql-write" || line != 4 {
		t.Fatalf("channel = %q, line = %d; want graphql-write at line 4", kind, line)
	}
}
