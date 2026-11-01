package intel

import (
	"bytes"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/require"
)

// Boundary fixtures use small limits to keep race instrumentation affordable.
// Lock the public wiring separately: no runtime option or test-only global may
// lower the real limits. A changed wrapper must be reviewed, not silently tested
// only through its smaller-budget helper.
func TestProductionReadLimitWiring(t *testing.T) {
	require.Equal(t, int64(64<<20), MaxSnapshotBytes)
	require.Equal(t, int64(256<<20), MaxHTTPBodyBytes)
	for _, tc := range []struct{ file, function, call string }{
		{"snapshotgz.go", "DecompressGZIP", "decompressGZIP(data, MaxSnapshotBytes)"},
		{"store.go", "Load", "s.load(MaxSnapshotBytes)"},
		{"update.go", "Update", "update(ctx, opts, MaxHTTPBodyBytes)"},
	} {
		t.Run(tc.function, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, tc.file, nil, 0)
			require.NoError(t, err)
			var function *ast.FuncDecl
			for _, decl := range file.Decls {
				if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == tc.function {
					require.Nil(t, function, "ambiguous wrapper")
					function = fn
				}
			}
			require.NotNil(t, function)
			require.Len(t, function.Body.List, 1, "public wrapper must delegate directly")
			ret, ok := function.Body.List[0].(*ast.ReturnStmt)
			require.True(t, ok)
			require.Len(t, ret.Results, 1)
			var rendered bytes.Buffer
			require.NoError(t, format.Node(&rendered, fset, ret.Results[0]))
			require.Equal(t, tc.call, rendered.String())
		})
	}

	// Update must forward that same bound to the per-ecosystem HTTP reader.
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "update.go", nil, 0)
	require.NoError(t, err)
	calls := 0
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		name, ok := call.Fun.(*ast.Ident)
		if !ok || name.Name != "fetchAndImport" {
			return true
		}
		calls++
		require.Len(t, call.Args, 7)
		bound, ok := call.Args[6].(*ast.Ident)
		require.True(t, ok)
		require.Equal(t, "maxBodyBytes", bound.Name)
		return true
	})
	require.Equal(t, 1, calls)
}
