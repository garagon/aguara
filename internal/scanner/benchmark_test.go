package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/garagon/aguara/internal/engine/nlp"
	"github.com/garagon/aguara/internal/engine/pattern"
	"github.com/garagon/aguara/internal/engine/toxicflow"
	"github.com/garagon/aguara/internal/rules"
	"github.com/garagon/aguara/internal/rules/builtin"
	"github.com/garagon/aguara/internal/scanner"
)

func BenchmarkScannerE2E(b *testing.B) {
	// Create a temp directory with 10 files
	dir := b.TempDir()
	for i := range 10 {
		content := "# Tool " + string(rune('A'+i)) + "\n\nThis tool manages data.\n\n"
		for range 50 {
			content += "Normal documentation text.\n"
		}
		if i%3 == 0 {
			content += "exec(user_input)\nos.system(command)\n"
		}
		if err := os.WriteFile(filepath.Join(dir, "tool_"+string(rune('a'+i))+".md"), []byte(content), 0644); err != nil {
			b.Fatal(err)
		}
	}

	rawRules, _ := rules.LoadFromFS(builtin.FS())
	compiled, _ := rules.CompileAll(rawRules)

	b.ResetTimer()
	for range b.N {
		s := scanner.New(4)
		s.RegisterAnalyzer(pattern.NewMatcher(compiled))
		s.RegisterAnalyzer(nlp.NewInjectionAnalyzer())
		s.RegisterAnalyzer(toxicflow.New())
		_, _ = s.Scan(context.Background(), dir)
	}
}
