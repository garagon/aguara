package output

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf8"
)

func TestIsTerminalNonFileWriter(t *testing.T) {
	if IsTerminal(&bytes.Buffer{}) {
		t.Error("expected IsTerminal to be false for a non-file writer")
	}
}

func TestIsTerminalRegularFile(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "out.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	if IsTerminal(f) {
		t.Error("expected IsTerminal to be false for a regular file")
	}
}

func TestDetectWidthNonTerminal(t *testing.T) {
	if w := DetectWidth(&bytes.Buffer{}); w != 0 {
		t.Errorf("expected width 0 for a non-file writer, got %d", w)
	}

	f, err := os.Create(filepath.Join(t.TempDir(), "out.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	if w := DetectWidth(f); w != 0 {
		t.Errorf("expected width 0 for a regular file, got %d", w)
	}
}

func TestTerminalFormatterWidth(t *testing.T) {
	cases := []struct {
		name  string
		width int
		want  int
	}{
		{"default", 0, lineWidth},
		{"narrow", 50, 50},
		{"wide", 100, 100},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &TerminalFormatter{Width: tc.width}
			if got := utf8.RuneCountInString(f.separator()); got != tc.want {
				t.Errorf("separator length = %d, want %d", got, tc.want)
			}
			header := f.sectionHeader("CRITICAL (5)")
			if got := utf8.RuneCountInString(header); got != tc.want {
				t.Errorf("sectionHeader length = %d, want %d", got, tc.want)
			}
		})
	}
}
