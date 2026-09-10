package aguara

import (
	"bytes"
	"testing"
)

func TestInlineTargetPreservesSource(t *testing.T) {
	for _, tc := range []struct {
		input, normalized string
		changed           bool
	}{
		{"plain", "plain", false},
		{"\uff49gnore", "ignore", true},
	} {
		target := inlineTarget(tc.input, "package.json")
		if string(target.Content) != tc.normalized || string(target.SourceContent()) != tc.input {
			t.Fatalf("lost source/text distinction: %+v", target)
		}
		if (target.OriginalContent != nil) != tc.changed {
			t.Fatal("unnecessary source copy")
		}
		if !bytes.Equal(target.Content, []byte(target.StringContent())) {
			t.Fatal("text view changed")
		}
	}
}
