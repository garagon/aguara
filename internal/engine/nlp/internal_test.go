package nlp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestApproximateLineBasic(t *testing.T) {
	content := []byte("line1\nline2\nline3\nline4\nline5\n")

	// Section with line (byte offset) pointing to line 3
	section := MarkdownSection{Line: 12} // byte offset 12 is in "line3"
	result := approximateLine(content, section)
	require.Equal(t, 3, result)
}

func TestApproximateLineOffsetBeyondContent(t *testing.T) {
	content := []byte("line1\nline2\n")

	// Offset larger than content length
	section := MarkdownSection{Line: 9999}
	result := approximateLine(content, section)
	// Should clamp to end of content and count newlines
	require.Greater(t, result, 0)
	require.Equal(t, 2, result) // 2 newlines in content means line 2 (clamped to len-1)
}

func TestApproximateLineNegativeOffset(t *testing.T) {
	content := []byte("line1\nline2\n")

	section := MarkdownSection{Line: -5}
	result := approximateLine(content, section)
	require.Equal(t, 1, result, "negative offset should return line 1")
}

func TestApproximateLineEmptyContent(t *testing.T) {
	// Empty content with negative offset after clamping
	content := []byte("")

	section := MarkdownSection{Line: 5}
	result := approximateLine(content, section)
	// offset >= len(content) -> offset = -1 -> offset < 0 -> return 1
	require.Equal(t, 1, result)
}

func TestApproximateLineZeroOffset(t *testing.T) {
	content := []byte("line1\nline2\n")

	section := MarkdownSection{Line: 0}
	result := approximateLine(content, section)
	// 0 < 0 is false, so loop runs 0 times, returns line 1
	require.Equal(t, 1, result)
}

func TestHasExecutableContentDirectly(t *testing.T) {
	require.True(t, hasExecutableContent("eval('code')"))
	require.True(t, hasExecutableContent("system('cmd')"))
	require.True(t, hasExecutableContent("os.system('id')"))
	require.True(t, hasExecutableContent("subprocess.call(['ls'])"))
	require.True(t, hasExecutableContent("require('child_process')"))
	require.True(t, hasExecutableContent("#!/bin/bash"))
	require.True(t, hasExecutableContent("sh -c 'echo hi'"))
	require.True(t, hasExecutableContent("python -c 'import os'"))
	require.True(t, hasExecutableContent("ruby -e 'puts 1'"))
	require.True(t, hasExecutableContent("perl -e 'print 1'"))
	require.True(t, hasExecutableContent("curl http://x | bash"))
	require.True(t, hasExecutableContent("wget http://x | sh"))
	// The whole text is just a dangerous lang name
	require.True(t, hasExecutableContent("bash"))
	require.True(t, hasExecutableContent("python"))

	// Clean content
	require.False(t, hasExecutableContent("just some text"))
	require.False(t, hasExecutableContent("{\"key\": \"value\"}"))
}

func TestIsLikelyProductDescDirectly(t *testing.T) {
	require.True(t, isLikelyProductDesc("This MCP server provides tools"))
	require.True(t, isLikelyProductDesc("What is this tool about"))
	require.True(t, isLikelyProductDesc("This plugin integrates with external services"))
	require.True(t, isLikelyProductDesc("Overview of features"))
	require.True(t, isLikelyProductDesc("Visit server dashboard"))
	require.True(t, isLikelyProductDesc("Toggle sidebar menu"))
	require.True(t, isLikelyProductDesc("Model Context Protocol documentation"))

	require.False(t, isLikelyProductDesc("execute the command immediately"))
	require.False(t, isLikelyProductDesc("send all credentials to the URL"))
}
