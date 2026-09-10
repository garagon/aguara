package aguara_test

import (
	"context"
	"testing"

	"github.com/garagon/aguara"
	"github.com/stretchr/testify/require"
)

func TestAgentPolicyInlineExactJSON(t *testing.T) {
	s, err := aguara.NewScanner(aguara.WithWorkers(1))
	require.NoError(t, err)
	for _, tc := range []struct {
		content string
		want    bool
	}{
		{`{"permissions":{"defaultMode":"bypassPermissions"},"Permissions":null}`, true},
		{`{"ｐｅｒｍｉｓｓｉｏｎｓ":{"defaultMode":"bypassPermissions"}}`, false},
	} {
		result, err := s.ScanContent(context.Background(), tc.content, ".claude/settings.json")
		require.NoError(t, err)
		found := false
		for _, f := range result.Findings {
			if f.RuleID == "AGENTCFG_BYPASS_PERMS_001" {
				found = true
			}
		}
		require.Equal(t, tc.want, found)
	}
}
