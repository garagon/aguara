package rulemeta

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecisionImpactFor(t *testing.T) {
	cases := []struct {
		name string
		id   string
		want string
	}{
		{name: "local shell script is context", id: "CMDEXEC_013", want: DecisionImpactContext},
		{name: "pip install is context", id: "EXTDL_009", want: DecisionImpactContext},
		{name: "system package install is context", id: "EXTDL_011", want: DecisionImpactContext},
		{name: "remote MCP endpoint is context", id: "MCPCFG_004", want: DecisionImpactContext},
		{name: "normalizes stable IDs", id: "  cmdexec_013 ", want: DecisionImpactContext},
		{name: "unknown built-in stays review", id: "SUPPLY_003", want: DecisionImpactReview},
		{name: "custom rule stays review", id: "CUSTOM_TEAM_RULE_001", want: DecisionImpactReview},
		{name: "empty ID stays review", id: "", want: DecisionImpactReview},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, DecisionImpactFor(tc.id))
		})
	}
}
