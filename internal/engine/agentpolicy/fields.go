package agentpolicy

import "github.com/garagon/aguara/internal/jsonfields"

func (p *rawSettings) UnmarshalJSON(data []byte) error {
	var next rawSettings
	err := jsonfields.Decode(data,
		jsonfields.Field{Name: "permissions", To: &next.Permissions},
		jsonfields.Field{Name: "hooks", To: &next.Hooks},
		jsonfields.Field{Name: "env", To: &next.Env},
		jsonfields.Field{Name: "enableAllProjectMcpServers", To: &next.EnableAllProjectMcpServers})
	if err == nil {
		*p = next
	}
	return err
}

func (p *permissions) UnmarshalJSON(data []byte) error {
	var next permissions
	err := jsonfields.Decode(data,
		jsonfields.Field{Name: "defaultMode", To: &next.DefaultMode},
		jsonfields.Field{Name: "allow", To: &next.Allow})
	if err == nil {
		*p = next
	}
	return err
}

func (p *hookMatcher) UnmarshalJSON(data []byte) error {
	var next hookMatcher
	err := jsonfields.Decode(data, jsonfields.Field{Name: "hooks", To: &next.Hooks})
	if err == nil {
		*p = next
	}
	return err
}

func (p *hookEntry) UnmarshalJSON(data []byte) error {
	var next hookEntry
	err := jsonfields.Decode(data,
		jsonfields.Field{Name: "type", To: &next.Type},
		jsonfields.Field{Name: "command", To: &next.Command})
	if err == nil {
		*p = next
	}
	return err
}
