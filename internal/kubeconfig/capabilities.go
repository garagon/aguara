package kubeconfig

import (
	"fmt"
	"sort"

	"gopkg.in/yaml.v3"
)

// Status distinguishes recognized ownership from no match and ambiguity.
type Status string

const (
	Supported     Status = "supported"
	NotApplicable Status = "not-applicable"
	Unsupported   Status = "unsupported"
)

// Grant groups identity capability scalars in a single container declaration.
type Grant struct {
	Path         string
	Capabilities []string
	Spans        []Span
	Line, Column int
}

// Classification is atomic: Unsupported never carries suppression spans.
type Classification struct {
	Status Status
	Reason string
	Grants []Grant
}

// IdentityCapabilities recognizes only explicit, canonical Kubernetes paths.
func (d *Document) IdentityCapabilities() Classification {
	if d == nil || !d.completeSpans || !d.CommentsSafe {
		return Classification{Status: Unsupported, Reason: "unsupported scalar boundaries"}
	}
	var grants []Grant
	for _, doc := range d.Nodes {
		if len(doc.Content) == 0 {
			continue
		}
		root := doc.Content[0]
		resources := []*yaml.Node{root}
		if text(field(root, "apiVersion")) == "v1" && text(field(root, "kind")) == "List" {
			items := field(root, "items")
			if items == nil || items.Kind != yaml.SequenceNode {
				return Classification{Status: Unsupported, Reason: "unsupported List items"}
			}
			resources = items.Content
		}
		for _, resource := range resources {
			found, ok := d.resourceGrants(resource)
			if !ok {
				return Classification{Status: Unsupported, Reason: "unsupported workload shape"}
			}
			grants = append(grants, found...)
		}
	}
	if len(grants) == 0 {
		return Classification{Status: NotApplicable}
	}
	sort.SliceStable(grants, func(i, j int) bool { return grants[i].Spans[0].Start < grants[j].Spans[0].Start })
	return Classification{Status: Supported, Grants: grants}
}

func (d *Document) resourceGrants(root *yaml.Node) ([]Grant, bool) {
	api, kind := text(field(root, "apiVersion")), text(field(root, "kind"))
	var path []string
	switch api + "/" + kind {
	case "v1/Pod":
		path = []string{"spec"}
	case "v1/ReplicationController", "apps/v1/Deployment", "apps/v1/StatefulSet", "apps/v1/DaemonSet", "apps/v1/ReplicaSet", "batch/v1/Job":
		path = []string{"spec", "template", "spec"}
	case "batch/v1/CronJob":
		path = []string{"spec", "jobTemplate", "spec", "template", "spec"}
	case "v1/List":
		return nil, false // No recursive List expansion.
	default:
		return nil, true
	}
	spec, prefix := root, ""
	for _, key := range path {
		spec = field(spec, key)
		if spec == nil || spec.Kind != yaml.MappingNode {
			return nil, false
		}
		if prefix != "" {
			prefix += "."
		}
		prefix += key
	}
	if os := field(spec, "os"); os != nil && text(field(os, "name")) != "linux" {
		return nil, false
	}
	var out []Grant
	for _, key := range []string{"containers", "initContainers", "ephemeralContainers"} {
		list := field(spec, key)
		if list == nil {
			continue
		}
		if list.Kind != yaml.SequenceNode || (key == "ephemeralContainers" && kind != "Pod") {
			return nil, false
		}
		for i, container := range list.Content {
			if container.Kind != yaml.MappingNode {
				return nil, false
			}
			grant, ok := d.containerGrant(container)
			if !ok {
				return nil, false
			}
			if len(grant.Spans) != 0 {
				grant.Path = fmt.Sprintf("%s.%s[%d]", prefix, key, i)
				out = append(out, grant)
			}
		}
	}
	return out, true
}

func (d *Document) containerGrant(container *yaml.Node) (Grant, bool) {
	node := container
	for _, key := range []string{"securityContext", "capabilities"} {
		node = field(node, key)
		if node == nil || node.Tag == "!!null" {
			return Grant{}, true
		}
		if node.Kind != yaml.MappingNode {
			return Grant{}, false
		}
	}
	// An invalid sibling drop list makes this declaration ambiguous; do not
	// silently claim an effective capability set for it.
	for _, key := range []string{"add", "drop"} {
		if !stringList(field(node, key)) {
			return Grant{}, false
		}
	}
	add := field(node, "add")
	if add == nil || add.Tag == "!!null" {
		return Grant{}, true
	}
	var grant Grant
	seen := make(map[string]bool)
	for _, item := range add.Content {
		if item.Value != "SETUID" && item.Value != "SETGID" {
			continue
		}
		span, ok := d.Spans[item]
		if !ok {
			return Grant{}, false
		}
		if len(grant.Spans) == 0 {
			grant.Line, grant.Column = item.Line, item.Column
		}
		grant.Spans = append(grant.Spans, span)
		if !seen[item.Value] {
			grant.Capabilities = append(grant.Capabilities, item.Value)
			seen[item.Value] = true
		}
	}
	return grant, true
}

func field(node *yaml.Node, name string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i]
		if key.Tag == "!!str" && key.Value == name {
			return node.Content[i+1]
		}
	}
	return nil
}

func text(n *yaml.Node) string {
	if n != nil && n.Kind == yaml.ScalarNode && n.Tag == "!!str" {
		return n.Value
	}
	return ""
}

func stringList(n *yaml.Node) bool {
	if n == nil || n.Tag == "!!null" {
		return true
	}
	if n.Kind != yaml.SequenceNode {
		return false
	}
	for _, item := range n.Content {
		if item.Kind != yaml.ScalarNode || item.Tag != "!!str" {
			return false
		}
	}
	return true
}
