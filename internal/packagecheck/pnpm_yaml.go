package packagecheck

import (
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"
)

// maxYAMLAliasHops bounds alias chains followed when resolving a node.
const maxYAMLAliasHops = 64

// pnpmPackageKeys returns the keys of the top-level `packages` mapping of
// a pnpm-lock.yaml, decoded the way yaml.Unmarshal decodes the keys of a
// map[string]any: tags such as !!binary are applied, alias keys resolve,
// and `<<` merge keys contribute the keys of the merged mappings. A
// document that is not a mapping, a `packages` value that is not a
// mapping, and a duplicate key anywhere in the top-level mapping or in the
// packages subtree are errors, as they were.
//
// The document is read as a node tree, which yaml.v3 builds in linear
// time. Decoding it into Go maps compares every key of a mapping with
// every other key, so a lockfile with millions of package keys never
// finished; duplicates are found here with a hash set instead. Aliases
// inside package values are not expanded.
func pnpmPackageKeys(data []byte) (map[string]bool, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if doc.Kind == 0 || len(doc.Content) == 0 {
		return nil, nil // empty document
	}
	root, err := resolveYAMLAlias(doc.Content[0])
	if err != nil {
		return nil, err
	}
	if isYAMLNull(root) {
		return nil, nil
	}
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("yaml: line %d: the document is not a mapping", root.Line)
	}
	if err := checkUniqueYAMLKeys(root); err != nil {
		return nil, err
	}
	packages, err := yamlMappingValue(root, "packages", map[*yaml.Node]bool{})
	if err != nil || packages == nil {
		return nil, err
	}
	packages, err = resolveYAMLAlias(packages)
	if err != nil {
		return nil, err
	}
	if isYAMLNull(packages) {
		return nil, nil
	}
	if packages.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("yaml: line %d: packages is not a mapping", packages.Line)
	}
	if err := checkUniqueYAMLKeysDeep(packages); err != nil {
		return nil, err
	}
	keys := map[string]bool{}
	if err := collectYAMLMappingKeys(packages, keys, map[*yaml.Node]bool{}); err != nil {
		return nil, err
	}
	return keys, nil
}

// yamlMappingValue returns the value of the scalar key name in mapping, or
// from a merged mapping when the mapping does not set it itself.
func yamlMappingValue(mapping *yaml.Node, name string, visited map[*yaml.Node]bool) (*yaml.Node, error) {
	if visited[mapping] {
		return nil, nil
	}
	visited[mapping] = true
	var merges []*yaml.Node
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		key, value := mapping.Content[i], mapping.Content[i+1]
		if isYAMLMergeKey(key) {
			merges = append(merges, value)
			continue
		}
		if s, err := yamlKeyString(key); err == nil && s == name {
			return value, nil
		}
	}
	for _, merge := range merges {
		sources, err := yamlMergeSources(merge)
		if err != nil {
			return nil, err
		}
		for _, src := range sources {
			if v, err := yamlMappingValue(src, name, visited); err != nil || v != nil {
				return v, err
			}
		}
	}
	return nil, nil
}

// collectYAMLMappingKeys adds the decoded keys of mapping, and of the
// mappings it merges, to keys.
func collectYAMLMappingKeys(mapping *yaml.Node, keys map[string]bool, visited map[*yaml.Node]bool) error {
	if visited[mapping] {
		return nil
	}
	visited[mapping] = true
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		key, value := mapping.Content[i], mapping.Content[i+1]
		if isYAMLMergeKey(key) {
			sources, err := yamlMergeSources(value)
			if err != nil {
				return err
			}
			for _, src := range sources {
				if err := collectYAMLMappingKeys(src, keys, visited); err != nil {
					return err
				}
			}
			continue
		}
		s, err := yamlKeyString(key)
		if err != nil {
			return err
		}
		keys[s] = true
	}
	return nil
}

// yamlKeyString decodes a mapping key into a string as yaml.Unmarshal
// would. A plain string scalar is its value; anything else (an alias, a
// !!binary or numeric tag, a collection) goes through the decoder.
func yamlKeyString(key *yaml.Node) (string, error) {
	if key.Kind == yaml.ScalarNode && (key.Tag == "!!str" || key.Tag == "tag:yaml.org,2002:str") {
		return key.Value, nil
	}
	var s string
	err := key.Decode(&s)
	return s, err
}

// yamlMergeSources returns the mappings a `<<` value merges: a mapping,
// an alias of one, or a sequence of those.
func yamlMergeSources(value *yaml.Node) ([]*yaml.Node, error) {
	items := []*yaml.Node{value}
	if value.Kind == yaml.SequenceNode {
		items = value.Content
	}
	out := make([]*yaml.Node, 0, len(items))
	for _, item := range items {
		resolved, err := resolveYAMLAlias(item)
		if err != nil {
			return nil, err
		}
		if resolved.Kind != yaml.MappingNode {
			return nil, errors.New("yaml: map merge requires map or sequence of maps as the value")
		}
		out = append(out, resolved)
	}
	return out, nil
}

func resolveYAMLAlias(n *yaml.Node) (*yaml.Node, error) {
	for hops := 0; n.Kind == yaml.AliasNode; hops++ {
		if n.Alias == nil || hops == maxYAMLAliasHops {
			return nil, fmt.Errorf("yaml: line %d: unresolvable alias", n.Line)
		}
		n = n.Alias
	}
	return n, nil
}

func isYAMLNull(n *yaml.Node) bool {
	return n.Kind == yaml.ScalarNode && (n.Tag == "!!null" || n.Tag == "tag:yaml.org,2002:null")
}

func isYAMLMergeKey(n *yaml.Node) bool {
	return n.Kind == yaml.ScalarNode && n.Value == "<<" &&
		(n.Tag == "" || n.Tag == "!" || n.Tag == "!!merge" || n.Tag == "tag:yaml.org,2002:merge")
}

// checkUniqueYAMLKeys reports a key that appears twice in one mapping,
// comparing node kind and raw value as yaml.v3 does.
func checkUniqueYAMLKeys(mapping *yaml.Node) error {
	type ident struct {
		kind  yaml.Kind
		value string
	}
	first := make(map[ident]int, len(mapping.Content)/2)
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		key := mapping.Content[i]
		id := ident{key.Kind, key.Value}
		if line, dup := first[id]; dup {
			return fmt.Errorf("yaml: unmarshal errors:\n  line %d: mapping key %#v already defined at line %d", key.Line, key.Value, line)
		}
		first[id] = key.Line
	}
	return nil
}

// checkUniqueYAMLKeysDeep applies checkUniqueYAMLKeys to n and every
// mapping below it, without following aliases.
func checkUniqueYAMLKeysDeep(n *yaml.Node) error {
	stack := []*yaml.Node{n}
	for len(stack) > 0 {
		node := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if node.Kind == yaml.MappingNode {
			if err := checkUniqueYAMLKeys(node); err != nil {
				return err
			}
		}
		if node.Kind != yaml.AliasNode {
			stack = append(stack, node.Content...)
		}
	}
	return nil
}
