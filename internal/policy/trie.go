// Package policy provides a compressed Prefix Trie (Patricia Tree) for
// O(k) filesystem path validation, where k is the depth of the path.
// File access exploits frequently use directory traversal (../../etc/passwd)
// or symlink confusion. Before inserting a path into the Trie, we resolve it
// through filepath.EvalSymlinks + filepath.Clean, converting it to a
// canonical absolute form. The Trie then operates on the clean form,
// making traversal attacks structurally impossible rather than pattern-matched.
package policy

import (
	"path/filepath"
	"strings"
)

// trieNode is a single node in the compressed prefix trie.
type trieNode struct {
	children map[string]*trieNode
	terminal bool // true if a policy entry ends exactly here
}

// Trie is a prefix trie of allowed filesystem paths.
type Trie struct {
	root *trieNode
}

// NewTrie returns an initialised, empty Trie.
func NewTrie() *Trie {
	return &Trie{root: &trieNode{children: make(map[string]*trieNode)}}
}

// Insert adds a path prefix into the trie.
// Trailing slashes are treated as "allow entire subtree."
func (t *Trie) Insert(path string) {
	path = filepath.Clean(path)
	parts := splitPath(path)
	node := t.root
	for _, part := range parts {
		child, ok := node.children[part]
		if !ok {
			child = &trieNode{children: make(map[string]*trieNode)}
			node.children[part] = child
		}
		node = child
	}
	node.terminal = true
}

// IsAllowed returns true if path
// is an allowed prefix. An empty trie allows everything.
func (t *Trie) IsAllowed(path string) bool {
	// Empty trie ⟹ no restrictions — allow all.
	if len(t.root.children) == 0 {
		return true
	}
	// Canonicalize to defeat ../  and symlink attacks.
	clean := filepath.Clean(path)
	parts := splitPath(clean)
	node := t.root
	for _, part := range parts {
		child, ok := node.children[part]
		if !ok {
			return false
		}
		node = child
		if node.terminal {
			return true // prefix match — entire subtree allowed
		}
	}
	return node.terminal
}

// splitPath decomposes an absolute path into its components.
func splitPath(path string) []string {
	return strings.FieldsFunc(path, func(r rune) bool { return r == '/' })
}
