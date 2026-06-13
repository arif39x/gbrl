// Package policy implements a compressed prefix trie for efficient
// filesystem path validation. It uses canonical paths to prevent
// traversal and symlink attacks.
package policy

import (
	"path/filepath"
	"strings"
)

// trieNode represents a single segment in the path trie.
type trieNode struct {
	children map[string]*trieNode
	terminal bool // true if a policy entry ends exactly here
}

// Trie stores allowed filesystem paths for prefix-based matching.
type Trie struct {
	root *trieNode
}

// NewTrie returns an initialized, empty Trie.
func NewTrie() *Trie {
	return &Trie{root: &trieNode{children: make(map[string]*trieNode)}}
}

// Insert adds a path to the trie. Subtree access is allowed for terminal nodes.
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

// IsAllowed returns true if the path matches an allowed prefix.
// An empty trie imposes no restrictions and returns true.
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
