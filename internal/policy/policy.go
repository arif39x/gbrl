// Package policy implements the security rules engine for GBRL. It translates
// YAML-defined rules into optimized lookup structures, like tries for path
// validation, and evaluates every intercepted syscall against these rules.
package policy

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Action defines how the monitor should respond to a policy hit.
type Action int

const (
	// ActionAllow lets the syscall proceed normally.
	ActionAllow Action = iota
	// ActionKill terminates the tracee immediately via SIGKILL.
	ActionKill
	// ActionFreeze suspends the tracee to allow for manual inspection.
	ActionFreeze
	// ActionDeny blocks the syscall, forcing it to return an error like -EPERM.
	ActionDeny
	// ActionDump triggers a full memory dump for forensic analysis.
	ActionDump
)

// String returns the human-readable name of the Action.
func (a Action) String() string {
	switch a {
	case ActionAllow:
		return "Allow"
	case ActionKill:
		return "Kill"
	case ActionFreeze:
		return "Freeze"
	case ActionDeny:
		return "Deny"
	case ActionDump:
		return "Dump"
	default:
		return "Unknown"
	}
}

// HeuristicConfig holds ransomware detection parameters.
type HeuristicConfig struct {
	EntropyWindow        int     `yaml:"entropy_window"`
	EntropyThreshold     float64 `yaml:"entropy_threshold"`
	MaxHighEntropyWrites int     `yaml:"max_high_entropy_writes"`
}

// rawPolicy is the parsed representation of the YAML file.
type rawPolicy struct {
	BlockSyscalls []string        `yaml:"block_syscalls"`
	AllowFS       []string        `yaml:"allow_fs"`
	Heuristic     HeuristicConfig `yaml:"heuristic"`
}

// Policy is the compiled, ready-to-evaluate security policy.
type Policy struct {
	// blockedSyscalls is an O(1) bitset represented as a map for syscalls
	// that should trigger an immediate SIGKILL.
	blockedSyscalls map[string]struct{}

	// fsTrie validates filesystem paths extracted from memory arguments.
	fsTrie *Trie

	// Heuristic holds the decoded entropy detection parameters.
	Heuristic HeuristicConfig
}

// SyscallCtx is the context presented to Evaluate for each intercepted syscall.
type SyscallCtx struct {
	// SyscallName is the human-readable name (e.g. "SYS_SOCKET").
	SyscallName string

	// ResolvedPath is the canonicalized filesystem path extracted from memory,
	// populated only for path-argument syscalls (openat, execve, etc.).
	ResolvedPath string

	// EntropyAlarm is set by the heuristic engine when the ransomware threshold
	// is exceeded.
	EntropyAlarm bool
}

// Load parses the YAML policy at path and compiles the internal structures.
// If path is empty, an open (allow-all) policy is returned.
func Load(path string) (*Policy, error) {
	p := &Policy{
		blockedSyscalls: make(map[string]struct{}),
		fsTrie:          NewTrie(),
		Heuristic: HeuristicConfig{
			EntropyWindow:        8192,
			EntropyThreshold:     7.2,
			MaxHighEntropyWrites: 5,
		},
	}
	if path == "" {
		return p, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy %q: %w", path, err)
	}

	var raw rawPolicy
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse policy %q: %w", path, err)
	}

	for _, name := range raw.BlockSyscalls {
		p.blockedSyscalls[name] = struct{}{}
	}
	for _, fsPath := range raw.AllowFS {
		p.fsTrie.Insert(fsPath)
	}
	if raw.Heuristic.EntropyWindow > 0 {
		p.Heuristic = raw.Heuristic
	}
	return p, nil
}

// Evaluate applies the policy to a syscall context and returns the Action.
// Priority: EntropyAlarm > BlockedSyscall > FSPolicy > Allow.
func (p *Policy) Evaluate(ctx SyscallCtx) Action {
	if ctx.EntropyAlarm {
		return ActionFreeze
	}
	if _, blocked := p.blockedSyscalls[ctx.SyscallName]; blocked {
		return ActionKill
	}
	if ctx.ResolvedPath != "" && !p.fsTrie.IsAllowed(ctx.ResolvedPath) {
		return ActionDeny
	}
	return ActionAllow
}
