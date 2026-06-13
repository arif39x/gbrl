// Package launcher configures process isolation and spawns the tracee under ptrace.
// It uses Linux namespaces and ptrace bootstrapping to ensure the sandboxed process
// starts in a controlled state.
package launcher

import (
	"fmt"
	"os/exec"
	"syscall"
)

const nobodyUID = 65534
const nobodyGID = 65534

// Config defines settings for launching a tracee.
type Config struct {
	// Args contains the command and its arguments.
	Args []string

	// Namespaces specify which Linux namespaces to unshare.
	IsolateMount   bool
	IsolateNetwork bool
	IsolatePID     bool
}

// Start spawns the tracee process in configured namespaces.
// The process halts at its first instruction.
func Start(cfg Config) (int, error) {
	if len(cfg.Args) == 0 {
		return 0, fmt.Errorf("launcher: no command specified")
	}

	cmd := exec.Command(cfg.Args[0], cfg.Args[1:]...) //nolint:gosec

	var cloneFlags uintptr
	if cfg.IsolateMount {
		cloneFlags |= syscall.CLONE_NEWNS
	}
	if cfg.IsolateNetwork {
		cloneFlags |= syscall.CLONE_NEWNET
	}
	if cfg.IsolatePID {
		cloneFlags |= syscall.CLONE_NEWPID
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Ptrace:     true,       // halt child at first execve stop
		Setpgid:    true,       // isolate process group (prevent signal leakage)
		Cloneflags: cloneFlags, // namespace isolation
	}

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("launcher: start %q: %w", cfg.Args[0], err)
	}

	// Wait for the initial SIGTRAP that ptrace delivers after execve.
	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(cmd.Process.Pid, &ws, 0, nil); err != nil {
		return 0, fmt.Errorf("launcher: initial wait4 pid=%d: %w", cmd.Process.Pid, err)
	}

	return cmd.Process.Pid, nil
}
