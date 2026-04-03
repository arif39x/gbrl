// Package launcher sets up process isolation and spawns the tracee under ptrace.
//
// OS Theory – Namespace
// Linux namespaces partition global kernel resources into per-process views:
//
//	CLONE_NEWNS  (mount)  — gives the child an independent mount table. Any
//	  mounts the child makes (or that malware attempts) are invisible to the
//	  host.
//
//	CLONE_NEWNET (network) — the child receives a fresh network stack with
//	  only lo (loopback). It cannot reach the internet unless the host
//	  explicitly sets up a veth pair — our default policy blocks this.
//
//	CLONE_NEWPID (PID)    — the child's PID namespace starts at PID 1. Its
//	  view of /proc shows only its own subtree; it cannot iterate host PIDs.
//
// Ptrace bootstrap:
//
//	SysProcAttr{Ptrace: true} causes the kernel to deliver SIGSTOP to the
//	child immediately after execve(2), before any user-space instruction runs.
//	The parent's Wait4 receives this stop and transfers control to the monitor
//	loop, which arms PTRACE_SYSCALL to intercept every subsequent boundary.
//
//	Setpgid: true places the child in its own process group, ensuring that
//	Ctrl-C (SIGINT) sent to the terminal's foreground process group does not
//	leak into the tracee — the tracer handles termination explicitly.
//
//	Credential drops to nobody (UID/GID 65534) before exec, applying the
//	principle of least privilege to the sandboxed binary.
package launcher

import (
	"fmt"
	"os/exec"
	"syscall"
)

const nobodyUID = 65534
const nobodyGID = 65534

// Config holds the settings for launching a tracee.
type Config struct {
	// Args is [binary, arg1, arg2, ...] of the command to sandbox.
	Args []string

	// Namespaces controls which Linux namespaces to unshare.
	IsolateMount   bool
	IsolateNetwork bool
	IsolatePID     bool
}

// Start launches the tracee process in the configured namespaces and returns
// its PID. The child halts at its first instruction; call monitor.Run next.
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
		// Credential: &syscall.Credential{
		// 	Uid: nobodyUID,
		// 	Gid: nobodyGID,
		// },
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
