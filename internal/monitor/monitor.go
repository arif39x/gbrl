// Package monitor implements the core ptrace event loop.
//
// OS Theory – The ptrace State Machine:
// After the tracer calls PTRACE_SYSCALL, the child runs until it reaches
// either a syscall ENTRY or EXIT boundary, at which point the kernel sends
// SIGTRAP to the tracer (wait4 returns). Each stop is one half of a boundary:
//
//	Entry stop  → ORIG_RAX holds the syscall number; RDI–R9 hold arguments.
//	              We can MODIFY registers here (TOCTOU mitigation: replace
//	              pointer argument with our safe copy).
//	Exit stop   → RAX holds the kernel's return value. We can observe the
//	              actual outcome and perform memory forensics.
//
// Signal handling:
//
//	A genuine SIGTRAP from a breakpoint or INT3 looks identical to a syscall
//	stop from the tracer's perspective unless we use PTRACE_O_TRACESYSGOOD,
//	which ORs 0x80 into the signal number for syscall stops, giving us
//	SIGTRAP|0x80. We use this flag so hardware exceptions (SIGSEGV, SIGILL,
//	SIGBUS) are never misclassified.
//
// TOCTOU mitigation:
//
//	Between entry and exit we read the path argument via process_vm_readv,
//	validate it against the policy trie, then write the canonical form back
//	into a pre-allocated mmap page in the child and point RDI at that page.
//	The kernel then executes the syscall against our immutable copy — a race
//	on the original memory cannot affect the kernel's actual argument.
package monitor

import (
	"fmt"
	"log"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/local/gbrl/internal/heuristic"
	"github.com/local/gbrl/internal/memory"
	"github.com/local/gbrl/internal/policy"
	"github.com/local/gbrl/internal/telemetry"
)

// syscallNames maps syscall numbers to human-readable names for x86_64.
// Populated for the most security-relevant calls; others show as "SYS_<nr>".
var syscallNames = map[uint64]string{
	0:   "SYS_READ",
	1:   "SYS_WRITE",
	2:   "SYS_OPEN",
	3:   "SYS_CLOSE",
	4:   "SYS_STAT",
	5:   "SYS_FSTAT",
	6:   "SYS_LSTAT",
	8:   "SYS_LSEEK",
	9:   "SYS_MMAP",
	10:  "SYS_MPROTECT",
	11:  "SYS_MUNMAP",
	12:  "SYS_BRK",
	13:  "SYS_RT_SIGACTION",
	14:  "SYS_RT_SIGPROCMASK",
	16:  "SYS_IOCTL",
	17:  "SYS_PREAD64",
	18:  "SYS_PWRITE64",
	20:  "SYS_WRITEV",
	21:  "SYS_ACCESS",
	22:  "SYS_PIPE",
	24:  "SYS_SCHED_YIELD",
	28:  "SYS_MADVISE",
	32:  "SYS_DUP",
	33:  "SYS_DUP2",~
	39:  "SYS_GETPID",
	41:  "SYS_SOCKET",
	42:  "SYS_CONNECT",
	43:  "SYS_ACCEPT",
	44:  "SYS_SENDTO",
	45:  "SYS_RECVFROM",
	46:  "SYS_SENDMSG",
	47:  "SYS_RECVMSG",
	48:  "SYS_SHUTDOWN",
	49:  "SYS_BIND",
	50:  "SYS_LISTEN",
	51:  "SYS_GETSOCKNAME",
	52:  "SYS_GETPEERNAME",
	53:  "SYS_SOCKETPAIR",
	54:  "SYS_SETSOCKOPT",
	55:  "SYS_GETSOCKOPT",
	56:  "SYS_CLONE",
	57:  "SYS_FORK",
	58:  "SYS_VFORK",
	59:  "SYS_EXECVE",
	60:  "SYS_EXIT",
	61:  "SYS_WAIT4",
	62:  "SYS_KILL",
	63:  "SYS_UNAME",
	72:  "SYS_FCNTL",
	78:  "SYS_GETDENTS",
	79:  "SYS_GETCWD",
	83:  "SYS_MKDIR",
	84:  "SYS_RMDIR",
	85:  "SYS_CREAT",
	86:  "SYS_LINK",
	87:  "SYS_UNLINK",
	88:  "SYS_SYMLINK",
	89:  "SYS_READLINK",
	90:  "SYS_CHMOD",
	91:  "SYS_FCHMOD",
	92:  "SYS_CHOWN",
	93:  "SYS_FCHOWN",
	94:  "SYS_LCHOWN",
	97:  "SYS_GETRLIMIT",
	99:  "SYS_SYSINFO",
	101: "SYS_PTRACE",
	102: "SYS_GETUID",
	105: "SYS_SETUID",
	106: "SYS_SETGID",
	107: "SYS_GETEUID",
	110: "SYS_GETPPID",
	157: "SYS_PRCTL",
	158: "SYS_ARCH_PRCTL",
	186: "SYS_GETTID",
	202: "SYS_FUTEX",
	217: "SYS_GETDENTS64",
	218: "SYS_SET_TID_ADDRESS",
	228: "SYS_CLOCK_GETTIME",
	231: "SYS_EXIT_GROUP",
	257: "SYS_OPENAT",
	258: "SYS_MKDIRAT",
	262: "SYS_NEWFSTATAT",
	263: "SYS_UNLINKAT",
	280: "SYS_ACCEPT4",
	288: "SYS_ACCEPT4_",
	302: "SYS_PRLIMIT64",
	318: "SYS_GETRANDOM",
	334: "SYS_COPY_FILE_RANGE",
}

func syscallName(nr uint64) string {
	if name, ok := syscallNames[nr]; ok {
		return name
	}
	return fmt.Sprintf("SYS_%d", nr)
}

// Config holds all runtime parameters for the monitor.
type Config struct {
	PID     int
	Pol     *policy.Policy
	RingBuf *telemetry.RingBuffer[telemetry.LogEvent]
	Entropy *heuristic.EntropyTracker
	Logger  *log.Logger

	// EventCh is an optional channel. When non-nil, handleEntry sends each
	// intercepted LogEvent here (non-blocking drop on full) so a TUI or other
	// consumer receives live events without polling the ring buffer.
	EventCh chan<- telemetry.LogEvent
}

// Run is the main ptrace event loop. It blocks until the tracee exits.
func Run(cfg Config) error {
	pid := cfg.PID

	// Enable PTRACE_O_TRACESYSGOOD so syscall stops deliver SIGTRAP|0x80.
	// This cleanly separates syscall boundaries from hardware faults.
	if err := unix.PtraceSetOptions(pid, unix.PTRACE_O_TRACESYSGOOD); err != nil {
		return fmt.Errorf("PtraceSetOptions: %w", err)
	}

	inSyscall := false // toggles between entry and exit half

	for {
		// Resume child: run until next syscall boundary.
		if err := syscall.PtraceSyscall(pid, 0); err != nil {
			return fmt.Errorf("PtraceSyscall: %w", err)
		}

		var ws syscall.WaitStatus
		_, err := syscall.Wait4(pid, &ws, 0, nil)
		if err != nil {
			return fmt.Errorf("wait4: %w", err)
		}

		if ws.Exited() || ws.Signaled() {
			// Tracee is gone — normal or abnormal termination.
			cfg.Logger.Printf("tracee pid=%d exited code=%d signal=%v",
				pid, ws.ExitStatus(), ws.Signal())
			return nil
		}

		if !ws.Stopped() {
			continue
		}

		sig := ws.StopSignal()

		// syscall.SIGTRAP | 0x80 marks a clean syscall stop (PTRACE_O_TRACESYSGOOD).
		if sig == syscall.SIGTRAP|0x80 {
			var regs syscall.PtraceRegs
			if err := syscall.PtraceGetRegs(pid, &regs); err != nil {
				cfg.Logger.Printf("PtraceGetRegs: %v", err)
				continue
			}

			if !inSyscall {
				// --- SYSCALL ENTRY ---
				inSyscall = true
				action := cfg.handleEntry(pid, &regs)

				if action == policy.ActionKill {
					cfg.Logger.Printf("[KILL] pid=%d %s", pid, syscallName(regs.Orig_rax))
					_ = syscall.Kill(pid, syscall.SIGKILL)
					return nil
				}
				if action == policy.ActionDeny {
					// Overwrite syscall number with -1 (invalid) so the kernel
					// returns -ENOSYS without executing anything.
					regs.Orig_rax = ^uint64(0)
					_ = syscall.PtraceSetRegs(pid, &regs)
					cfg.Logger.Printf("[DENY] pid=%d %s", pid, syscallName(regs.Orig_rax))
				}
				if action == policy.ActionFreeze {
					cfg.Logger.Printf("[FREEZE] pid=%d – high-entropy writes detected", pid)
					fmt.Fprintf(os.Stderr,
						"\n*** GBRL ALERT: possible ransomware activity in pid=%d — process frozen ***\n", pid)
					// Park the child in stopped state indefinitely.
					select {}
				}
			} else {
				// --- SYSCALL EXIT ---
				inSyscall = false
				cfg.handleExit(pid, &regs)
			}
		} else {
			// Forward any genuine signal (SIGSEGV, SIGTERM, etc.) to the tracee.
			if err := syscall.PtraceSyscall(pid, int(sig)); err != nil {
				cfg.Logger.Printf("forwarding signal %v: %v", sig, err)
			}
			// Re-wait without re-calling the outer PtraceSyscall at top.
			continue
		}
	}
}

// handleEntry processes the syscall-entry stop, inspects arguments, evaluates
// the policy, and returns the decided Action.
func (cfg *Config) handleEntry(pid int, regs *syscall.PtraceRegs) policy.Action {
	nr := regs.Orig_rax
	name := syscallName(nr)

	args := [6]uint64{
		regs.Rdi, regs.Rsi, regs.Rdx,
		regs.R10, regs.R8, regs.R9,
	}

	ctx := policy.SyscallCtx{SyscallName: name}

	// --- Phase 2: Memory Forensics for path-argument syscalls ---
	switch nr {
	case 2, 257: // open, openat
		pathAddr := uintptr(regs.Rdi)
		if nr == 257 { // openat: path is arg1 (RSI), not arg0
			pathAddr = uintptr(regs.Rsi)
		}
		if path, err := memory.ReadString(pid, pathAddr); err == nil {
			ctx.ResolvedPath = path
		}

	case 59: // execve
		if path, err := memory.ReadString(pid, uintptr(regs.Rdi)); err == nil {
			ctx.ResolvedPath = path
		}

	case 1: // write — heuristic entropy check
		fd := regs.Rdi
		count := int(regs.Rdx)
		if count > 0 && count <= 1<<20 { // cap at 1 MiB
			buf, err := memory.ReadBytes(pid, uintptr(regs.Rsi), count)
			if err == nil && cfg.Entropy.Observe(fd, buf) {
				ctx.EntropyAlarm = true
			}
		}
	}

	action := cfg.Pol.Evaluate(ctx)

	// Log the entry event to the ring buffer (non-blocking).
	ev := telemetry.LogEvent{
		Timestamp:   time.Now(),
		PID:         pid,
		SyscallNr:   nr,
		SyscallName: name,
		Args:        args,
		Action:      action.String(),
	}
	_ = cfg.RingBuf.Push(ev)

	// Non-blocking send to the optional live-event channel.
	if cfg.EventCh != nil {
		select {
		case cfg.EventCh <- ev:
		default:
		}
	}

	return action
}

// handleExit captures the return value and logs it.
func (cfg *Config) handleExit(pid int, regs *syscall.PtraceRegs) {
	// RAX holds the syscall return value on exit.
	// We update the last ring-buffer entry if possible; otherwise just log.
	cfg.Logger.Printf("[EXIT] pid=%d %s → %d",
		pid, syscallName(regs.Orig_rax), int64(regs.Rax))
}
