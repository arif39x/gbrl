// Package memory provides safe, high-speed extraction of data from a tracee's
// virtual address space using process_vm_readv(2).
//
// OS Theory
// The traditional approach to reading a tracee's memory is PTRACE_PEEKDATA,
// which copies a single machine word (8 bytes) per syscall round-trip. Reading
// a 4096-byte pathname that way costs 512 kernel transitions — roughly 1 ms.
//
// process_vm_readv(2), introduced in Linux 3.2, performs scatter-gather I/O
// between two processes' virtual address spaces using the kernel's own page-
// table walk. The data is transferred entirely in the kernel half of the
// virtual-address mapping with no intermediate copy through the tracer's user-
// space stack. A single call reads megabytes with one syscall — ~10× faster
// than PTRACE_PEEKDATA for string arguments.
package memory

import (
	"fmt"

	"golang.org/x/sys/unix"
)

const maxStringLen = 4096

// ReadBytes copies n bytes from addr in process pid into a fresh slice.
func ReadBytes(pid int, addr uintptr, n int) ([]byte, error) {
	if n <= 0 {
		return nil, nil
	}
	buf := make([]byte, n)

	localVec := []unix.Iovec{{
		Base: &buf[0],
		Len:  uint64(n),
	}}
	remoteVec := []unix.RemoteIovec{{
		Base: addr,
		Len:  n,
	}}

	nRead, err := unix.ProcessVMReadv(pid, localVec, remoteVec, 0)
	if err != nil {
		return nil, fmt.Errorf("process_vm_readv pid=%d addr=0x%x: %w", pid, addr, err)
	}
	return buf[:nRead], nil
}

// ReadString reads a null-terminated C string from addr in process pid.
// It reads up to maxStringLen bytes to find the terminator.
func ReadString(pid int, addr uintptr) (string, error) {
	if addr == 0 {
		return "", nil
	}
	raw, err := ReadBytes(pid, addr, maxStringLen)
	if err != nil {
		return "", err
	}
	// Trim at the first null byte.
	for i, b := range raw {
		if b == 0 {
			return string(raw[:i]), nil
		}
	}
	return string(raw), nil
}
