// Package memory implements high-speed data extraction from a tracee's
// address space using process_vm_readv(2). This avoids the overhead
// of multiple PTRACE_PEEKDATA calls.
package memory

import (
	"fmt"

	"golang.org/x/sys/unix"
)

const maxStringLen = 4096

// ReadBytes copies n bytes from addr in process pid into a new slice.
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
// It reads up to maxStringLen bytes.
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
