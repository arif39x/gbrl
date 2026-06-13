// Package interceptor provides the core interface for mediating guest system
// calls. It defines how the host evaluates and responds to WASI imports,
// ensuring that every sensitive operation is checked against a policy before
// it can proceed.
//
// To prevent TOCTOU (time-of-check to time-of-use) vulnerabilities, all data
// is copied from the guest's memory into the host before being passed to these
// hooks. Performance is critical: implementations should aim for sub-100µs
// response times and must avoid blocking I/O.
package interceptor

// PolicyDecision represents the outcome of a policy evaluation.
type PolicyDecision int

const (
	// DecisionAllow permits the operation to proceed normally.
	DecisionAllow PolicyDecision = iota
	// DecisionDeny blocks the operation, usually returning an error to the guest.
	DecisionDeny
	// DecisionAllowAndLog permits the operation but ensures it is recorded.
	DecisionAllowAndLog
	// DecisionFreeze suspends the guest's execution indefinitely.
	DecisionFreeze
	// DecisionDump triggers a memory or state dump for later analysis.
	DecisionDump
)

func (d PolicyDecision) String() string {
	switch d {
	case DecisionAllow:
		return "Allow"
	case DecisionDeny:
		return "Deny"
	case DecisionAllowAndLog:
		return "AllowAndLog"
	case DecisionFreeze:
		return "Freeze"
	case DecisionDump:
		return "Dump"
	default:
		return "Unknown"
	}
}

// SyscallInterceptor defines the set of hooks used to mediate every WASI
// call made by the guest. A concrete implementation typically integrates
// policy evaluation, behavioral analysis, and telemetry logging.
type SyscallInterceptor interface {
	// OnOpenFile mediates WASI path_open. The path has been pre-canonicalized
	// and copied from guest memory to prevent TOCTOU issues.
	OnOpenFile(path string, dirfd int32, oflags uint16) PolicyDecision

	// OnWriteBuffer mediates WASI fd_write. The buffer is a host-owned copy of
	// the guest's data, limited to a reasonable size (e.g., 1 MiB).
	OnWriteBuffer(fd int32, buf []byte) PolicyDecision

	// OnNetworkConnect mediates WASI sock_connect requests.
	OnNetworkConnect(addr string, port uint16) PolicyDecision

	// OnExecve mediates WASI proc_spawn (process creation).
	OnExecve(path string, args []string) PolicyDecision

	// OnRandomGet mediates WASI random_get, allowing the host to control or
	// monitor the guest's source of entropy.
	OnRandomGet(buf []byte) PolicyDecision

	// OnClockGet mediates WASI clock_time_get, which can be used to mitigate
	// side-channel timing attacks.
	OnClockGet(clockID uint32) PolicyDecision
}

// AllowAllInterceptor is a reference implementation that permits every
// operation. It is useful for benchmarking or as a baseline during development.
type AllowAllInterceptor struct{}

// OnOpenFile permits all file opens in the allow-all interceptor.
func (AllowAllInterceptor) OnOpenFile(path string, dirfd int32, oflags uint16) PolicyDecision {
	return DecisionAllow
}

// OnWriteBuffer permits all writes in the allow-all interceptor.
func (AllowAllInterceptor) OnWriteBuffer(fd int32, buf []byte) PolicyDecision {
	return DecisionAllow
}

// OnNetworkConnect denies all outbound connections in the allow-all
// interceptor, as it is designed for local-only execution.
func (AllowAllInterceptor) OnNetworkConnect(addr string, port uint16) PolicyDecision {
	return DecisionDeny
}

// OnExecve denies all process spawning in the allow-all interceptor to
// prevent the guest from escaping the sandbox.
func (AllowAllInterceptor) OnExecve(path string, args []string) PolicyDecision {
	return DecisionDeny
}

// OnRandomGet permits all random data requests in the allow-all interceptor.
func (AllowAllInterceptor) OnRandomGet(buf []byte) PolicyDecision {
	return DecisionAllow
}

// OnClockGet permits all clock reads in the allow-all interceptor.
func (AllowAllInterceptor) OnClockGet(clockID uint32) PolicyDecision {
	return DecisionAllow
}
