// Package executor handles the setup and lifecycle of WASM guest modules.
// It wraps the wazero runtime, provides custom WASI implementations for
// interception, and manages guest memory access.
package executor

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/sys"

	"github.com/local/gbrl/internal/interceptor"
)

// GuestConfig defines the environment and constraints for a WASM guest.
type GuestConfig struct {
	// WASMBytes contains the compiled binary data of the .wasm module.
	WASMBytes []byte

	// Args provides the command-line arguments the guest will see.
	Args []string

	// SandboxRoot specifies the host directory to mount as the guest's root (/).
	// Filesystem access is disabled if this is left empty.
	SandboxRoot string

	// MaxMemoryPages sets the upper bound for the guest's linear memory.
	// Each page is 64 KiB. Defaults to 256 (16 MiB) if not specified.
	MaxMemoryPages uint32

	// Interceptor handles all policy decisions for WASI system calls.
	// If unset, it defaults to allowing all calls.
	Interceptor interceptor.SyscallInterceptor
}

// GuestExecutor manages a single execution instance of a WASM guest.
type GuestExecutor struct {
	runtime   wazero.Runtime
	module    api.Module
	pid       int32
	closed    bool
	intercept interceptor.SyscallInterceptor
	ctx       context.Context
	cancel    context.CancelFunc
}

// New initializes an empty GuestExecutor ready for loading.
func New() *GuestExecutor {
	return &GuestExecutor{}
}

// Load prepares the WASM module for execution. It sets up the runtime,
// compiles the binary, and configures the sandbox—including custom WASI
// function overrides and filesystem mounts.
func (g *GuestExecutor) Load(ctx context.Context, cfg GuestConfig) error {
	if g.runtime != nil {
		return fmt.Errorf("executor: already loaded")
	}

	if cfg.Interceptor == nil {
		cfg.Interceptor = interceptor.AllowAllInterceptor{}
	}
	g.intercept = cfg.Interceptor

	g.ctx, g.cancel = context.WithCancel(ctx)

	runtimeConfig := wazero.NewRuntimeConfigInterpreter()
	g.runtime = wazero.NewRuntimeWithConfig(g.ctx, runtimeConfig)

	// Instantiate a custom WASI module with overridden functions.
	builder := g.runtime.NewHostModuleBuilder("wasi_snapshot_preview1")
	buildWASIWithOverrides(builder, g.intercept)
	if _, err := builder.Instantiate(g.ctx); err != nil {
		g.runtime.Close(g.ctx)
		g.runtime = nil
		return fmt.Errorf("executor: instantiate WASI module: %w", err)
	}

	// Compile the guest WASM binary.
	compiled, err := g.runtime.CompileModule(g.ctx, cfg.WASMBytes)
	if err != nil {
		g.runtime.Close(g.ctx)
		g.runtime = nil
		return fmt.Errorf("executor: compile module: %w", err)
	}

	maxPages := cfg.MaxMemoryPages
	if maxPages == 0 {
		maxPages = 256
	}

	modConfig := wazero.NewModuleConfig().
		WithName(fmt.Sprintf("gbrl-guest-%d", time.Now().UnixNano())).
		WithArgs(cfg.Args...).
		WithStartFunctions().
		WithStdin(nil).
		WithStdout(nil).
		WithStderr(nil)

	if cfg.SandboxRoot != "" {
		modConfig = modConfig.WithFSConfig(
			wazero.NewFSConfig().WithDirMount(cfg.SandboxRoot, "/"),
		)
	}

	mod, err := g.runtime.InstantiateModule(g.ctx, compiled, modConfig)
	if err != nil {
		g.runtime.Close(g.ctx)
		g.runtime = nil
		return fmt.Errorf("executor: instantiate module: %w", err)
	}

	g.module = mod
	g.pid = int32(hashModuleName(mod.Name()))
	return nil
}

// Run executes the guest's entry point (_start) and blocks until it finishes.
// It returns the guest's exit code or an error if the execution failed.
func (g *GuestExecutor) Run(ctx context.Context) (exitCode uint32, err error) {
	if g.module == nil {
		return 0, fmt.Errorf("executor: not loaded")
	}
	start := g.module.ExportedFunction("_start")
	if start == nil {
		return 0, fmt.Errorf("executor: no _start function")
	}
	_, err = start.Call(ctx)
	if err != nil {
		if exitErr, ok := err.(*sys.ExitError); ok {
			return exitErr.ExitCode(), nil
		}
		return 0, err
	}
	return 0, nil
}

func (g *GuestExecutor) Terminate(exitCode uint32) error {
	if g.closed {
		return nil
	}
	g.closed = true
	if g.cancel != nil {
		g.cancel()
	}
	if g.module != nil {
		g.module.CloseWithExitCode(g.ctx, exitCode)
		g.module = nil
	}
	if g.runtime != nil {
		g.runtime.Close(g.ctx)
		g.runtime = nil
	}
	return nil
}

// ReadGuestMemory fetches a raw block of data from the guest's linear memory.
func (g *GuestExecutor) ReadGuestMemory(addr uint32, n uint32) ([]byte, error) {
	if g.module == nil {
		return nil, fmt.Errorf("executor: not loaded")
	}
	mem := g.module.Memory()
	if mem == nil {
		return nil, fmt.Errorf("executor: no memory")
	}
	data, ok := mem.Read(addr, n)
	if !ok {
		return nil, fmt.Errorf("executor: read memory at 0x%x size %d: out of bounds", addr, n)
	}
	buf := make([]byte, len(data))
	copy(buf, data)
	return buf, nil
}

func (g *GuestExecutor) DumpMemory(path string) error {
	if g.module == nil {
		return fmt.Errorf("executor: not loaded")
	}
	mem := g.module.Memory()
	if mem == nil {
		return fmt.Errorf("executor: no memory")
	}
	size := mem.Size()
	data, ok := mem.Read(0, size)
	if !ok {
		return fmt.Errorf("executor: read memory at 0 size=%d: out of bounds", size)
	}
	return os.WriteFile(path, data, 0644)
}

func (g *GuestExecutor) PID() int32 {
	return g.pid
}

func hashModuleName(s string) int32 {
	var h uint32
	for _, c := range []byte(s) {
		h = h*31 + uint32(c)
	}
	return int32(h & 0x7fffffff)
}

