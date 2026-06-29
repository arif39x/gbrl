package executor

import (
	"context"
	"crypto/rand"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"golang.org/x/sys/unix"

	"github.com/local/gbrl/internal/interceptor"
)

// buildWASIWithOverrides exports all standard WASI functions, then overrides
// the ones that need interceptor hooks or that crash due to nil Sys context.
func buildWASIWithOverrides(builder wazero.HostModuleBuilder, intercept interceptor.SyscallInterceptor) {
	// Export all standard WASI functions first.
	wasi_snapshot_preview1.NewFunctionExporter().ExportFunctions(builder)

	// Override clock functions (they access internal Sys context which is nil).
	builder.NewFunctionBuilder().WithFunc(func(ctx context.Context, id uint32, resultResolution uint32) uint32 {
		// clock_res_get — use module only via ctx if needed
		_ = ctx
		_ = resultResolution
		_ = id
		return wasiErrnoSuccess
	}).WithName("clock_res_get").Export("clock_res_get")

	builder.NewFunctionBuilder().WithGoModuleFunction(
		api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			id := uint32(stack[0])
			precision := uint64(stack[1])
			resultTimestamp := uint32(stack[2])
			_ = precision
			mem := mod.Memory()

			decision := intercept.OnClockGet(id)
			switch decision {
			case interceptor.DecisionDeny:
				stack[0] = uint64(wasiErrnoInval)
				return
			case interceptor.DecisionFreeze:
				select {}
			}

			var ns int64
			switch id {
			case 0: // realtime
				ns = time.Now().UnixNano()
			case 1: // monotonic
				ns = time.Now().UnixNano()
			default:
				stack[0] = uint64(wasiErrnoInval)
				return
			}
			if !mem.WriteUint64Le(resultTimestamp, uint64(ns)) {
				stack[0] = uint64(wasiErrnoFault)
				return
			}
			stack[0] = uint64(wasiErrnoSuccess)
		}),
		[]api.ValueType{api.ValueTypeI32, api.ValueTypeI64, api.ValueTypeI32},
		[]api.ValueType{api.ValueTypeI32},
	).WithName("clock_time_get").Export("clock_time_get")

	// Override fd_write to intercept via the policy engine.
	builder.NewFunctionBuilder().WithGoModuleFunction(
		api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			fd := int32(stack[0])
			iovs := uint32(stack[1])
			iovsCount := uint32(stack[2])
			resultNwritten := uint32(stack[3])
			mem := mod.Memory()

			total, errno := doWritev(mem, fd, iovs, iovsCount, intercept)
			if errno != wasiErrnoSuccess {
				stack[0] = uint64(errno)
				return
			}
			if !mem.WriteUint32Le(resultNwritten, total) {
				stack[0] = uint64(wasiErrnoFault)
				return
			}
			stack[0] = uint64(wasiErrnoSuccess)
		}),
		[]api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32},
		[]api.ValueType{api.ValueTypeI32},
	).WithName("fd_write").Export("fd_write")

	// Override path_open to intercept via policy.
	builder.NewFunctionBuilder().WithGoModuleFunction(
		api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			wasiPathOpen(ctx, mod, stack, intercept)
		}),
		[]api.ValueType{
			api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32,
			api.ValueTypeI32, api.ValueTypeI64, api.ValueTypeI64, api.ValueTypeI32,
			api.ValueTypeI32,
		},
		[]api.ValueType{api.ValueTypeI32},
	).WithName("path_open").Export("path_open")

	// Override poll_oneoff to avoid nil Sys context crash.
	builder.NewFunctionBuilder().WithGoModuleFunction(
		api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			in := uint32(stack[0])
			out := uint32(stack[1])
			nsubscriptions := uint32(stack[2])
			resultNevents := uint32(stack[3])
			mem := mod.Memory()

			if nsubscriptions == 0 {
				stack[0] = uint64(wasiErrnoInval)
				return
			}

			inBuf, ok := mem.Read(in, nsubscriptions*48)
			if !ok {
				stack[0] = uint64(wasiErrnoFault)
				return
			}
			outBuf, ok := mem.Read(out, nsubscriptions*32)
			if !ok {
				stack[0] = uint64(wasiErrnoFault)
				return
			}
			for i := range outBuf {
				outBuf[i] = 0
			}

			var minTimeout time.Duration = 1<<63 - 1
			var nevents uint32

			for i := uint32(0); i < nsubscriptions; i++ {
				inOff := i * 48
				outOff := nevents * 32
				eventType := inBuf[inOff+8]

				// Copy userdata
				copy(outBuf[outOff:outOff+8], inBuf[inOff:inOff+8])

				switch eventType {
				case 0: // clock
					timeout := leUint64(inBuf[inOff+24:])
					if timeout < uint64(minTimeout) {
						minTimeout = time.Duration(timeout)
					}
					// event: [8:10]errno=0, [10:14]eventType=0 (clock)
					outBuf[outOff+8] = 0
					outBuf[outOff+9] = 0
					outBuf[outOff+10] = eventType
					nevents++
				case 1: // fd_read
					outBuf[outOff+8] = uint8(wasiErrnoNotsup & 0xff)
					outBuf[outOff+9] = uint8(wasiErrnoNotsup >> 8)
					outBuf[outOff+10] = eventType
					nevents++
				case 2: // fd_write
					outBuf[outOff+8] = uint8(wasiErrnoNotsup & 0xff)
					outBuf[outOff+9] = uint8(wasiErrnoNotsup >> 8)
					outBuf[outOff+10] = eventType
					nevents++
				default:
					stack[0] = uint64(wasiErrnoInval)
					return
				}
			}

			if !mem.WriteUint32Le(resultNevents, nevents) {
				stack[0] = uint64(wasiErrnoFault)
				return
			}

			if minTimeout > 0 && minTimeout < 1<<63-1 {
				time.Sleep(minTimeout)
			}
			stack[0] = uint64(wasiErrnoSuccess)
		}),
		[]api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32},
		[]api.ValueType{api.ValueTypeI32},
	).WithName("poll_oneoff").Export("poll_oneoff")

	// Override random_get to use crypto/rand instead of the deterministic default.
	builder.NewFunctionBuilder().WithGoModuleFunction(
		api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			buf := uint32(stack[0])
			bufLen := uint32(stack[1])
			mem := mod.Memory()

			data := make([]byte, bufLen)
			if _, err := rand.Read(data); err != nil {
				stack[0] = uint64(wasiErrnoIo)
				return
			}
			if !mem.Write(buf, data) {
				stack[0] = uint64(wasiErrnoFault)
				return
			}
			stack[0] = uint64(wasiErrnoSuccess)
		}),
		[]api.ValueType{api.ValueTypeI32, api.ValueTypeI32},
		[]api.ValueType{api.ValueTypeI32},
	).WithName("random_get").Export("random_get")
}

// ─── Override implementations ──────────────────────────────────────────────

func doWritev(mem api.Memory, fd int32, iovs uint32, iovsCount uint32, intercept interceptor.SyscallInterceptor) (uint32, uint32) {
	iovsBuf, ok := mem.Read(iovs, iovsCount*8)
	if !ok {
		return 0, wasiErrnoFault
	}

	var total uint32
	for i := uint32(0); i < iovsCount; i++ {
		base := leUint32(iovsBuf[i*8:])
		length := leUint32(iovsBuf[i*8+4:])
		if length == 0 {
			continue
		}

		buf, ok := mem.Read(base, length)
		if !ok {
			return total, wasiErrnoFault
		}

		decision := intercept.OnWriteBuffer(fd, buf)
		switch decision {
		case interceptor.DecisionAllow, interceptor.DecisionAllowAndLog:
			if fd == 1 || fd == 2 {
				writeToFD(int(fd), buf)
			}
			total += length
		case interceptor.DecisionDeny:
			return total, wasiErrnoIo
		case interceptor.DecisionFreeze:
			select {}
		case interceptor.DecisionDump:
			total += length
		default:
			if fd == 1 || fd == 2 {
				writeToFD(int(fd), buf)
			}
			total += length
		}
	}
	return total, wasiErrnoSuccess
}

func wasiPathOpen(ctx context.Context, mod api.Module, stack []uint64, intercept interceptor.SyscallInterceptor) {
	_ = ctx
	_ = int32(stack[0])  // dirfd
	_ = uint32(stack[1])  // dirflags
	pathOff := uint32(stack[2])
	pathLen := uint32(stack[3])
	_ = uint64(stack[4])  // oflags
	resultFD := uint32(stack[8])
	mem := mod.Memory()

	pathBytes, ok := mem.Read(pathOff, pathLen)
	if !ok {
		stack[0] = uint64(wasiErrnoFault)
		return
	}
	pathStr := string(pathBytes)

	decision := intercept.OnOpenFile(pathStr, 0, 0)
	switch decision {
	case interceptor.DecisionDeny:
		stack[0] = uint64(wasiErrnoAcces)
		return
	case interceptor.DecisionFreeze:
		select {}
	}

	if !mem.WriteUint32Le(resultFD, uint32(42)) {
		stack[0] = uint64(wasiErrnoFault)
		return
	}
	stack[0] = uint64(wasiErrnoSuccess)
}

func writeToFD(fd int, p []byte) {
	if len(p) == 0 {
		return
	}
	for len(p) > 0 {
		n, err := unix.Write(fd, p)
		if n < 0 {
			n = 0
		}
		if err != nil {
			return
		}
		p = p[n:]
	}
}

// ─── WASI errno constants ──────────────────────────────────────────────────

const (
	wasiErrnoSuccess uint32 = 0
	wasiErrnoAcces   uint32 = 2
	wasiErrnoBadf    uint32 = 8
	wasiErrnoFault   uint32 = 21
	wasiErrnoInval   uint32 = 28
	wasiErrnoIo      uint32 = 29
	wasiErrnoNotsup  uint32 = 35
)

func leUint32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func leUint64(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}

