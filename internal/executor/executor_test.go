package executor_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/local/gbrl/internal/executor"
	"github.com/local/gbrl/internal/interceptor"
)

// recordingInterceptor embeds AllowAllInterceptor but records every call.
type recordingInterceptor struct {
	interceptor.AllowAllInterceptor

	writeBufferCalled bool
	onWriteBufferFD   int32
	onWriteBufferBuf  []byte

	onClockGetCalled bool
	onClockGetID     uint32

	onOpenFileCalled bool
	openFilePath     string
}

func (r *recordingInterceptor) OnWriteBuffer(fd int32, buf []byte) interceptor.PolicyDecision {
	r.writeBufferCalled = true
	r.onWriteBufferFD = fd
	r.onWriteBufferBuf = make([]byte, len(buf))
	copy(r.onWriteBufferBuf, buf)
	return r.AllowAllInterceptor.OnWriteBuffer(fd, buf)
}

func (r *recordingInterceptor) OnClockGet(clockID uint32) interceptor.PolicyDecision {
	r.onClockGetCalled = true
	r.onClockGetID = clockID
	return r.AllowAllInterceptor.OnClockGet(clockID)
}

func (r *recordingInterceptor) OnOpenFile(path string, dirfd int32, oflags uint16) interceptor.PolicyDecision {
	r.onOpenFileCalled = true
	r.openFilePath = path
	return r.AllowAllInterceptor.OnOpenFile(path, dirfd, oflags)
}

func TestRecordingInterceptor_HelloWasm(t *testing.T) {
	wasmBytes, err := os.ReadFile("testdata/hello.wasm")
	if err != nil {
		t.Fatal("read hello.wasm:", err)
	}

	rec := &recordingInterceptor{}
	exec := executor.New()

	err = exec.Load(context.Background(), executor.GuestConfig{
		WASMBytes:   wasmBytes,
		Args:        []string{"hello"},
		Interceptor: rec,
	})
	if err != nil {
		exec.Terminate(0)
		t.Fatal("Load:", err)
	}
	defer exec.Terminate(0)

	exitCode, err := exec.Run(context.Background())
	if err != nil {
		t.Fatal("Run:", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	if !rec.writeBufferCalled {
		t.Error("OnWriteBuffer was not called")
	} else {
		if rec.onWriteBufferFD != 1 {
			t.Errorf("OnWriteBuffer fd: want 1, got %d", rec.onWriteBufferFD)
		}
		if !strings.Contains(string(rec.onWriteBufferBuf), "hello from wasm!") {
			t.Errorf("OnWriteBuffer buf does not contain %q: got %q", "hello from wasm!", string(rec.onWriteBufferBuf))
		}
	}

	if !rec.onClockGetCalled {
		t.Error("OnClockGet was not called")
	}
}

// denyInterceptor returns DecisionDeny for every intercepted call.
type denyInterceptor struct{}

func (denyInterceptor) OnOpenFile(path string, dirfd int32, oflags uint16) interceptor.PolicyDecision {
	return interceptor.DecisionDeny
}

func (denyInterceptor) OnWriteBuffer(fd int32, buf []byte) interceptor.PolicyDecision {
	return interceptor.DecisionDeny
}

func (denyInterceptor) OnNetworkConnect(addr string, port uint16) interceptor.PolicyDecision {
	return interceptor.DecisionDeny
}

func (denyInterceptor) OnExecve(path string, args []string) interceptor.PolicyDecision {
	return interceptor.DecisionDeny
}

func (denyInterceptor) OnRandomGet(buf []byte) interceptor.PolicyDecision {
	return interceptor.DecisionDeny
}

func (denyInterceptor) OnClockGet(clockID uint32) interceptor.PolicyDecision {
	return interceptor.DecisionDeny
}

func TestDenyInterceptor_HelloWasm(t *testing.T) {
	wasmBytes, err := os.ReadFile("testdata/hello.wasm")
	if err != nil {
		t.Fatal("read hello.wasm:", err)
	}

	exec := executor.New()
	err = exec.Load(context.Background(), executor.GuestConfig{
		WASMBytes:   wasmBytes,
		Args:        []string{"hello"},
		Interceptor: denyInterceptor{},
	})
	if err != nil {
		t.Log("Load denied (expected):", err)
		return
	}
	defer exec.Terminate(0)

	_, err = exec.Run(context.Background())
	if err == nil {
		t.Error("expected error from Run with deny interceptor, got nil")
	} else {
		t.Log("Run denied (expected):", err)
	}
}
