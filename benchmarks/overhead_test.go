// Package benchmarks measures the per-syscall overhead GBRL introduces
// compared to a native subprocess execution.
//
// Methodology:
//
//	BenchmarkNative   — spawns /bin/true via exec.Command with no tracing.
//	BenchmarkGBRL     — spawns /bin/true under the full GBRL ptrace loop.
//
// Both benchmarks run b.N iterations so that go test normalises to ns/op.
// The delta (GBRL - Native) attributable to ptrace overhead is:
//
//	Δ = (GBRL ns/op) − (Native ns/op)
//
// Expected result on modern hardware: ~500 µs – 2 ms per /bin/true run
// (dominated by ptrace context switch + wait4 pairs), scaling linearly with
// the number of syscalls the child makes.
package benchmarks

import (
	"log"
	"os"
	"os/exec"
	"testing"

	"github.com/local/gbrl/internal/heuristic"
	"github.com/local/gbrl/internal/launcher"
	"github.com/local/gbrl/internal/monitor"
	"github.com/local/gbrl/internal/policy"
	"github.com/local/gbrl/internal/telemetry"
)

// BenchmarkNative measures bare subprocess execution cost.
func BenchmarkNative(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		cmd := exec.Command("/bin/true")
		if err := cmd.Run(); err != nil {
			b.Fatalf("native run: %v", err)
		}
	}
}

// BenchmarkGBRL measures the same command through the full ptrace loop.
// Must be run with CAP_SYS_PTRACE (i.e. sudo or a privileged test user).
func BenchmarkGBRL(b *testing.B) {
	pol, _ := policy.Load("") // open (allow-all) policy
	logger := log.New(os.Stderr, "", 0)

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		rb := telemetry.NewRingBuffer[telemetry.LogEvent](1 << 10)
		entropy := heuristic.NewEntropyTracker(
			pol.Heuristic.EntropyThreshold,
			pol.Heuristic.MaxHighEntropyWrites,
		)

		pid, err := launcher.Start(launcher.Config{
			Args:           []string{"/bin/true"},
			IsolateNetwork: false,
			IsolateMount:   false,
			IsolatePID:     false,
		})
		if err != nil {
			b.Skipf("launcher.Start: %v (run with sudo)", err)
		}

		monCfg := monitor.Config{
			PID:     pid,
			Pol:     pol,
			RingBuf: rb,
			Entropy: entropy,
			Logger:  logger,
		}
		if err := monitor.Run(monCfg); err != nil {
			b.Fatalf("monitor: %v", err)
		}
	}
}
