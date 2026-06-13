// Package benchmarks compares the per-syscall overhead of GBRL against
// native subprocess execution.
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

// BenchmarkNative measures the cost of bare subprocess execution.
func BenchmarkNative(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		cmd := exec.Command("/bin/true")
		if err := cmd.Run(); err != nil {
			b.Fatalf("native run: %v", err)
		}
	}
}

// BenchmarkGBRL measures command execution through the full GBRL ptrace loop.
// It requires CAP_SYS_PTRACE privileges.
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
