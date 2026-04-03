package heuristic_test

import (
	"testing"

	"github.com/local/gbrl/internal/heuristic"
)

func TestShannonEntropy_HighForRandom(t *testing.T) {
	// Uniform byte distribution → entropy close to 8.
	buf := make([]byte, 256)
	for i := range buf {
		buf[i] = byte(i)
	}
	h := heuristic.ShannonEntropy(buf)
	if h < 7.9 {
		t.Errorf("expected high entropy for uniform dist, got %.4f", h)
	}
}

func TestShannonEntropy_LowForConstant(t *testing.T) {
	buf := make([]byte, 256) // all zeros
	h := heuristic.ShannonEntropy(buf)
	if h != 0 {
		t.Errorf("expected zero entropy for constant buf, got %.4f", h)
	}
}

func TestEntropyTracker_Fires(t *testing.T) {
	et := heuristic.NewEntropyTracker(7.0, 3)

	// Build a near-uniform (high-entropy) buffer.
	highEntropy := make([]byte, 1024)
	for i := range highEntropy {
		highEntropy[i] = byte(i % 256)
	}

	fired := false
	for i := 0; i < 5; i++ {
		if et.Observe(1, highEntropy) {
			fired = true
			break
		}
	}
	if !fired {
		t.Error("EntropyTracker should have fired after 3 high-entropy writes")
	}
}

func TestEntropyTracker_NoFireOnLowEntropy(t *testing.T) {
	et := heuristic.NewEntropyTracker(7.0, 3)
	low := []byte("hello world this is plain text with low entropy")
	for i := 0; i < 10; i++ {
		if et.Observe(1, low) {
			t.Error("should not fire on low-entropy data")
		}
	}
}

func BenchmarkShannonEntropy(b *testing.B) {
	buf := make([]byte, 8192)
	for i := range buf {
		buf[i] = byte(i % 256)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = heuristic.ShannonEntropy(buf)
	}
}
