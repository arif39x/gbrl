package telemetry_test

import (
	"testing"

	"github.com/local/gbrl/internal/telemetry"
)

func TestRingBuffer_PushPop(t *testing.T) {
	rb := telemetry.NewRingBuffer[int](4)

	for i := 0; i < 4; i++ {
		if err := rb.Push(i); err != nil {
			t.Fatalf("Push(%d): %v", i, err)
		}
	}

	// Buffer is full — next push must fail.
	if err := rb.Push(99); err != telemetry.ErrFull {
		t.Fatalf("expected ErrFull, got %v", err)
	}

	for i := 0; i < 4; i++ {
		v, err := rb.Pop()
		if err != nil {
			t.Fatalf("Pop: %v", err)
		}
		if v != i {
			t.Fatalf("want %d got %d", i, v)
		}
	}

	// Buffer is empty — next pop must fail.
	if _, err := rb.Pop(); err != telemetry.ErrEmpty {
		t.Fatalf("expected ErrEmpty, got %v", err)
	}
}

func TestRingBuffer_NonPowerOfTwo_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for non-power-of-two capacity")
		}
	}()
	telemetry.NewRingBuffer[int](3)
}

func BenchmarkRingBuffer_Push(b *testing.B) {
	rb := telemetry.NewRingBuffer[int](1 << 16)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := rb.Push(i); err != nil {
			// Drain when full to keep benchmark steady.
			_, _ = rb.Pop()
			_ = rb.Push(i)
		}
	}
}
