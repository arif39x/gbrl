// Package telemetry provides a lock-free ring buffer for non-blocking
// event logging in the hot ptrace path.
// Each syscall stop already incurs ~1–2 µs of kernel round-trip
// latency (context switch into the kernel, wait4 wakeup, register read).
// Any blocking mutex inside the event-logging path would serialize multiple
// tracee threads and amplify that latency. A power-of-2 ring buffer with
// sync/atomic head/tail cursors provides SPSC (single-producer /
// single-consumer) lock-free semantics the monitor goroutine pushes without
// ever blocking, and the CSV writer goroutine drains at its own pace.
package telemetry

import (
	"errors"
	"sync/atomic"
)

// ErrFull is returned by Push when the buffer has no free slots.
var ErrFull = errors.New("ring buffer full")

// ErrEmpty is returned by Pop when no events are available.
var ErrEmpty = errors.New("ring buffer empty")

// RingBuffer is a generic lock-free SPSC ring buffer.
// Capacity MUST be a power of two.
type RingBuffer[T any] struct {
	buf  []T
	mask uint64
	head atomic.Uint64 // written by producer
	tail atomic.Uint64 // written by consumer
}

// NewRingBuffer creates a RingBuffer with the given capacity.
// Panics if cap is not a power of two or is zero.
func NewRingBuffer[T any](cap uint64) *RingBuffer[T] {
	if cap == 0 || (cap&(cap-1)) != 0 {
		panic("ring buffer capacity must be a non-zero power of two")
	}
	return &RingBuffer[T]{
		buf:  make([]T, cap),
		mask: cap - 1,
	}
}

// Push enqueues an item without blocking.
// Returns ErrFull if the buffer is at capacity.
func (r *RingBuffer[T]) Push(item T) error {
	head := r.head.Load()
	tail := r.tail.Load()
	if head-tail > r.mask {
		return ErrFull
	}
	r.buf[head&r.mask] = item
	r.head.Store(head + 1)
	return nil
}

// Pop dequeues an item without blocking.
// Returns ErrEmpty if the buffer is empty.
func (r *RingBuffer[T]) Pop() (T, error) {
	var zero T
	tail := r.tail.Load()
	if r.head.Load() == tail {
		return zero, ErrEmpty
	}
	item := r.buf[tail&r.mask]
	r.tail.Store(tail + 1)
	return item, nil
}

// Len returns an approximate count of queued items.
func (r *RingBuffer[T]) Len() int {
	return int(r.head.Load() - r.tail.Load())
}
