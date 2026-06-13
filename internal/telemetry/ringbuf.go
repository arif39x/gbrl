// Package telemetry implements a lock-free, single-producer single-consumer (SPSC)
// ring buffer for non-blocking event logging. It minimizes latency in the hot
// ptrace path by avoiding mutex serialization between tracee threads and
// the telemetry drainer.
package telemetry

import (
	"errors"
	"sync/atomic"
)

// ErrFull indicates the buffer has no free slots.
var ErrFull = errors.New("ring buffer full")

// ErrEmpty indicates no events are available for consumption.
var ErrEmpty = errors.New("ring buffer empty")

// RingBuffer is a generic lock-free SPSC ring buffer.
// Capacity must be a power of two.
type RingBuffer[T any] struct {
	buf  []T
	mask uint64
	head atomic.Uint64 // written by producer
	tail atomic.Uint64 // written by consumer
}

// NewRingBuffer returns a new RingBuffer with the specified capacity.
// It panics if cap is zero or not a power of two.
func NewRingBuffer[T any](cap uint64) *RingBuffer[T] {
	if cap == 0 || (cap&(cap-1)) != 0 {
		panic("ring buffer capacity must be a non-zero power of two")
	}
	return &RingBuffer[T]{
		buf:  make([]T, cap),
		mask: cap - 1,
	}
}

// Push adds an item to the buffer without blocking.
// It returns ErrFull if the buffer is at capacity.
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

// Pop removes and returns an item from the buffer without blocking.
// It returns ErrEmpty if the buffer is empty.
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

// Len returns the approximate number of queued items.
func (r *RingBuffer[T]) Len() int {
	return int(r.head.Load() - r.tail.Load())
}
