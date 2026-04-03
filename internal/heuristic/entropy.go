// Package heuristic implements Shannon-entropy based ransomware detection.
//
// Research Context
// Shannon entropy H(X) = -Σ p(x) log₂ p(x) where the sum is over all 256
// possible byte values. Random / encrypted / compressed data has H ≈ 8 bits
// per byte. Ransomware exhibits a characteristic burst pattern: many write(2)
// calls across different file descriptors with near-maximum entropy content,
// occurring densely in time (encrypting a subtree quickly to maximise damage
// before detection).
//
// GBRL's detector maintains per-FD sliding state. When a process exceeds the
// configured threshold of high-entropy write events it is flagged for Freeze:
// the ptrace lock holds the child in stopped state while the operator receives
// an alert, preserving forensic state without allowing further encryption.
package heuristic

import (
	"math"
	"sync"
)

// EntropyThreshold is the default Shannon entropy above which a write is
// considered "high entropy" (fully encrypted content approaches 8.0).
const EntropyThreshold = 7.2

// ShannonEntropy computes the Shannon entropy (bits per byte) of buf.
// Returns 0 for empty input.
func ShannonEntropy(buf []byte) float64 {
	if len(buf) == 0 {
		return 0
	}
	var freq [256]int
	for _, b := range buf {
		freq[b]++
	}
	entropy := 0.0
	n := float64(len(buf))
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// fdState tracks high-entropy write count for a single file descriptor.
type fdState struct {
	count int
}

// EntropyTracker maintains per-FD write entropy state across the lifetime
// of a process. It is safe for concurrent use.
type EntropyTracker struct {
	mu        sync.Mutex
	fds       map[uint64]*fdState
	threshold float64
	maxHits   int
}

// NewEntropyTracker creates a tracker with configurable parameters.
func NewEntropyTracker(threshold float64, maxHits int) *EntropyTracker {
	return &EntropyTracker{
		fds:       make(map[uint64]*fdState),
		threshold: threshold,
		maxHits:   maxHits,
	}
}

// Observe records a write of buf to fd. Returns true when the cumulative
// high-entropy write count for that fd crosses the alarm threshold.
func (et *EntropyTracker) Observe(fd uint64, buf []byte) bool {
	h := ShannonEntropy(buf)
	if h < et.threshold {
		return false
	}
	et.mu.Lock()
	defer et.mu.Unlock()
	s, ok := et.fds[fd]
	if !ok {
		s = &fdState{}
		et.fds[fd] = s
	}
	s.count++
	return s.count >= et.maxHits
}

// Reset clears state for an fd (e.g. after it is closed).
func (et *EntropyTracker) Reset(fd uint64) {
	et.mu.Lock()
	delete(et.fds, fd)
	et.mu.Unlock()
}
