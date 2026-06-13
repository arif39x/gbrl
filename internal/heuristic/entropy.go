// Package heuristic implements Shannon-entropy based ransomware detection.
// It monitors write(2) calls for high-entropy content, which often indicates
// encryption activity.
package heuristic

import (
	"math"
	"sync"
)

// EntropyThreshold defines the Shannon entropy level above which data is
// considered high-entropy (fully encrypted content approaches 8.0).
const EntropyThreshold = 7.2

// ShannonEntropy calculates the Shannon entropy in bits per byte for buf.
// It returns 0 for empty input.
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

// fdState tracks the high-entropy write count for a file descriptor.
type fdState struct {
	count int
}

// EntropyTracker maintains per-FD write entropy state across a process's lifetime.
// It is safe for concurrent use.
type EntropyTracker struct {
	mu        sync.Mutex
	fds       map[uint64]*fdState
	threshold float64
	maxHits   int
}

// NewEntropyTracker returns a tracker with the specified threshold and hit limit.
func NewEntropyTracker(threshold float64, maxHits int) *EntropyTracker {
	return &EntropyTracker{
		fds:       make(map[uint64]*fdState),
		threshold: threshold,
		maxHits:   maxHits,
	}
}

// Observe records a write to fd and returns true if the cumulative high-entropy
// write count for that fd reaches the alarm threshold.
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

// Reset clears the tracked state for an fd.
func (et *EntropyTracker) Reset(fd uint64) {
	et.mu.Lock()
	delete(et.fds, fd)
	et.mu.Unlock()
}
