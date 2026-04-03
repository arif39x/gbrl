// Package telemetry provides CSV-based event logging backed by the lock-free
// ring buffer. The CSV writer runs in its own goroutine, draining the buffer
// and flushing records to disk without interfering with the tracer loop.
package telemetry

import (
	"encoding/csv"
	"fmt"
	"os"
	"sync"
	"time"
)

// LogEvent captures a single syscall interception record.
type LogEvent struct {
	Timestamp   time.Time
	PID         int
	SyscallNr   uint64
	SyscallName string
	Args        [6]uint64
	ReturnVal   uint64
	Action      string // Allow | Kill | Freeze | Deny
}

// CSVWriter drains a RingBuffer[LogEvent] and writes CSV rows to a file.
type CSVWriter struct {
	rb   *RingBuffer[LogEvent]
	w    *csv.Writer
	f    *os.File
	done chan struct{}
	wg   sync.WaitGroup
}

// NewCSVWriter opens path for appending and returns a CSVWriter.
func NewCSVWriter(path string, rb *RingBuffer[LogEvent]) (*CSVWriter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open log file %q: %w", path, err)
	}
	w := csv.NewWriter(f)
	cw := &CSVWriter{rb: rb, w: w, f: f, done: make(chan struct{})}

	// Write header only if the file is brand new (zero size).
	info, _ := f.Stat()
	if info.Size() == 0 {
		_ = w.Write([]string{
			"timestamp", "pid", "syscall_nr", "syscall_name",
			"arg0", "arg1", "arg2", "arg3", "arg4", "arg5",
			"return_val", "action",
		})
		w.Flush()
	}
	return cw, nil
}

// Start launches the background drain goroutine.
func (cw *CSVWriter) Start() {
	cw.wg.Add(1)
	go func() {
		defer cw.wg.Done()
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-cw.done:
				cw.drain()
				cw.w.Flush()
				cw.f.Close()
				return
			case <-ticker.C:
				cw.drain()
				cw.w.Flush()
			}
		}
	}()
}

// Stop signals the writer to flush and exit.
func (cw *CSVWriter) Stop() {
	close(cw.done)
	cw.wg.Wait()
}

func (cw *CSVWriter) drain() {
	for {
		ev, err := cw.rb.Pop()
		if err != nil {
			return
		}
		row := []string{
			ev.Timestamp.UTC().Format(time.RFC3339Nano),
			fmt.Sprintf("%d", ev.PID),
			fmt.Sprintf("%d", ev.SyscallNr),
			ev.SyscallName,
			fmt.Sprintf("%d", ev.Args[0]),
			fmt.Sprintf("%d", ev.Args[1]),
			fmt.Sprintf("%d", ev.Args[2]),
			fmt.Sprintf("%d", ev.Args[3]),
			fmt.Sprintf("%d", ev.Args[4]),
			fmt.Sprintf("%d", ev.Args[5]),
			fmt.Sprintf("%d", ev.ReturnVal),
			ev.Action,
		}
		_ = cw.w.Write(row)
	}
}
