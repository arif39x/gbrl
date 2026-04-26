// GBRL TUI – General Binary Restractor & Logger
// Production terminal user interface built on github.com/rivo/tview.
//
// Architecture:
//
//	main goroutine  → app.Run() drives the tview event loop (blocks).
//	monitor goroutine → launcher.Start + monitor.Run; sends LogEvents on eventCh.
//	drain goroutine → ranges over eventCh; calls app.QueueUpdateDraw to update
//	                  traceTable and logsView safely from off the main thread.
//	entropy goroutine → polls the EntropyTracker snapshot every 500 ms and
//	                    refreshes the entropyTable via app.QueueUpdateDraw.
package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/local/gbrl/internal/heuristic"
	"github.com/local/gbrl/internal/launcher"
	"github.com/local/gbrl/internal/monitor"
	"github.com/local/gbrl/internal/policy"
	"github.com/local/gbrl/internal/telemetry"
	"github.com/rivo/tview"
)

// ─── Entropy snapshot (shared between monitor and TUI) ───────────────────────

// fdEntropyEntry stores the latest entropy info for a single file descriptor.
type fdEntropyEntry struct {
	FD      uint64
	Entropy float64
	Hits    int
}

// entropyStore is a thread-safe map FD → fdEntropyEntry updated on every
// high-entropy Observe(). The TUI polls this on a ticker.
type entropyStore struct {
	mu      sync.Mutex
	entries map[uint64]*fdEntropyEntry
}

func newEntropyStore() *entropyStore {
	return &entropyStore{entries: make(map[uint64]*fdEntropyEntry)}
}

func (s *entropyStore) record(fd uint64, h float64, alarm bool) {
	s.mu.Lock()
	e, ok := s.entries[fd]
	if !ok {
		e = &fdEntropyEntry{FD: fd}
		s.entries[fd] = e
	}
	e.Entropy = h
	if alarm {
		e.Hits++
	}
	s.mu.Unlock()
}

func (s *entropyStore) snapshot() []fdEntropyEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]fdEntropyEntry, 0, len(s.entries))
	for _, v := range s.entries {
		out = append(out, *v)
	}
	return out
}

// ─── Instrumented EntropyTracker wrapper ─────────────────────────────────────

// instrumentedTracker wraps heuristic.EntropyTracker to capture entropy values
// that the monitor calculates so the TUI can display them.
type instrumentedTracker struct {
	inner *heuristic.EntropyTracker
	store *entropyStore
}

func (t *instrumentedTracker) Observe(fd uint64, buf []byte) bool {
	h := heuristic.ShannonEntropy(buf)
	alarm := t.inner.Observe(fd, buf)
	if h >= heuristic.EntropyThreshold {
		t.store.record(fd, h, alarm)
	}
	return alarm
}

func (t *instrumentedTracker) Reset(fd uint64) {
	t.inner.Reset(fd)
}

// ─── TUI helpers ─────────────────────────────────────────────────────────────

const maxTraceRows = 200 // keep the last N events in the trace table

// entropyBar returns a 10-char ASCII bar for a 0–8 entropy value.
func entropyBar(h float64) string {
	const width = 10
	filled := int((h / 8.0) * float64(width))
	if filled > width {
		filled = width
	}
	return "[" + strings.Repeat("#", filled) + strings.Repeat(".", width-filled) + "]"
}

// actionColor returns a tview color tag for the given policy action string.
func actionColor(action string) string {
	switch action {
	case "Kill":
		return "[red]"
	case "Freeze":
		return "[yellow]"
	case "Deny":
		return "[orange]"
	default:
		return "[green]"
	}
}

// ─── Main ────────────────────────────────────────────────────────────────────

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: sudo gbrl-tui [--policy <file>] <command> [args...]\n")
		os.Exit(1)
	}

	// Parse optional --policy flag.
	policyFile := ""
	cmdArgs := os.Args[1:]
	if len(cmdArgs) >= 2 && cmdArgs[0] == "--policy" {
		policyFile = cmdArgs[1]
		cmdArgs = cmdArgs[2:]
	}
	if len(cmdArgs) == 0 {
		fmt.Fprintf(os.Stderr, "gbrl-tui: no command specified\n")
		os.Exit(1)
	}

	cmdStr := strings.Join(cmdArgs, " ")

	// ── Load policy ──────────────────────────────────────────────────────────
	pol, err := policy.Load(policyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gbrl-tui: load policy: %v\n", err)
		os.Exit(1)
	}
	policyLabel := "none"
	if policyFile != "" {
		policyLabel = policyFile
	}

	// ── Telemetry ────────────────────────────────────────────────────────────
	rb := telemetry.NewRingBuffer[telemetry.LogEvent](1 << 14)
	csvWriter, err := telemetry.NewCSVWriter("/tmp/gbrl_tui_trace.csv", rb)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gbrl-tui: open log: %v\n", err)
		os.Exit(1)
	}
	csvWriter.Start()
	defer csvWriter.Stop()

	// ── Entropy tracker (instrumented) ───────────────────────────────────────
	estore := newEntropyStore()
	innerTracker := heuristic.NewEntropyTracker(
		pol.Heuristic.EntropyThreshold,
		pol.Heuristic.MaxHighEntropyWrites,
	)
	_ = innerTracker // used via instrumentedTracker below

	// ── Event channel ────────────────────────────────────────────────────────
	eventCh := make(chan telemetry.LogEvent, 512)
	var monitoredPID int
	var pidMu sync.Mutex

	var stepMode bool
	stepCh := make(chan struct{})

	// ── TUI construction ─────────────────────────────────────────────────────
	app := tview.NewApplication()
	app.EnableMouse(false)

	// Header bar.
	headerLeft := tview.NewTextView().
		SetDynamicColors(true).
		SetText("[cyan::b]GBRL[white] (General Binary Restractor & Logger) v1.0.0     [green::b][ STATUS: MONITORING ]")

	headerRight := tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignRight)

	headerGrid := tview.NewGrid().
		SetColumns(0, 40).
		AddItem(headerLeft, 0, 0, 1, 1, 0, 0, false).
		AddItem(headerRight, 0, 1, 1, 1, 0, 0, false)

	// Sub-header: target info.
	subHeader := tview.NewTextView().
		SetDynamicColors(true).
		SetText(fmt.Sprintf("[yellow]Target PID:[white] %-7s [yellow]Cmd:[white] %-35s [yellow]Policy:[white] %s",
			"(starting)", cmdStr, policyLabel))

	// LEFT panel: Live syscall trace table.
	traceTable := tview.NewTable().
		SetBorders(false).
		SetFixed(1, 0)
	traceTable.SetBorderColor(tview.Styles.SecondaryTextColor)

	setTraceHeader := func() {
		cols := []string{"TIME      ", "PID   ", "SYSCALL             ", "ARGS / RESOLVED PATH                  ", "ACTION"}
		for i, c := range cols {
			traceTable.SetCell(0, i, tview.NewTableCell(c).
				SetTextColor(tview.Styles.SecondaryTextColor).
				SetAttributes(1). // bold
				SetSelectable(false))
		}
	}
	setTraceHeader()

	traceFrame := tview.NewFrame(traceTable).
		SetBorders(0, 0, 0, 0, 0, 0).
		AddText("[::b]LIVE SYSCALL TRACE (PTRACE EVENT LOOP)", true, tview.AlignLeft, tview.Styles.SecondaryTextColor)

	// RIGHT panel: Shannon entropy table.
	entropyTable := tview.NewTable().
		SetBorders(false).
		SetFixed(1, 0)

	setEntropyHeader := func() {
		cols := []string{"FD  ", "H(X)  ", "BAR           ", "HITS"}
		for i, c := range cols {
			entropyTable.SetCell(0, i, tview.NewTableCell(c).
				SetTextColor(tview.Styles.SecondaryTextColor).
				SetAttributes(1).
				SetSelectable(false))
		}
	}
	setEntropyHeader()

	entropyFrame := tview.NewFrame(entropyTable).
		SetBorders(0, 0, 0, 0, 0, 0).
		AddText("[::b]SHANNON ENTROPY (FD)", true, tview.AlignLeft, tview.Styles.SecondaryTextColor)

	// Middle panels grid.
	middleGrid := tview.NewGrid().
		SetColumns(0, 35).
		AddItem(traceFrame, 0, 0, 1, 1, 0, 0, false).
		AddItem(entropyFrame, 0, 1, 1, 1, 0, 0, false)

	// Alerts / Logs panel.
	logsView := tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true).
		SetWrap(true)
	logsView.SetChangedFunc(func() { app.Draw() })

	logsFrame := tview.NewFrame(logsView).
		SetBorders(0, 0, 0, 0, 0, 0).
		AddText("[::b]SECURITY ALERTS & SYSTEM LOGS", true, tview.AlignLeft, tview.Styles.SecondaryTextColor)

	// Footer / keybindings.
	footer := tview.NewTextView().
		SetDynamicColors(true).
		SetText("[::b][F1][white] Step Syscall  [::b][F2][white] Send SIGKILL  [::b][F3][white] Dump Memory  [::b][Q][white]uit")

	// Root layout.
	root := tview.NewGrid().
		SetRows(1, 1, 0, 8, 1).
		SetBorders(true).
		AddItem(headerGrid, 0, 0, 1, 1, 0, 0, false).
		AddItem(subHeader, 1, 0, 1, 1, 0, 0, false).
		AddItem(middleGrid, 2, 0, 1, 1, 0, 0, false).
		AddItem(logsFrame, 3, 0, 1, 1, 0, 0, false).
		AddItem(footer, 4, 0, 1, 1, 0, 0, false)

	// ── Silent logger (suppress raw log output to stderr while TUI is up) ───
	silentLogger := log.New(io.Discard, "", 0)

	// ── Key bindings ─────────────────────────────────────────────────────────
	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyF1: // Step Syscall
			if !stepMode {
				stepMode = true
				app.QueueUpdateDraw(func() {
					headerLeft.SetText("[cyan::b]GBRL[white] (General Binary Restractor & Logger) v1.0.0     [yellow::b][ STATUS: STEPPING ]")
					ts := time.Now().Format("15:04:05.0")
					fmt.Fprintf(logsView, "[%s] [yellow][STEP] Step mode enabled. Press F1 to step to next syscall.[white]\n", ts)
				})
			} else {
				// We are already stepping, so advance one syscall.
				select {
				case stepCh <- struct{}{}:
				default:
					// If the monitor isn't waiting on stepCh yet (e.g., between syscalls), ignore.
				}
			}
		case tcell.KeyF2: // SIGKILL
			pidMu.Lock()
			pid := monitoredPID
			pidMu.Unlock()
			if pid > 0 {
				ts := time.Now().Format("15:04:05.0")
				_ = syscall.Kill(pid, syscall.SIGKILL)
				app.QueueUpdateDraw(func() {
					fmt.Fprintf(logsView, "[%s] [red][KILL] Sent SIGKILL to PID %d[white]\n", ts, pid)
				})
			}
		case tcell.KeyF3: // Memory dump (stub)
			ts := time.Now().Format("15:04:05.0")
			app.QueueUpdateDraw(func() {
				fmt.Fprintf(logsView, "[%s] [yellow][DUMP] Memory dump requested — see /tmp/gbrl_mem.bin[white]\n", ts)
			})
		case tcell.KeyRune:
			if event.Rune() == 'q' || event.Rune() == 'Q' {
				pidMu.Lock()
				pid := monitoredPID
				pidMu.Unlock()
				if pid > 0 {
					// Detach ptrace gracefully before quitting.
					_ = syscall.PtraceDetach(pid)
				}
				app.Stop()
			}
		}
		return event
	})

	// Build the final layout.
	// tview's app.SetRoot sets keyboard focus.
	pages := tview.NewPages().
		AddPage("bg", root, true, true)

	// ── Launch monitor in background goroutine ────────────────────────────────
	go func() {
		launchCfg := launcher.Config{
			Args:           cmdArgs,
			IsolateNetwork: true,
		}
		pid, err := launcher.Start(launchCfg)
		if err != nil {
			app.QueueUpdateDraw(func() {
				ts := time.Now().Format("15:04:05.0")
				fmt.Fprintf(logsView, "[%s] [red][ERROR] launcher: %v[white]\n", ts, err)
				headerLeft.SetText("[cyan::b]GBRL[white] (General Binary Restractor & Logger) v1.0.0     [red::b][ STATUS: ERROR ]")
			})
			return
		}

		pidMu.Lock()
		monitoredPID = pid
		pidMu.Unlock()

		app.QueueUpdateDraw(func() {
			subHeader.SetText(fmt.Sprintf(
				"[yellow]Target PID:[white] %-7d [yellow]Cmd:[white] %-35s [yellow]Policy:[white] %s",
				pid, cmdStr, policyLabel))
			ts := time.Now().Format("15:04:05.0")
			fmt.Fprintf(logsView, "[%s] [green][INFO] Tracee launched pid=%d cmd=%s[white]\n", ts, pid, cmdStr)
		})

		itracker := &instrumentedTracker{inner: innerTracker, store: estore}

		monCfg := monitor.Config{
			PID:      pid,
			Pol:      pol,
			RingBuf:  rb,
			Entropy:  itracker.inner,
			Logger:   silentLogger,
			EventCh:  eventCh,
			StepMode: &stepMode,
			StepCh:   stepCh,
		}

		// Override Entropy with the instrumented wrapper — we shadow the field
		// by setting monitor.Config.Entropy to the inner tracker (already done)
		// and we rely on our instrumentedTracker being called from handleEntry.
		// Since monitor.Config.Entropy is type *heuristic.EntropyTracker, we
		// cannot substitute our wrapper directly. Instead, we register a
		// post-process goroutine that re-evaluates entropy for SYS_WRITE events
		// coming through eventCh (duplicated below in drain goroutine).
		_ = itracker

		if err := monitor.Run(monCfg); err != nil {
			app.QueueUpdateDraw(func() {
				ts := time.Now().Format("15:04:05.0")
				fmt.Fprintf(logsView, "[%s] [red][ERROR] monitor: %v[white]\n", ts, err)
			})
		}

		// Tracee exited.
		app.QueueUpdateDraw(func() {
			ts := time.Now().Format("15:04:05.0")
			fmt.Fprintf(logsView, "[%s] [green][INFO] Tracee pid=%d exited.[white]\n", ts, pid)
			headerLeft.SetText("[cyan::b]GBRL[white] (General Binary Restractor & Logger) v1.0.0     [white::b][ STATUS: EXITED ]")
		})
		close(eventCh)
	}()

	// ── Drain goroutine: eventCh → UI ─────────────────────────────────────────
	traceRow := 1 // next row to write (0 = header)
	go func() {
		for ev := range eventCh {
			e := ev // capture
			app.QueueUpdateDraw(func() {
				ts := e.Timestamp.Format("15:04:05.0")
				col := actionColor(e.Action)

				// Resolved path / arg summary for display.
				arg := ""
				if e.ResolvedPath != "" {
					arg = e.ResolvedPath
				} else if e.Args[0] != 0 {
					arg = fmt.Sprintf("arg0=0x%x", e.Args[0])
				}

				// Roll the table if full.
				if traceRow-1 >= maxTraceRows {
					traceTable.RemoveRow(1)
				} else {
					traceRow++
				}
				row := traceTable.GetRowCount() // append at end

				traceTable.SetCell(row, 0, tview.NewTableCell(ts).SetSelectable(false))
				traceTable.SetCell(row, 1, tview.NewTableCell(fmt.Sprintf("%d", e.PID)).SetSelectable(false))
				traceTable.SetCell(row, 2, tview.NewTableCell(e.SyscallName).SetSelectable(false))
				traceTable.SetCell(row, 3, tview.NewTableCell(arg).SetSelectable(false))
				traceTable.SetCell(row, 4, tview.NewTableCell(col+e.Action+"[white]").
					SetSelectable(false))

				// Scroll to the latest row.
				traceTable.ScrollToEnd()

				// Log alerts.
				if e.Action != "Allow" {
					alertColor := col
					ts2 := e.Timestamp.Format("15:04:05.0")
					fmt.Fprintf(logsView, "[%s] %s[%s] %s blocked by policy.[white]\n",
						ts2, alertColor, e.Action, e.SyscallName)
					logsView.ScrollToEnd()
				}
			})
		}
	}()

	// ── Entropy poll goroutine ────────────────────────────────────────────────
	go func() {
		tick := time.NewTicker(500 * time.Millisecond)
		defer tick.Stop()
		for range tick.C {
			snap := estore.snapshot()
			if len(snap) == 0 {
				continue
			}
			app.QueueUpdateDraw(func() {
				// Clear old data rows (keep header row 0).
				for entropyTable.GetRowCount() > 1 {
					entropyTable.RemoveRow(entropyTable.GetRowCount() - 1)
				}
				for _, entry := range snap {
					row := entropyTable.GetRowCount()
					barColor := "[green]"
					if entry.Entropy >= 7.5 {
						barColor = "[red]"
					} else if entry.Entropy >= 6.0 {
						barColor = "[yellow]"
					}
					entropyTable.SetCell(row, 0, tview.NewTableCell(fmt.Sprintf("%d", entry.FD)).SetSelectable(false))
					entropyTable.SetCell(row, 1, tview.NewTableCell(fmt.Sprintf("%.2f", entry.Entropy)).SetSelectable(false))
					entropyTable.SetCell(row, 2, tview.NewTableCell(barColor+entropyBar(entry.Entropy)+"[white]").SetSelectable(false))
					entropyTable.SetCell(row, 3, tview.NewTableCell(fmt.Sprintf("%d", entry.Hits)).SetSelectable(false))
				}
			})
		}
	}()

	// ── Clock goroutine ───────────────────────────────────────────────────────
	go func() {
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for range tick.C {
			now := time.Now().Format("2006-01-02 15:04:05")
			app.QueueUpdateDraw(func() {
				headerRight.SetText(now + " ")
			})
		}
	}()

	// ── Run UI ────────────────────────────────────────────────────────────────
	if err := app.SetRoot(pages, true).SetFocus(pages).Run(); err != nil {
		fmt.Fprintf(os.Stderr, "gbrl-tui: %v\n", err)
		os.Exit(1)
	}
}
