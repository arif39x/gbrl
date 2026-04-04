I am building a Go-based Linux sandbox and security monitor called "gbrl" (General Binary Restractor & Logger). I have already written the backend engine which includes ptrace interception (`internal/monitor`), an entropy-based ransomware heuristic (`internal/heuristic`), and telemetry (`internal/telemetry`).

I need to build the production Terminal User Interface (TUI) for this tool using the `github.com/rivo/tview` library. The UI must connect to the REAL backend engine, not mock data.

Please write the complete `cmd/gbrl-tui/main.go` file matching this layout:

 ┌─────────────────────────────────────────────────────────────────────────────┐
 │ GBRL (General Binary Restractor & Logger) v1.0.0     [ STATUS: MONITORING ] │
 │ Target PID: 10425 | Cmd: /bin/python3 encrypt.py  | Policy: strict_fs.yaml  │
 ├──────────────────────────────────────────────────────┬──────────────────────┤
 │ LIVE SYSCALL TRACE (PTRACE EVENT LOOP)               │ SHANNON ENTROPY (FD) │
 │ TIME       PID   SYSCALL      ARGS / RESOLVED PATH   │ FD   H(X)       HITS │
 │ 15:02:41.1 10425 SYS_OPENAT   /home/user/doc.txt     │ 3    [##........] 0  │
 │ 15:02:41.2 10425 SYS_CONNECT  192.168.1.50 (DENY)    │ 5    [########..] 3  │
 ├──────────────────────────────────────────────────────┴──────────────────────┤
 │ SECURITY ALERTS & SYSTEM LOGS                                               │
 │ [15:02:41.2] [DENY] Network syscall SYS_CONNECT blocked by policy.          │
 │ [15:02:41.5] [FREEZE] High-entropy write sequence limit (5) reached!        │
 ├─────────────────────────────────────────────────────────────────────────────┤
 │ [F1] Step Syscall  [F2] Send SIGKILL  [F3] Dump memory  [F4] Config  [Q]uit │
 └─────────────────────────────────────────────────────────────────────────────┘

Requirements for the Integration:

1. **Imports:** Import the actual internal packages (`github.com/local/gbrl/internal/launcher`, `github.com/local/gbrl/internal/monitor`, `github.com/local/gbrl/internal/policy`, `github.com/local/gbrl/internal/heuristic`, `github.com/local/gbrl/internal/telemetry`).
2. **Concurrency Architecture (Crucial):** - The UI runs on the main thread via `app.Run()`.
   - The ptrace `monitor.Run(cfg)` function contains a blocking `wait4` loop. You MUST execute the launcher and monitor inside a separate background Goroutine.
3. **Event Streaming (The Bridge):**
   - Create a Go channel (`chan telemetry.LogEvent`) to pass intercepted syscalls from the real `handleEntry` / `handleExit` hooks to the UI thread.
   - Set up a listener Goroutine that ranges over this channel and safely updates the `traceTable` and `logsView` using `app.QueueUpdateDraw()`.
4. **Real Entropy Tracking:**
   - The backend `heuristic.EntropyTracker` maintains per-FD state. Pass a callback or use an interface wrapper so that whenever `Observe()` calculates a new Shannon entropy value for a file descriptor, it sends an update payload to the UI to update the `entropyTable`.
5. **Real Commands:** - Wire the [F2] key to actually send `unix.SIGKILL` to the currently monitored PID using `syscall.Kill()`.
   - Wire the [Q] key to safely detach ptrace and shut down the UI.
6. **Command Line Args:** Ensure the `main()` function parses `os.Args` to pass the target command (e.g., `/bin/python3 script.py`) to `launcher.Start()`, dynamically updating the "Cmd:" header in the UI.

Please provide the fully runnable `main.go` file that wires up the TUI to the existing backend architecture.