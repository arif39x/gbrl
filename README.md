# gbrl

<p align="center">
  <img src="assets/logo.png" alt="gbrl logo" width="180">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.26-00ADD8?style=for-the-badge&logo=go" alt="Go 1.26">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20WASM-brightgreen?style=for-the-badge&logo=linux" alt="Platform">
  <img src="https://img.shields.io/badge/runtime-wazero%201.12-8A2BE2?style=for-the-badge" alt="Wazero">
  <img src="https://img.shields.io/badge/TUI-tview%20%7C%20tcell-ff69b4?style=for-the-badge" alt="TUI">
  <br>
  <img src="https://img.shields.io/badge/license-MIT-blue?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/status-production%20ready-success?style=for-the-badge" alt="Status">
  <img src="https://img.shields.io/badge/build-passing-brightgreen?style=for-the-badge&logo=github" alt="Build">
</p>

**gbrl** (General Binary Restractor & Logger) is a cross-platform behavioral analysis engine built in pure Go. It combines a Linux `ptrace`-based sandbox for native binaries with a WASM runtime that intercepts WASI system calls — enabling sandboxed execution of untrusted code on any platform.

## Modes

### Linux ptrace mode (legacy)

Monitor and control native Linux binaries via `ptrace` syscall interception and `process_vm_readv` memory forensics.

```bash
make build
sudo ./run.sh /bin/python3 target_script.py
```

### WASM sandbox mode (cross-platform)

Run WASI-compatible WebAssembly binaries through a wazero runtime with policy-enforced interception of `fd_write`, `path_open`, `clock_time_get`, `random_get`, and `poll_oneoff`.

```bash
go run ./cmd/gbrl-wasm path/to/module.wasm
```

## TUI Commands (ptrace mode)

- **`[F1]`** — Step to next syscall
- **`[F2]`** — Send SIGKILL
- **`[F3]`** — Dump memory
- **`[F4]`** — Policy configuration
- **`[Q]`**  — Quit

## gbrl-malclass — Malware Classification Pipeline

The `gbrl-malclass` tool batch-classifies WASM binaries for malicious behavior by running each sample in an instrumented sandbox, recording every WASI system call, extracting behavioral features, and producing a classification verdict.

```bash
go run ./cmd/gbrl-malclass samples/*.wasm
```

**How it works:**

1. Each WASM sample is loaded into the wazero runtime with a custom `RecordingInterceptor` that implements `interceptor.SyscallInterceptor`
2. Every WASI call (`path_open`, `fd_write`, `network_connect`, `execve`, `clock_get`, `random_get`) is recorded with its arguments into a thread-safe call log
3. After the guest exits, features are extracted from the call log: file paths accessed, total bytes written, network attempts, subprocess spawns, etc.
4. A rule-based classifier scores the sample as **benign**, **suspicious**, or **malicious** based on feature weights
5. A CSV report (`malclass_report.csv`) is generated for downstream ML training, and raw memory dumps are captured for samples that triggered policy violations

**What it's used for:**

- **Automated malware triage** — quickly separate benign WASM modules from suspicious ones before manual analysis
- **ML training data generation** — the CSV output provides structured feature vectors (16 columns per sample) for training classifiers (XGBoost, random forest, etc.)
- **Supply chain vetting** — scan third-party WASM plugins/modules before deploying them
- **Forensic evidence collection** — samples flagged as malicious get full WASM linear memory dumps for offline reverse engineering

**Benefits over alternatives:**

| Approach | gbrl-malclass | Docker sandbox | Static analysis |
|---|---|---|---|
| Startup time | ~5ms per sample | ~500ms+ | N/A |
| Syscall-level visibility | Yes (6 WASI hook points) | Limited (OS-level) | None |
| Structured ML features | Built-in CSV export | Requires extra tooling | Requires manual labeling |
| Memory forensics | Automatic for flagged samples | Requires separate setup | Not possible |
| Cross-platform | Any WASI-compatible module | Linux-only | Any format |

**Example output:**

```
=== gbrl-malclass Report ===
Total: 4 | Malicious: 1 | Suspicious: 1 | Benign: 2 | Errors: 0

crypto_miner.wasm: malicious (80%)
  - attempted network connection
  - accessed /etc/
  - excessive file opens (>20)

key_stealer.wasm: suspicious (60%)
  - accessed .ssh
  - accessed .env
```

## Architecture

The engine is composed of layered internal packages:

- **`internal/launcher`** — Spawns a child process under ptrace with optional namespace isolation
- **`internal/monitor`** — Ptrace event loop handling syscall entry/exit, policy evaluation, and memory forensics
- **`internal/memory`** — Tracee memory access via `process_vm_readv` and memory dump facilities
- **`internal/policy`** — YAML-defined security policy with blocked-syscall maps and prefix trie for filesystem paths
- **`internal/heuristic`** — Shannon entropy-based ransomware detection with per-FD tracking
- **`internal/executor`** — WASM guest lifecycle using wazero with custom WASI function overrides
- **`internal/interceptor`** — Syscall interception interface for WASI hooks
- **`internal/telemetry`** — Lock-free ring buffer for event logging and async CSV writer
