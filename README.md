# gbrl

![gbrl logo](assets/gbrl.jpeg)

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

## Architecture

Detailed design is documented in `ARCHITECTURE.md`.
