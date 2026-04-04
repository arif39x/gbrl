# gbrl

**gbrl** (General Binary Restractor & Logger) is a high-performance sandbox and security monitor for Linux written entirely in Go. Think of it as a low-level security guard for binaries. By combining `ptrace` for syscall interception and `process_vm_readv` for memory forensics, **gbrl** monitors and controls program behavior in real-time, enforcing security boundaries without severely degrading system performance.

## Usage

To start monitoring a binary, you just pass it as an argument:

```bash
# General building
make build

# Launch the TUI interface with the target binary
./run.sh /bin/python3 target_script.py
```

## Interactive TUI Commands

While the `gbrl` terminal interface is running, use the following keyboard shortcuts to interact with the target process:

- **`[F1]`** : **Step Syscall** — Step execution to the next syscall (useful for debugging).
- **`[F2]`** : **Send SIGKILL** — Terminate the monitored process immediately to halt bad behavior.
- **`[F3]`** : **Dump memory** — Trigger a memory dump of the target process using `process_vm_readv`.
- **`[F4]`** : **Config** — Open the active security policy configuration.
- **`[Q]`**  : **Quit** — Safely detach `ptrace` and exit the sandbox.
