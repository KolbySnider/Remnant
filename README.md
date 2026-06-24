# Remnant C2

A small C2 framework. Python server with an interactive CLI, Windows beacon in C, encrypted custom binary protocol between them. Runs Beacon Object Files in-process.

> Built out of curiosity as a follow-up to an earlier C2 I wrote. It has known OPSEC issues throughout and isn't meant for real engagements. May clean it up later.

<img width="605" height="183" alt="C C" src="https://github.com/user-attachments/assets/de76f2d8-26da-47eb-9a80-de2d01a3fd64" />

---

## What's in it

### Custom binary protocol

All agent traffic uses a binary wire format. The first 24 bytes are plaintext so the server can route packets without touching the crypto; everything after that is AES-256-GCM.

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

Command IDs are grouped by range: lifecycle in `0x0001–0x00FF`, tasking in `0x0100–0x01FF`, BOF/loader in `0x0400–0x04FF`. The batch flag lets you coalesce multiple sub-packages into a single checkin.

### ECDH-P256 key exchange

On first contact the beacon spins up an ephemeral ECDH-P256 keypair, sends the 65-byte uncompressed public key (X9.62) to `/register`, and gets the server's back. Both sides do the math independently:

```
session_key = SHA-256(ECDH shared secret X-coordinate)
```

One gotcha worth flagging: BCrypt's `BCRYPT_KDF_RAW_SECRET` returns the X-coordinate in little-endian, so the agent reverses it to big-endian before hashing. Otherwise the two sides derive different keys and nothing works. Every registration uses a fresh keypair; no session key gets reused.

### COFFLoader

The COFFLoader lives at `agent/src/loader/COFFLoader.c`. It resolves symbols, applies x86-64 relocations, and calls a BOF's `go()` in-process. A few things on top of the basic loader pattern:

BOFs get their own heap via `HeapCreate(HEAP_NO_SERIALIZE)`, separate from the beacon's allocator. If a BOF corrupts its heap it doesn't take the beacon with it, and cleanup is a single `HeapDestroy` call.

A per-loader `CRITICAL_SECTION` with a 4000 spin count keeps things thread-safe without callers needing to lock externally.

`__C_specific_handler` (the x64 SEH handler) is resolved straight from the linker rather than via `GetProcAddress`, since `GetProcAddress` can't find compiler-internal symbols. With it registered, BOFs that actually use SEH work.

Page-boundary alignment checks and read guards catch overruns during relocation processing before they silently chew up memory.

A configurable timeout (`COFF_DEFAULT_TIMEOUT_MS`) kills runaway BOFs instead of wedging the beacon loop.

Between executions, loaded sections and resolved IATs are XOR-encrypted in memory with a per-run key derived from stack ASLR and a high-res timer. Decrypted right before `go()` runs, re-encrypted on return.

### Structured tasking

Tasks move through a typed queue, not raw command strings:

1. Operator types `shell <cmd>` or `bof <name> [args]` at the CLI.
2. The server packages the task (for BOFs, that includes the `.obj`) onto a pending queue.
3. On the next checkin, all pending tasks for that agent get batched into one encrypted response.
4. The beacon dispatches by command ID. BOFs go directly to the COFFLoader with the pre-packed argument buffer.
5. Output lands in a thread-safe buffer and ships out on the following checkin as a `PKG_CMD_TASK_OUTPUT` package, correlated to the original task via `request_id`.

### Persistent agent state

Agent sessions — session key, task history, output, stats — get serialized to `agents.json` and reloaded on restart. You can kill and bring the server back without losing active sessions, as long as the beacon reconnects within its retry window.

### Jittered sleep

`sleep_ms = BASE_MS + rand() % (JITTER_MS * 2) - JITTER_MS`, floored at 1 second. Compile-time defaults are 5000ms base, 3000ms jitter.

---

## Requirements

**Server**
- Python 3.8+
- `pip install flask cryptography`

**Agent (build)**
- Windows, or Linux with MinGW-w64
- `x86_64-w64-mingw32-gcc` on PATH

---

## Building

Beacons are built from the server CLI with `generate`. The server shells out to `agent/build.bat` and drops the binary in `agent/build/`.

Prerequisite on whatever machine runs the server:
- `x86_64-w64-mingw32-gcc` on PATH (MinGW-w64)

### The generate command

```
 > generate [--ip IP] [--port PORT] [--ua USER_AGENT] [--token AUTH_TOKEN]
            [--sleep MS] [--jitter MS] [--https] [--out filename.exe]
```

All flags optional. Defaults come from the server's own listen config and auth token.

| Flag | Default | Description |
|------|---------|-------------|
| `--ip` | server listen IP (or `127.0.0.1`) | C2 callback address baked into the beacon |
| `--port` | server listen port | C2 callback port |
| `--ua` | `Mozilla/5.0 (Windows NT 10.0; Win64; x64)...` | HTTP User-Agent |
| `--token` | server auth token | `X-C2-Token` header sent on registration |
| `--sleep` | `5000` | Base checkin interval, ms |
| `--jitter` | `3000` | Symmetric jitter, ms |
| `--https` | off | Use HTTPS (cert validation is disabled) |
| `--out` | `beacon.exe` | Output filename under `agent/build/` |

### Examples

```
 > generate
 > generate --ip 10.0.0.1 --port 443 --out implant.exe
 > generate --ip 10.0.0.1 --port 443 --https --token MyToken123 --sleep 10000 --jitter 5000 --out beacon_https.exe
```

On success the server prints the final path:

```
 12:00:00  BUILD  Building  beacon.exe  ip=10.0.0.1  port=443  https=False
 12:00:01  OK     Built  /path/to/agent/build/beacon.exe
```

Build output:
- `agent/build/<filename>` — the beacon
- `agent/build/bofs/*.obj` — compiled BOFs (also copied to `server/bofs/`)

---

## Running

### Server

```bash
cd server
python c2server.py
```

Optional auth token so only beacons that know it can register:

```bash
# Windows
set C2_AUTH_TOKEN=MyToken123 && python c2server.py

# Linux/macOS
C2_AUTH_TOKEN=MyToken123 python c2server.py
```

The server binds `0.0.0.0:8080`, reloads any saved agents, and drops you into the CLI:

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

## How it talks

**Registration.** Beacon POSTs its 65-byte ECDH-P256 pubkey to `/register`. Server generates its own ephemeral keypair, derives the session key (SHA-256 of the shared secret X-coord), assigns a UUID, and sends back its pubkey plus the UUID. Both sides arrive at the same session key without it crossing the wire.

**Checkin.** Beacon hits `POST /checkin/<uuid>` on its jittered interval. Each request carries whatever output was buffered since the last checkin in an encrypted package. The server decrypts, processes it, and responds with any pending tasks batched into a single encrypted package.

**Dispatch.** Beacon decrypts the response, reads the command ID off each sub-package, and runs it. Shell commands go through `cmd.exe /c` with output captured. BOFs go to the COFFLoader with their pre-packed argument buffer.

---

## CLI Reference

### Global

| Command       | Description                           |
|---------------|---------------------------------------|
| `list`        | List all registered agents            |
| `bofs`        | List available BOF modules            |
| `use <id>`    | Select an agent (partial UUID OK)     |
| `clear`       | Clear the terminal                    |
| `help`        | Show command reference                |
| `exit`        | Shut down the server                  |

### Agent (after `use <id>`)

| Command              | Description                                    |
|----------------------|------------------------------------------------|
| `shell <cmd>`        | Run a shell command via `cmd.exe /c`           |
| `bof <name> [args]`  | Run a BOF with optional typed args             |
| `output [n]`         | Show last N outputs (default 10)               |
| `info`               | Show agent details and session key             |
| `stats`              | Show bytes sent/received, task counts          |
| `kill`               | Send `PKG_CMD_EXIT`; beacon calls ExitProcess  |
| `back`               | Deselect the current agent                     |

### BOF argument syntax

Arguments to `bof` are space-separated with an optional type prefix. Unprefixed tokens are treated as UTF-8 strings.

| Prefix   | Type           | Example                  |
|----------|----------------|--------------------------|
| `s:`     | UTF-8 string   | `s:C:\Windows\System32`  |
| `w:`     | UTF-16LE string| `w:Administrator`        |
| `i:`     | 32-bit integer | `i:1337`                 |
| `h:`     | 16-bit short   | `h:443`                  |
| *(none)* | UTF-8 string   | `hostname`               |

The server packs these in BeaconPack format before embedding them in the task package. The beacon hands the packed buffer straight to `go(char *args, int len)`.

---

## Included BOFs

| Module            | Description                                                            |
|-------------------|------------------------------------------------------------------------|
| `whoami`          | Current user, domain, SID, privilege level, token elevation type       |
| `pslist`          | Process list — PID, PPID, thread count, image name                     |
| `sysinfo`         | OS version, hostname, domain, uptime, architecture                     |
| `arp_cache`       | ARP table via `GetIpNetTable`                                          |
| `tcp_connections` | Active TCP connections via `GetTcpTable2`                              |
| `dirlist`         | Directory listing with sizes and attributes                            |

### Writing your own

BOFs are standard COFF objects compiled with `gcc -c`. They export `go(char *args, int len)` and use the `BeaconData*` API to parse arguments and `BeaconPrintf` / `BeaconOutput` to produce output. Drop the compiled `.obj` into `server/bofs/` and it's available via `bof` immediately.

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
## TODO (maybe)
1. Indirect syscalls: help with not being detected by userland hooks
2. Sleep obfuscation: Implement either ekko or foliage sleep or an adhoc version of both
3. Persistence: Should be easy enough to add just lazy
4. Token manipulation
5. process injection

---

## Credits

This builds on a few open-source projects worth calling out:

**[TrustedSec](https://github.com/trustedsec)** — the COFFLoader and the broader BOF design 

**[Havoc C2](https://github.com/HavocFramework/Havoc)** — the wire protocol framing, the command ID layout, and the batch-package idea were all influenced by Havoc's agent-server design.
