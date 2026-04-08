#!/usr/bin/env python3
"""
cloudedge.py — Pure-Python CloudEdge / Meari / Arenti camera client.

Connects via the CS2 P2P network (reimplements PPCS_API) and streams
H.264 video over a proprietary UDP protocol.  No native libraries,
no Android emulation, no QEMU — runs on any platform with Python 3.8+.

Usage examples:

  # Save 60 seconds of H.264 to a file:
  python3 cloudedge.py --did UABPAM-000000-XXXXX \\
      --password <md5hash> --initstring "EDHNFF..." -o clip.h264

  # Pipe live video into ffplay for instant preview:
  python3 cloudedge.py --did UABPAM-000000-XXXXX \\
      --password <md5hash> --initstring "EDHNFF..." -o - | \\
      ffplay -fflags nobuffer -flags low_delay \\
        -framedrop -f h264 -framerate 10 -i pipe:0

  # Re-publish as RTSP via mediamtx:
  python3 cloudedge.py ... -o - --duration 0 | \\
      ffmpeg -fflags nobuffer+genpts -use_wallclock_as_timestamps 1 \\
        -f h264 -i pipe:0 -c:v copy -f rtsp \\
        -rtsp_transport tcp rtsp://localhost:8554/camera

Protocol stack (bottom → top):
  1. UDP transport
  2. Proprietary XOR encryption (ciphertext-feedback, key-derived table)
  3. CS2 P2P session framing  (version · msg_type · length)
  4. DRW channel multiplexing (channel · sequence · ACK-based reliability)
  5. PPCS application protocol (52-byte header with MD5 integrity)
  6. Media framing             (32-byte MediaHeader + H.264 NALs / audio)

Dependencies: Python ≥ 3.8 standard library only.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
from collections import defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

if TYPE_CHECKING:
    from typing import BinaryIO

# ─────────────────────────────────────────────────────────────────────
# Encryption tables
# ─────────────────────────────────────────────────────────────────────

# 256-byte XOR table for the default transport key ("WeEye2ppStronGer").
# cipher[i] = plain[i] ^ TABLE[prev_cipher_byte];  prev starts at 0.
XOR_TABLE = bytes([
    0xeb, 0x55, 0x2f, 0x0e, 0xba, 0x18, 0x30, 0x5e, 0x15, 0x62, 0xbc, 0x34, 0x72, 0x32, 0x3c, 0xec,
    0xd6, 0x61, 0x08, 0x78, 0xfe, 0xea, 0x97, 0x6b, 0x1b, 0xb6, 0x1f, 0x5d, 0xab, 0x35, 0xc2, 0xbb,
    0xb5, 0x46, 0xfa, 0x37, 0x50, 0x7c, 0xb8, 0x0a, 0x7f, 0x13, 0x28, 0xc5, 0x98, 0x2f, 0x5a, 0x69,
    0x2a, 0x30, 0x58, 0x12, 0xf1, 0xbc, 0x6e, 0x74, 0x06, 0x3c, 0x88, 0xf5, 0x04, 0x08, 0x0d, 0x59,
    0xee, 0x97, 0x4f, 0xd2, 0xdd, 0x1f, 0x20, 0x82, 0xc7, 0xc2, 0x14, 0xc6, 0x1a, 0xfa, 0xa7, 0xfb,
    0xa4, 0xb8, 0xcb, 0xb0, 0xd5, 0x28, 0x47, 0xf6, 0x26, 0x5a, 0x0e, 0xac, 0xd8, 0x58, 0x5e, 0x5c,
    0xae, 0x6e, 0x34, 0x33, 0x73, 0x88, 0xec, 0xb4, 0x24, 0x0d, 0x78, 0x81, 0xb3, 0x4f, 0x6b, 0x8d,
    0x8a, 0x20, 0x5d, 0x6a, 0x2d, 0x14, 0xbb, 0xbf, 0xe0, 0xa7, 0x37, 0x64, 0x4b, 0xcb, 0x0a, 0x55,
    0x48, 0x47, 0xc5, 0x18, 0x91, 0x0e, 0x69, 0x62, 0x8f, 0x5e, 0x12, 0x32, 0x9e, 0x34, 0x74, 0x61,
    0x03, 0xec, 0xf5, 0xea, 0x0f, 0x78, 0x59, 0xb6, 0xed, 0x6b, 0xd2, 0x35, 0x6c, 0x5d, 0x82, 0x46,
    0xa0, 0xbb, 0xc6, 0x7c, 0x53, 0x37, 0xfb, 0x13, 0x9f, 0x0a, 0xb0, 0x2f, 0x80, 0xc5, 0xf6, 0x30,
    0x10, 0x69, 0xac, 0xbc, 0x57, 0x12, 0x5c, 0x3c, 0xcd, 0x74, 0x33, 0x08, 0xe6, 0xf5, 0xb4, 0x97,
    0xcf, 0x59, 0x81, 0x1f, 0x4c, 0xd2, 0x8d, 0xc2, 0x92, 0x82, 0x6a, 0xfa, 0x63, 0xc6, 0xbf, 0xb8,
    0x8e, 0xfb, 0x64, 0x28, 0xc3, 0xb0, 0x55, 0x5a, 0x44, 0xf6, 0x18, 0x58, 0x9c, 0xac, 0x62, 0x6e,
    0xde, 0x5c, 0x32, 0x88, 0x21, 0x33, 0x61, 0x0d, 0x7b, 0xb4, 0xea, 0x4f, 0x0b, 0x81, 0xb6, 0x20,
    0xf7, 0x8d, 0x35, 0x14, 0x71, 0x6a, 0x46, 0xa7, 0x85, 0xbf, 0x7c, 0xcb, 0xc4, 0x64, 0x13, 0x47,
])

# Base selector table from libPPCS_API.so .rodata — used for ReportSessionReady.
_PROP_SELECT_BASE = bytes.fromhex(
    '7c9ce84a13dedcb22f2123e4307b3d8cbc0b270c3cf79ae7087196009785efc1'
    '1fc4dba1c2ebd901faba3b05b81587832872d18b5ad6da9358feaacc6e1bf0a3'
    '88ab43c00db545384f502266207f075b14981d9ba72ab9a8cbf1fc4947063eb1'
    '0e043a945eee541134dd4df9ecc7c9e3781a6f706ba4bda95dd5f8e5bb26af42'
    '37d8e1020aae5f1cc573094e6924906d12b319ad748a2940f52dbea559e0f479'
    'd24bce8982488425c6912ba2fb8fe9a6b09e3f65f603312eac0f952c5ced39b7'
    '336c567eb4a0fd7a815351868d9f77ff6a80dfe2bf10d775645776f355cdd0c8'
    '18e6364162cf99f2324c67606192cad3ea637d16b68ed46835c3529d46441e17'
)

_REPORT_SESSION_KEY = b'SSD@cs2-network.'
_PROTO_VERSION = 0xf1


# ─────────────────────────────────────────────────────────────────────
# Encryption / decryption
# ─────────────────────────────────────────────────────────────────────

def _prop_encrypt(plaintext: bytes) -> bytes:
    out = bytearray(len(plaintext))
    prev = 0
    for i, b in enumerate(plaintext):
        c = b ^ XOR_TABLE[prev]
        out[i] = c
        prev = c
    return bytes(out)


def _prop_decrypt(ciphertext: bytes) -> bytes:
    out = bytearray(len(ciphertext))
    prev = 0
    for i, b in enumerate(ciphertext):
        out[i] = b ^ XOR_TABLE[prev]
        prev = b
    return bytes(out)


def _derive_prop_state(key: bytes) -> bytes:
    s = [0, 0, 0, 0]
    for v in key[:20]:
        if v == 0:
            break
        s[0] = (s[0] + v) & 0xFF
        s[1] = (s[1] - v) & 0xFF
        s[2] = (s[2] + (v // 3)) & 0xFF
        s[3] ^= v
    return bytes(s)


def _prop_encrypt_keyed(plaintext: bytes, key: bytes) -> bytes:
    if not key:
        return plaintext
    state = _derive_prop_state(key)
    out = bytearray(len(plaintext))
    prev = 0
    for i, v in enumerate(plaintext):
        off = (prev + state[prev & 3]) & 0xFF
        c = v ^ _PROP_SELECT_BASE[off]
        out[i] = c
        prev = c
    return bytes(out)


# ─────────────────────────────────────────────────────────────────────
# CS2 P2P message framing
# ─────────────────────────────────────────────────────────────────────

class _Msg:
    HELLO            = 0x00;  HELLO_ACK        = 0x01
    P2P_REQ          = 0x20;  P2P_REQ_ACK      = 0x21
    LAN_SEARCH       = 0x30;  LAN_SEARCH_ACK   = 0x31
    PUNCH_TO         = 0x40;  PUNCH            = 0x41;  PUNCH_ACK = 0x42
    ALIVE            = 0xA0;  ALIVE_ACK        = 0xA1
    DRW              = 0xD0;  DRW_ACK          = 0xD1
    PSR              = 0xE0;  PSR_ACK          = 0xE1
    CLOSE            = 0xF4
    REPORT_SESSION   = 0xF9
    BYTE_COUNT       = 0x82;  SESSION_INFO     = 0x69

_MSG_NAMES = {v: k for k, v in vars(_Msg).items()
              if isinstance(v, int) and not k.startswith('_')}


def _msg_name(t: int) -> str:
    return _MSG_NAMES.get(t, f'0x{t:02X}')


def _make_msg(msg_type: int, payload: bytes = b'') -> bytes:
    return struct.pack('>BBH', _PROTO_VERSION, msg_type, len(payload)) + payload


def _parse_msg(data: bytes) -> Tuple[int, int, bytes]:
    if len(data) < 4:
        return (-1, 0, b'')
    mt = data[1]
    plen = struct.unpack('>H', data[2:4])[0]
    pay = data[4:4 + plen] if plen <= len(data) - 4 else data[4:]
    return (mt, plen, pay)


# ─────────────────────────────────────────────────────────────────────
# DID encoding & initstring decoding
# ─────────────────────────────────────────────────────────────────────

def _encode_did(did: str) -> bytes:
    parts = did.split('-')
    if len(parts) != 3:
        raise ValueError(f'DID must be PREFIX-SERIAL-SUFFIX, got: {did}')
    prefix = parts[0].encode('ascii').ljust(8, b'\x00')[:8]
    serial = int(parts[1])
    suffix = parts[2].encode('ascii').ljust(8, b'\x00')[:8]
    return prefix + struct.pack('>I', serial) + suffix


def decode_initstring_servers(initstring: str) -> List[str]:
    """Decode dispatch server IPs from CS2 initstring (A–P hex nibble encoding)."""
    # Add known initstring→IP mappings here if the generic decoder
    # produces incorrect results for your device:
    #   _KNOWN = {'YOURINITSTRINGHERE': '1.2.3.4,5.6.7.8'}
    _KNOWN: Dict[str, str] = {}
    encoded = initstring.split(':')[0] if ':' in initstring else initstring
    hit = _KNOWN.get(encoded)
    if hit:
        return [ip.strip() for ip in hit.split(',') if ip.strip()]

    # Fallback: decode using CS2 character mapping (A-P → nibbles 0-F)
    char_map = {chr(c): i for i, c in enumerate(range(ord('A'), ord('Q')))}
    try:
        raw: list[int] = []
        for i in range(0, len(encoded) - 1, 2):
            hi, lo = char_map.get(encoded[i]), char_map.get(encoded[i + 1])
            if hi is not None and lo is not None:
                raw.append((hi << 4) | lo)
        servers: list[str] = []
        i = 0
        while i + 5 < len(raw):
            ip = f'{raw[i]}.{raw[i+1]}.{raw[i+2]}.{raw[i+3]}'
            if all(0 < b < 255 for b in raw[i:i + 4]):
                servers.append(ip)
            i += 6
        return servers
    except Exception:
        return []


# ─────────────────────────────────────────────────────────────────────
# DRW channel helpers
# ─────────────────────────────────────────────────────────────────────

_DRW_HDR = 4  # marker(1) + channel(1) + seq(2)


def _make_drw_data(ch: int, seq: int, payload: bytes) -> bytes:
    return _make_msg(_Msg.DRW, struct.pack('>BBH', 0xd1, ch, seq) + payload)


def _make_drw_ack(ch: int, seqs: List[int]) -> bytes:
    hdr = struct.pack('>BBH', 0xd1, ch, len(seqs))
    for s in seqs:
        hdr += struct.pack('>H', s)
    return _make_msg(_Msg.DRW_ACK, hdr)


# ─────────────────────────────────────────────────────────────────────
# ReportSessionReady
# ─────────────────────────────────────────────────────────────────────

def _sockaddr(addr: Tuple[str, int]) -> bytes:
    ip, port = addr
    return (struct.pack('>H', socket.AF_INET)
            + struct.pack('<H', port)
            + socket.inet_aton(ip)[::-1]
            + b'\x00' * 8)


def _build_report_session(did: str, session_no: int,
                          local: Tuple[str, int],
                          external: Tuple[str, int],
                          peer: Tuple[str, int],
                          elapsed_ms: int) -> bytes:
    prefix, serial, suffix = did.split('-')
    p = bytearray(84)
    p[0:7] = prefix.encode('ascii')[:7].ljust(7, b'\x00')
    p[7] = 0x74  # 't' — P2P direct
    struct.pack_into('>I', p, 8, int(serial))
    p[12:19] = suffix.encode('ascii')[:7].ljust(7, b'\x00')
    p[19] = 0x72  # 'r'
    struct.pack_into('>I', p, 20, session_no)
    struct.pack_into('>HHH', p, 24, 0x0100, 0x0001, elapsed_ms & 0xFFFF)
    p[30:32] = b'\x00\x00'
    p[32] = 126; p[33] = 0; p[34] = 0x5f; p[35] = 0x63
    p[36:52] = _sockaddr(local)
    p[52:68] = _sockaddr(external)
    p[68:84] = _sockaddr(peer)
    inner = _prop_encrypt_keyed(bytes(p), _REPORT_SESSION_KEY)
    return _make_msg(_Msg.REPORT_SESSION, inner)


# ─────────────────────────────────────────────────────────────────────
# PPCS application protocol — 52-byte header with MD5 integrity
# ─────────────────────────────────────────────────────────────────────
#
#   Offset  Size  Field
#   0       4     Magic   0x56565099  (big-endian)
#   4       4     Version 1
#   8       4     Sequence number     (incrementing)
#   12      4     Type                (0x11FF init, 0x12FF close,
#                                      0x8000 HTTP cmd, 0x888E heartbeat)
#   16      32    MD5 hex digest      (ASCII)
#   48      4     Payload length
#
#   MD5 input: "{user}|{pass16}|{magic_dec}|{seq}|{type}|{plen}|meari.p2p.ppcs"

_PPCS_MAGIC     = 0x56565099
_PPCS_HDR       = 52
_PPCS_VER       = 1
_MEDIA_HDR      = 32

_TYPE_INIT      = 0x11FF
_TYPE_CLOSE     = 0x12FF
_TYPE_HTTP      = 0x8000
_TYPE_HEARTBEAT = 0x888E


def _ppcs_md5(user: str, pw16: str, magic: int,
              seq: int, mtype: int, plen: int) -> str:
    s = f'{user}|{pw16}|{magic}|{seq}|{mtype}|{plen}|meari.p2p.ppcs'
    return hashlib.md5(s.encode('ascii')).hexdigest()


def _ppcs_header(seq: int, mtype: int, plen: int,
                 user: str, pw16: str) -> bytes:
    md5 = _ppcs_md5(user, pw16, _PPCS_MAGIC, seq, mtype, plen)
    hdr = struct.pack('>IIII', _PPCS_MAGIC, _PPCS_VER, seq, mtype)
    hdr += md5.encode('ascii')
    hdr += struct.pack('>I', plen)
    return hdr


def _ppcs_parse(data: bytes) -> Optional[dict]:
    if len(data) < _PPCS_HDR:
        return None
    magic, ver, seq, mtype = struct.unpack('>IIII', data[:16])
    if magic != _PPCS_MAGIC:
        return None
    md5 = data[16:48].decode('ascii', errors='replace')
    plen = struct.unpack('>I', data[48:52])[0]
    return dict(magic=magic, version=ver, seqno=seq,
                type=mtype, md5=md5, payload_len=plen)


# ─────────────────────────────────────────────────────────────────────
# Media header (32 bytes, little-endian)
# ─────────────────────────────────────────────────────────────────────

@dataclass
class _MediaHdr:
    frame_no: int = 0
    codec: int = 0
    fps: int = 0
    timestamp: int = 0
    frame_size: int = 0

    def is_video(self) -> bool:
        return self.codec == 0x01

    def is_audio(self) -> bool:
        return self.codec in (0x02, 0x82)

    @classmethod
    def unpack(cls, data: bytes) -> '_MediaHdr':
        f = struct.unpack('<IIIIIIII', data[:32])
        return cls(frame_no=f[0], codec=f[3], fps=f[4],
                   timestamp=f[5], frame_size=f[7])


# ═════════════════════════════════════════════════════════════════════
# Transport: CS2 P2P client
# ═════════════════════════════════════════════════════════════════════

_DISPATCH_PORT = 32100


def _log(msg: str) -> None:
    print(f'[cloudedge] {msg}', file=sys.stderr, flush=True)


class CS2Transport:
    """Low-level UDP P2P transport with channel multiplexing."""

    def __init__(self, did: str, initstring: str,
                 dispatch_servers: Optional[List[str]] = None):
        self.did = did
        self.did_bytes = _encode_did(did)
        self.dispatchers = dispatch_servers or decode_initstring_servers(initstring)
        self.sock: Optional[socket.socket] = None
        self.peer: Optional[Tuple[str, int]] = None
        self.external: Optional[Tuple[str, int]] = None
        self._t0 = 0.0
        self._session = 0
        self.running = False
        self._lock = threading.Lock()

        self.tx_seq: Dict[int, int] = defaultdict(int)
        self.rx_seq: Dict[int, int] = defaultdict(int)
        self._rx_init: set = set()
        self.rx_buf: Dict[int, Dict[int, bytes]] = defaultdict(dict)
        self.ch_data: Dict[int, bytearray] = defaultdict(bytearray)
        self._events: Dict[int, threading.Event] = defaultdict(threading.Event)
        self._ack_q: Dict[int, List[int]] = defaultdict(list)
        self._threads: list = []

    # -- raw I/O ---------------------------------------------------

    def _tx(self, data: bytes, addr: Tuple[str, int]) -> None:
        assert self.sock
        self.sock.sendto(_prop_encrypt(data), addr)

    def _rx(self, timeout: float = 5.0) -> Tuple[Optional[bytes], Optional[Tuple[str, int]]]:
        assert self.sock
        try:
            self.sock.settimeout(timeout)
            raw, addr = self.sock.recvfrom(65536)
            return _prop_decrypt(raw), addr
        except socket.timeout:
            return None, None

    # -- connect ---------------------------------------------------

    def connect(self) -> bool:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('0.0.0.0', 0))
        self._t0 = time.monotonic()
        port = self.sock.getsockname()[1]
        _log(f'Bound UDP :{port}')

        if not self.dispatchers:
            _log('No dispatch servers')
            return False

        hello = _make_msg(_Msg.HELLO)
        req_pay = bytearray(36)
        req_pay[0:20] = self.did_bytes
        struct.pack_into('>HH', req_pay, 20, 0x0002, port)
        p2p_req = _make_msg(_Msg.P2P_REQ, bytes(req_pay))
        lan = _make_msg(_Msg.LAN_SEARCH)

        for ip in self.dispatchers:
            self._tx(hello, (ip, _DISPATCH_PORT))
            self._tx(p2p_req, (ip, _DISPATCH_PORT))
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self._tx(lan, ('255.255.255.255', 32108))
            self._tx(lan, ('192.168.0.255', 32108))
        except OSError:
            pass

        camera = self._phase1_discover(p2p_req, lan)
        if not camera:
            _log('Connection failed — device offline or behind symmetric NAT')
            return False

        self.peer = camera
        _log(f'Connected to {camera[0]}:{camera[1]}')
        self._report_session()

        self.running = True
        t1 = threading.Thread(target=self._recv_loop, daemon=True)
        t2 = threading.Thread(target=self._psr_loop, daemon=True)
        t1.start(); t2.start()
        self._threads = [t1, t2]

        self._tx(_make_msg(_Msg.PSR), self.peer)
        time.sleep(1.2)
        return True

    def _phase1_discover(self, p2p_req: bytes, lan: bytes) -> Optional[Tuple[str, int]]:
        targets: List[Tuple[str, int]] = []
        got_punch_to = False
        deadline = time.time() + 15.0
        retries = 0
        dispatch_set = set(self.dispatchers)

        while time.time() < deadline:
            data, addr = self._rx(0.3)
            if not data:
                if retries < 30:
                    for ip in self.dispatchers:
                        self._tx(p2p_req, (ip, _DISPATCH_PORT))
                    retries += 1
                if got_punch_to:
                    break
                continue

            mt, _, pay = _parse_msg(data)
            if addr is None:
                continue

            if mt == _Msg.HELLO_ACK and len(pay) >= 8:
                ext_ip = f'{pay[4]}.{pay[5]}.{pay[6]}.{pay[7]}'
                ext_port = struct.unpack('<H', pay[2:4])[0]
                self.external = (ext_ip, ext_port)
                if retries <= 1:
                    _log(f'NAT external: {ext_ip}:{ext_port}')

            elif mt == _Msg.P2P_REQ_ACK:
                if retries <= 1:
                    _log(f'Device online (via {addr[0]})')

            elif mt == _Msg.LAN_SEARCH_ACK:
                _log(f'LAN device at {addr[0]}:{addr[1]}')
                return addr

            elif mt == _Msg.PUNCH_TO and len(pay) >= 8:
                port_base = struct.unpack('<H', pay[2:4])[0]
                ib = pay[4:8]
                wan = f'{ib[0]}.{ib[1]}.{ib[2]}.{ib[3]}'
                lan_ip = f'{ib[3]}.{ib[2]}.{ib[1]}.{ib[0]}'
                if port_base == 0:
                    continue
                if not got_punch_to:
                    _log(f'PUNCH_TO {wan}:{port_base}')
                for base_ip in (wan, lan_ip):
                    if base_ip == '0.0.0.0':
                        continue
                    if not base_ip.startswith(('192.168.', '10.', '172.')) and base_ip == lan_ip:
                        continue
                    for p in range(port_base - 3, port_base + 4):
                        t = (base_ip, p)
                        if t not in targets:
                            targets.append(t)
                got_punch_to = True
                punch = _make_msg(_Msg.PUNCH, self.did_bytes[:20])
                for t in targets:
                    try:
                        self._tx(punch, t)
                    except OSError:
                        pass

            elif mt in (_Msg.PUNCH, _Msg.PUNCH_ACK):
                self._tx(_make_msg(_Msg.PUNCH, self.did_bytes[:20]), addr)
                self._tx(_make_msg(_Msg.PUNCH_ACK, self.did_bytes[:20]), addr)
                return addr

            elif mt in (_Msg.DRW, _Msg.SESSION_INFO, _Msg.BYTE_COUNT):
                if mt == _Msg.DRW:
                    self._handle_drw(pay)
                return addr

        # Phase 2: active punching
        if not targets:
            return None

        punch = _make_msg(_Msg.PUNCH, self.did_bytes[:20])
        req2 = bytearray(36)
        req2[0:20] = self.did_bytes
        struct.pack_into('>HH', req2, 20, 0x0002, self.sock.getsockname()[1])
        struct.pack_into('>I', req2, 24, 0x1002000a)
        p2p_req2 = _make_msg(_Msg.P2P_REQ, bytes(req2))

        punch_deadline = time.time() + 12.0
        iteration = 0
        while time.time() < punch_deadline:
            iteration += 1
            for t in targets:
                try:
                    self._tx(punch, t)
                except OSError:
                    pass
            if iteration % 10 == 0:
                for ip in self.dispatchers:
                    self._tx(p2p_req2, (ip, _DISPATCH_PORT))

            self.sock.settimeout(0.05)
            for _ in range(50):
                try:
                    raw, addr = self.sock.recvfrom(4096)
                except (socket.timeout, BlockingIOError):
                    break
                data = _prop_decrypt(raw)
                mt, _, pay = _parse_msg(data)
                if addr[0] in dispatch_set:
                    if mt == _Msg.PUNCH_TO and len(pay) >= 8:
                        pb = struct.unpack('<H', pay[2:4])[0]
                        ib = pay[4:8]
                        w = f'{ib[0]}.{ib[1]}.{ib[2]}.{ib[3]}'
                        l = f'{ib[3]}.{ib[2]}.{ib[1]}.{ib[0]}'
                        if pb:
                            for base_ip in (w, l):
                                if base_ip == '0.0.0.0':
                                    continue
                                for p in range(pb - 3, pb + 4):
                                    tt = (base_ip, p)
                                    if tt not in targets:
                                        targets.append(tt)
                    continue
                if mt in (_Msg.PUNCH, _Msg.PUNCH_ACK):
                    self._tx(_make_msg(_Msg.PUNCH, self.did_bytes[:20]), addr)
                    self._tx(_make_msg(_Msg.PUNCH_ACK, self.did_bytes[:20]), addr)
                    return addr
                if mt in (_Msg.DRW, _Msg.SESSION_INFO, _Msg.BYTE_COUNT,
                          _Msg.PSR, _Msg.LAN_SEARCH_ACK):
                    if mt == _Msg.DRW:
                        self._handle_drw(pay)
                    return addr
        return None

    def _report_session(self) -> None:
        if not self.peer:
            return
        self._session += 1
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect(self.peer)
            local = probe.getsockname()
        finally:
            probe.close()
        ext = self.external or local
        ms = min(int((time.monotonic() - self._t0) * 1000), 0xFFFF)
        pkt = _build_report_session(self.did, self._session,
                                    local, ext, self.peer, ms)
        for ip in self.dispatchers:
            self._tx(pkt, (ip, _DISPATCH_PORT))

    # -- DRW handling ----------------------------------------------

    def _handle_drw(self, pay: bytes) -> None:
        if len(pay) < _DRW_HDR:
            return
        ch = pay[1]
        seq = struct.unpack('>H', pay[2:4])[0]
        data = pay[4:]
        with self._lock:
            self.rx_buf[ch][seq] = data
            self._ack_q[ch].append(seq)
            if ch not in self._rx_init:
                self._rx_init.add(ch)
                self.rx_seq[ch] = seq
            while self.rx_seq[ch] in self.rx_buf[ch]:
                self.ch_data[ch].extend(self.rx_buf[ch].pop(self.rx_seq[ch]))
                self.rx_seq[ch] = (self.rx_seq[ch] + 1) & 0xFFFF
            self._events[ch].set()

    def _flush_acks(self) -> None:
        with self._lock:
            for ch, seqs in self._ack_q.items():
                if seqs and self.peer:
                    self._tx(_make_drw_ack(ch, seqs), self.peer)
                    seqs.clear()

    def _psr_loop(self) -> None:
        while self.running:
            if self.peer:
                try:
                    self._tx(_make_msg(_Msg.PSR), self.peer)
                except OSError:
                    pass
            time.sleep(0.2)

    def _recv_loop(self) -> None:
        assert self.sock
        sock = self.sock  # local ref — survives reset()
        dispatch_set = set(self.dispatchers)
        while self.running:
            try:
                sock.settimeout(1.0)
                raw, addr = sock.recvfrom(65536)
            except socket.timeout:
                if self.peer:
                    try:
                        self._tx(_make_msg(_Msg.ALIVE), self.peer)
                    except OSError:
                        break
                continue
            except OSError:
                break
            data = _prop_decrypt(raw)
            mt, _, pay = _parse_msg(data)

            if mt == _Msg.DRW:
                self._handle_drw(pay)
                self._flush_acks()
            elif mt == _Msg.ALIVE:
                try:
                    self._tx(_make_msg(_Msg.ALIVE_ACK), addr)
                except OSError:
                    break
            elif mt == _Msg.PUNCH:
                try:
                    self._tx(_make_msg(_Msg.PUNCH_ACK, self.did_bytes[:20]), addr)
                except OSError:
                    break
            elif mt == _Msg.PSR:
                try:
                    self._tx(_make_msg(_Msg.PSR_ACK, pay), addr)
                except OSError:
                    break
            elif mt == _Msg.CLOSE:
                _log('Peer closed')
                self.running = False

    # -- channel I/O -----------------------------------------------

    def write(self, ch: int, data: bytes) -> int:
        if not self.peer:
            return -1
        with self._lock:
            seq = self.tx_seq[ch]
            self.tx_seq[ch] = (seq + 1) & 0xFFFF
        self._tx(_make_drw_data(ch, seq, data), self.peer)
        return len(data)

    def read(self, ch: int, size: int, timeout_ms: int = 5000) -> Optional[bytes]:
        deadline = time.time() + timeout_ms / 1000.0
        while time.time() < deadline:
            with self._lock:
                if len(self.ch_data[ch]) >= size:
                    r = bytes(self.ch_data[ch][:size])
                    del self.ch_data[ch][:size]
                    return r
            self._events[ch].wait(0.1)
            self._events[ch].clear()
        with self._lock:
            if self.ch_data[ch]:
                r = bytes(self.ch_data[ch][:size])
                del self.ch_data[ch][:size]
                return r
        return None

    def read_available(self, ch: int) -> bytes:
        with self._lock:
            r = bytes(self.ch_data[ch])
            self.ch_data[ch].clear()
            return r

    def reset(self) -> None:
        """Tear down the current session so connect() can be called again."""
        self.running = False
        # Let threads notice running=False before closing the socket
        time.sleep(0.3)
        if self.peer:
            try:
                self._tx(_make_msg(_Msg.CLOSE), self.peer)
            except Exception:
                pass
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        for t in self._threads:
            t.join(timeout=3)
        self._threads.clear()
        self.sock = None
        self.peer = None
        self.external = None
        self.tx_seq.clear()
        self.rx_seq.clear()
        self._rx_init.clear()
        self.rx_buf.clear()
        self.ch_data.clear()
        self._ack_q.clear()
        for ev in self._events.values():
            ev.set()
        self._events.clear()

    def close(self) -> None:
        self.running = False
        if self.peer:
            try:
                self._tx(_make_msg(_Msg.CLOSE), self.peer)
            except Exception:
                pass
        if self.sock:
            self.sock.close()


# ═════════════════════════════════════════════════════════════════════
# CloudEdge client (application layer)
# ═════════════════════════════════════════════════════════════════════

class CloudEdgeClient:
    """High-level client: connect, authenticate, stream video."""

    def __init__(self, did: str, password_hash: str, initstring: str,
                 dispatch_servers: Optional[List[str]] = None):
        self.did = did
        self.password_hash = password_hash
        self.password_16 = password_hash[:16]
        self.username = 'admin'
        self.initstring = initstring
        self._dispatch_servers = dispatch_servers
        self.p2p = CS2Transport(did, initstring, dispatch_servers)
        self.frame_count = 0
        self.total_bytes = 0
        self._seq = 0
        self._seq_lock = threading.Lock()

    def connect(self) -> bool:
        if not self.p2p.connect():
            return False
        if not self._authenticate():
            return False
        # Start PPCS heartbeat thread
        self._hb_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._hb_thread.start()
        return True

    def reconnect(self) -> bool:
        """Tear down current session and establish a new one."""
        _log('Reconnecting...')
        self.p2p.reset()
        self.p2p = CS2Transport(self.did, self.initstring, self._dispatch_servers)
        self._seq = 0
        return self.connect()

    def _heartbeat_loop(self) -> None:
        """Send PPCS heartbeat (0x888E) every 15s to keep the session alive."""
        while self.p2p.running:
            time.sleep(15)
            if not self.p2p.running:
                break
            try:
                self._ppcs_write(_TYPE_HEARTBEAT)
            except OSError:
                _log('Heartbeat send failed — connection lost')
                self.p2p.running = False
                break

    def _next_seq(self) -> int:
        with self._seq_lock:
            s = self._seq; self._seq += 1; return s

    def _ppcs_write(self, mtype: int, payload: bytes = b'') -> int:
        seq = self._next_seq()
        hdr = _ppcs_header(seq, mtype, len(payload),
                           self.username, self.password_16)
        return self.p2p.write(0, hdr + payload)

    def _authenticate(self) -> bool:
        assert self.p2p.peer
        self.p2p._tx(_make_msg(_Msg.PSR), self.p2p.peer)

        # 1. Session init
        self._seq = 0
        self._ppcs_write(_TYPE_INIT, b'\x00' * 8)

        # 2. HTTP auth
        auth_b64 = base64.b64encode(
            f'admin:{self.password_hash}'.encode()).decode()
        body = json.dumps({
            'action': 'GET',
            'deviceurl': 'http://127.0.0.1/devices/storage'
        }, separators=(',', ':')).replace('/', '\\/')
        req = (
            f'GET /devices/storage HTTP/1.0\r\n'
            f'Host: 127.0.0.1\r\n'
            f'User-Agent: Awesome HTTP Client\r\n'
            f'Content-Type: text/plain, charset=us-ascii\r\n'
            f'Connection: close\r\n'
            f'Authorization: Basic {auth_b64}\r\n'
            f'Content-Length: {len(body)}\r\n\r\n{body}'
        ).encode()
        self._ppcs_write(_TYPE_HTTP, req)

        # 3. Read response
        resp = self.p2p.read(0, _PPCS_HDR, timeout_ms=5000)
        if resp:
            hdr = _ppcs_parse(resp)
            if hdr:
                _log(f'Auth: type=0x{hdr["type"]:04X} plen={hdr["payload_len"]}')
                if hdr['payload_len'] > 0:
                    pay = self.p2p.read(0, hdr['payload_len'], timeout_ms=3000)
                    if pay:
                        # Check for HTTP 200
                        if b'200 OK' in pay[:64]:
                            _log('Auth OK')
                        else:
                            _log(f'Auth response: {pay[:128]}')
            time.sleep(0.5)
            self.p2p.read_available(0)  # drain
        else:
            _log('No auth response — proceeding')
        return True

    def stream_video(self, output: BinaryIO, duration_sec: int = 60) -> None:
        """Read video frames from channel 1 and write H.264 NALs to *output*."""
        _log(f'Streaming for {duration_sec}s (0 = indefinite)...')
        start = time.time()
        magic = struct.pack('>I', _PPCS_MAGIC)
        buf = bytearray()
        got_key = False
        last_ts: Optional[int] = None
        wall_t0: Optional[float] = None
        idle_since: Optional[float] = None
        _MAX_IDLE = 15.0
        _MAX_RETRIES = 10

        retries = 0
        while True:
            if duration_sec > 0 and time.time() - start >= duration_sec:
                break

            if not self.p2p.running:
                if retries >= _MAX_RETRIES:
                    _log(f'Giving up after {retries} reconnect attempts')
                    break
                retries += 1
                delay = min(2 ** retries, 30)
                _log(f'Disconnected — retry {retries}/{_MAX_RETRIES} in {delay}s')
                time.sleep(delay)
                if self.reconnect():
                    _log('Reconnected')
                    buf.clear()
                    got_key = False
                    last_ts = None
                    wall_t0 = None
                    idle_since = None
                else:
                    _log('Reconnect failed')
                continue

            data = self.p2p.read(1, 4096, timeout_ms=500)
            if not data:
                if idle_since is None:
                    idle_since = time.time()
                elif time.time() - idle_since > _MAX_IDLE:
                    _log(f'No data for {_MAX_IDLE}s — forcing reconnect')
                    self.p2p.running = False
                continue
            idle_since = None
            retries = 0
            buf.extend(data)

            while len(buf) >= _MEDIA_HDR:
                if buf[:4] == magic:
                    if len(buf) < _PPCS_HDR:
                        break
                    h = _ppcs_parse(bytes(buf[:_PPCS_HDR]))
                    if not h:
                        del buf[:1]; continue
                    total = _PPCS_HDR + h['payload_len']
                    if len(buf) < total:
                        break
                    del buf[:_PPCS_HDR]
                    continue

                mh = _MediaHdr.unpack(bytes(buf[:_MEDIA_HDR]))
                total = _MEDIA_HDR + mh.frame_size
                if mh.frame_size == 0 or mh.frame_size > 2 * 1024 * 1024:
                    del buf[:1]; continue
                if len(buf) < total:
                    break

                frame = bytes(buf[_MEDIA_HDR:total])

                if mh.is_video():
                    if not got_key:
                        if (b'\x00\x00\x00\x01\x67' in frame
                                or b'\x00\x00\x00\x01\x27' in frame):
                            got_key = True
                            wall_t0 = time.time()
                            last_ts = mh.timestamp
                            _log('Got keyframe — streaming')
                        else:
                            del buf[:total]; continue

                    if last_ts is not None and wall_t0 is not None:
                        dt = (mh.timestamp - last_ts) & 0xFFFFFFFF
                        if 0 < dt < 5000:
                            target = wall_t0 + dt / 1000.0
                            gap = target - time.time()
                            if gap > 0:
                                time.sleep(gap)
                        wall_t0 += dt / 1000.0
                    last_ts = mh.timestamp

                    try:
                        output.write(frame)
                        output.flush()
                    except (BrokenPipeError, OSError):
                        _log('Output pipe broken')
                        return
                    self.frame_count += 1
                    self.total_bytes += len(frame)

                    if self.frame_count <= 3 or self.frame_count % 30 == 0:
                        el = time.time() - start
                        fps = self.frame_count / el if el > 0 else 0
                        _log(f'Frame {self.frame_count}: {mh.frame_size}B '
                             f'ts={mh.timestamp} total={self.total_bytes}B '
                             f'{fps:.1f}fps')

                del buf[:total]

        _log(f'Done: {self.frame_count} frames, {self.total_bytes} bytes')

    def _is_local_rtsp(self, rtsp_url: str) -> Tuple[bool, Optional[str], int]:
        parsed = urllib.parse.urlparse(rtsp_url)
        host = parsed.hostname
        port = parsed.port or 8554
        is_local = host in ('localhost', '127.0.0.1', '::1')
        return is_local, host, port

    def _port_open(self, host: str, port: int, timeout: float = 0.5) -> bool:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False

    def _stop_existing_mediamtx(self) -> None:
        """Stop existing mediamtx instances to avoid stale/bad state."""
        try:
            out = subprocess.check_output(['pgrep', '-x', 'mediamtx'], text=True)
        except Exception:
            return

        pids = [int(x) for x in out.split() if x.strip().isdigit()]
        for pid in pids:
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass

        deadline = time.time() + 3.0
        while time.time() < deadline:
            alive = False
            for pid in pids:
                try:
                    os.kill(pid, 0)
                    alive = True
                    break
                except OSError:
                    continue
            if not alive:
                break
            time.sleep(0.1)

    def _ensure_mediamtx(self, rtsp_url: str,
                         mediamtx_config: Optional[str],
                         force_restart: bool = True) -> Optional[subprocess.Popen]:
        is_local, host, port = self._is_local_rtsp(rtsp_url)
        if not is_local or not host:
            return None

        if force_restart:
            _log('Restarting mediamtx to ensure clean RTSP state')
            self._stop_existing_mediamtx()

        if self._port_open(host, port):
            _log(f'mediamtx already listening on {host}:{port}')
            return None

        mediamtx_bin = shutil.which('mediamtx')
        if not mediamtx_bin:
            _log('mediamtx not found in PATH; RTSP publish may fail')
            return None

        # Resolve config path from common locations so auto-start works
        # whether the script is run from repo root or cloudedge-client/.
        cfg_path: Optional[str] = None
        if mediamtx_config:
            candidates = []
            if os.path.isabs(mediamtx_config):
                candidates.append(mediamtx_config)
            else:
                script_dir = os.path.dirname(os.path.abspath(__file__))
                candidates.extend([
                    os.path.join(os.getcwd(), mediamtx_config),
                    os.path.join(script_dir, mediamtx_config),
                    os.path.join(os.path.dirname(script_dir), mediamtx_config),
                ])
            for c in candidates:
                if os.path.exists(c):
                    cfg_path = c
                    break

        cmd = [mediamtx_bin]
        if cfg_path:
            cmd.append(cfg_path)
            _log(f'Using mediamtx config: {cfg_path}')
        else:
            _log('mediamtx config not found; using builtin defaults')

        _log('Starting mediamtx automatically')
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)

        deadline = time.time() + 5.0
        while time.time() < deadline:
            if self._port_open(host, port):
                _log(f'mediamtx started on {host}:{port}')
                return proc
            if proc.poll() is not None:
                break
            time.sleep(0.1)

        _log('mediamtx did not start successfully')
        try:
            proc.terminate()
        except Exception:
            pass
        return None

    def stream_rtsp(self, rtsp_url: str, duration_sec: int = 0,
                    mediamtx_auto: bool = True,
                    mediamtx_config: Optional[str] = 'mediamtx.yml',
                    mediamtx_force_restart: bool = True) -> None:
        """Stream video to an RTSP server, restarting ffmpeg on reconnect."""
        _log(f'RTSP mode → {rtsp_url}')
        mediamtx_proc: Optional[subprocess.Popen] = None
        if mediamtx_auto:
            mediamtx_proc = self._ensure_mediamtx(
                rtsp_url,
                mediamtx_config,
                force_restart=mediamtx_force_restart,
            )

        start = time.time()
        magic = struct.pack('>I', _PPCS_MAGIC)
        buf = bytearray()
        got_key = False
        last_ts: Optional[int] = None
        wall_t0: Optional[float] = None
        idle_since: Optional[float] = None
        ffproc: Optional[subprocess.Popen] = None
        _MAX_IDLE = 15.0
        _MAX_RETRIES = 50  # more retries for long-running RTSP

        def _start_ffmpeg() -> subprocess.Popen:
            cmd = [
                'ffmpeg', '-hide_banner', '-loglevel', 'warning',
                '-analyzeduration', '10M', '-probesize', '10M',
                '-fflags', 'nobuffer+genpts',
                '-use_wallclock_as_timestamps', '1',
                '-f', 'h264', '-i', 'pipe:0',
                '-c:v', 'copy', '-f', 'rtsp',
                '-rtsp_transport', 'tcp',
                rtsp_url,
            ]
            _log(f'Starting ffmpeg → {rtsp_url}')
            return subprocess.Popen(cmd, stdin=subprocess.PIPE,
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)

        def _stop_ffmpeg() -> None:
            nonlocal ffproc
            if ffproc and ffproc.poll() is None:
                try:
                    ffproc.stdin.close()
                except Exception:
                    pass
                ffproc.terminate()
                try:
                    ffproc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    ffproc.kill()
            ffproc = None

        def _write_frame(frame: bytes) -> bool:
            nonlocal ffproc
            if not ffproc or ffproc.poll() is not None:
                _stop_ffmpeg()
                ffproc = _start_ffmpeg()
            try:
                ffproc.stdin.write(frame)
                ffproc.stdin.flush()
                return True
            except (BrokenPipeError, OSError):
                _log('ffmpeg pipe broken — will restart')
                _stop_ffmpeg()
                return False

        retries = 0
        try:
            while True:
                if duration_sec > 0 and time.time() - start >= duration_sec:
                    break

                if not self.p2p.running:
                    if retries >= _MAX_RETRIES:
                        _log(f'Giving up after {retries} reconnect attempts')
                        break
                    retries += 1
                    delay = min(2 ** retries, 30)
                    _log(f'Disconnected — retry {retries}/{_MAX_RETRIES} '
                         f'in {delay}s')
                    time.sleep(delay)
                    if self.reconnect():
                        _log('Reconnected')
                        buf.clear()
                        got_key = False
                        last_ts = None
                        wall_t0 = None
                        idle_since = None
                        _stop_ffmpeg()  # restart ffmpeg with fresh stream
                    else:
                        _log('Reconnect failed')
                    continue

                data = self.p2p.read(1, 4096, timeout_ms=500)
                if not data:
                    if idle_since is None:
                        idle_since = time.time()
                    elif time.time() - idle_since > _MAX_IDLE:
                        _log(f'No data for {_MAX_IDLE}s — forcing reconnect')
                        self.p2p.running = False
                    continue
                idle_since = None
                retries = 0
                buf.extend(data)

                while len(buf) >= _MEDIA_HDR:
                    if buf[:4] == magic:
                        if len(buf) < _PPCS_HDR:
                            break
                        h = _ppcs_parse(bytes(buf[:_PPCS_HDR]))
                        if not h:
                            del buf[:1]; continue
                        total = _PPCS_HDR + h['payload_len']
                        if len(buf) < total:
                            break
                        del buf[:_PPCS_HDR]
                        continue

                    mh = _MediaHdr.unpack(bytes(buf[:_MEDIA_HDR]))
                    total = _MEDIA_HDR + mh.frame_size
                    if mh.frame_size == 0 or mh.frame_size > 2 * 1024 * 1024:
                        del buf[:1]; continue
                    if len(buf) < total:
                        break

                    frame = bytes(buf[_MEDIA_HDR:total])

                    if mh.is_video():
                        if not got_key:
                            if (b'\x00\x00\x00\x01\x67' in frame
                                    or b'\x00\x00\x00\x01\x27' in frame):
                                got_key = True
                                wall_t0 = time.time()
                                last_ts = mh.timestamp
                                _log('Got keyframe — streaming')
                            else:
                                del buf[:total]; continue

                        if last_ts is not None and wall_t0 is not None:
                            dt = (mh.timestamp - last_ts) & 0xFFFFFFFF
                            if 0 < dt < 5000:
                                target = wall_t0 + dt / 1000.0
                                gap = target - time.time()
                                if gap > 0:
                                    time.sleep(gap)
                            wall_t0 += dt / 1000.0
                        last_ts = mh.timestamp

                        _write_frame(frame)
                        self.frame_count += 1
                        self.total_bytes += len(frame)

                        if self.frame_count <= 3 or self.frame_count % 30 == 0:
                            el = time.time() - start
                            fps = self.frame_count / el if el > 0 else 0
                            _log(f'Frame {self.frame_count}: {mh.frame_size}B '
                                 f'ts={mh.timestamp} total={self.total_bytes}B '
                                 f'{fps:.1f}fps')

                    del buf[:total]
        finally:
            _stop_ffmpeg()
            if mediamtx_proc and mediamtx_proc.poll() is None:
                _log('Leaving auto-started mediamtx running')

        _log(f'Done: {self.frame_count} frames, {self.total_bytes} bytes')

    def close(self) -> None:
        self.p2p.close()


# ═════════════════════════════════════════════════════════════════════
# CLI
# ═════════════════════════════════════════════════════════════════════

def main() -> int:
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)

    ap = argparse.ArgumentParser(
        description='CloudEdge camera — pure-Python P2P client',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    ap.add_argument('--config', metavar='FILE',
                    help='JSON config file with did, password, initstring, '
                         'and optionally dispatch_servers')
    ap.add_argument('--did',
                    help='Device ID  (e.g. UABPAM-000000-XXXXX)')
    ap.add_argument('--password',
                    help='Password MD5 hash (32 hex chars)')
    ap.add_argument('--initstring',
                    help='PPCS init string from cloud API')
    ap.add_argument('--duration', type=int, default=60,
                    help='Seconds to stream (0 = indefinite)')
    ap.add_argument('-o', '--output', default='live.h264',
                    help='Output file (use "-" for stdout)')
    ap.add_argument('--rtsp', metavar='URL',
                    help='Publish to RTSP server via ffmpeg '
                         '(e.g. rtsp://localhost:8554/camera)')
    ap.add_argument('--no-mediamtx-auto', action='store_true',
                    help='Do not auto-start mediamtx for local rtsp:// URLs')
    ap.add_argument('--mediamtx-config', default='mediamtx.yml',
                    help='mediamtx config path used when auto-starting '
                         '(default: mediamtx.yml)')
    ap.add_argument('--mediamtx-no-restart', action='store_true',
                    help='Do not force-restart existing mediamtx process')

    args = ap.parse_args()

    # Load config file and let CLI args override
    dispatch_servers = None
    if args.config:
        with open(args.config) as f:
            cfg = json.load(f)
        if not args.did:
            args.did = cfg.get('did')
        if not args.password:
            args.password = cfg.get('password')
        if not args.initstring:
            args.initstring = cfg.get('initstring')
        dispatch_servers = cfg.get('dispatch_servers')

    if not all([args.did, args.password, args.initstring]):
        ap.error('--did, --password, and --initstring are required '
                 '(via CLI args or --config file)')

    _log(f'DID: {args.did}')
    dispatchers = dispatch_servers or decode_initstring_servers(args.initstring)
    _log(f'Dispatchers: {dispatchers}')

    client = CloudEdgeClient(args.did, args.password, args.initstring,
                             dispatch_servers)
    if not client.connect():
        _log('Connection failed')
        return 1

    try:
        if args.rtsp:
            client.stream_rtsp(
                args.rtsp,
                args.duration,
                mediamtx_auto=not args.no_mediamtx_auto,
                mediamtx_config=args.mediamtx_config,
                mediamtx_force_restart=not args.mediamtx_no_restart,
            )
        else:
            out: BinaryIO
            if args.output == '-':
                out = sys.stdout.buffer
            else:
                out = open(args.output, 'wb')
            try:
                client.stream_video(out, args.duration)
            except BrokenPipeError:
                pass
            finally:
                if out is not sys.stdout.buffer:
                    out.close()
    except KeyboardInterrupt:
        _log('Interrupted')
    finally:
        client.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
