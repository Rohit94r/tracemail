"""
SIH26159 SecureMailScope — Exact packet byte-offset index.

Byte offsets in findings must be verifiable. The previous implementation
derived them as ``packet_index * 128``, which is a fabricated number that
happened to look plausible. This module walks the container format and
returns the real offset of every packet's data inside the file.

Supported containers:
  * classic libpcap  (magic a1b2c3d4 / a1b23c4d and byte-swapped forms)
  * pcapng           (SHB / IDB / EPB block walk)

If a container cannot be walked, :func:`build_offset_index` returns an
empty mapping and the caller must mark offsets as unavailable rather
than inventing them.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Dict, Optional

# Classic pcap global-header magics, keyed by the raw 4 bytes on disk.
# Matching on the raw bytes is the only unambiguous test: the two magics
# 0xA1B2C3D4 and 0xD4C3B2A1 are byte-swaps of each other, so every integer
# interpretation of a valid header lands on one of the two known values and
# an integer-based test cannot tell the file's byte order apart from the
# other. Value: (endian used for the rest of the header, divisor to seconds).
_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1000),   # little-endian, microsecond
    b"\xa1\xb2\xc3\xd4": (">", 1000),   # big-endian, microsecond
    b"\x4d\x3c\xb2\xa1": ("<", 1),      # little-endian, nanosecond
    b"\xa1\xb2\x3c\x4d": (">", 1),      # big-endian, nanosecond
}

_PCAPNG_SHB = 0x0A0D0D0A
_PCAPNG_EPB = 0x00000006
_PCAPNG_SPB = 0x00000003


def detect_container(path: Path) -> str:
    """Return 'pcap', 'pcapng' or 'unknown'."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(4)
    except OSError:
        return "unknown"
    if len(head) < 4:
        return "unknown"
    if head in _PCAP_MAGICS:
        return "pcap"
    if head == b"\x0a\x0d\x0d\x0a":
        return "pcapng"
    return "unknown"


def _index_pcap(path: Path) -> Dict[int, int]:
    """Walk classic pcap record headers, returning {packet_no(1-based): offset}."""
    out: Dict[int, int] = {}
    with open(path, "rb") as fh:
        gh = fh.read(24)
        if len(gh) < 24:
            return out
        spec = _PCAP_MAGICS.get(gh[:4])
        if spec is None:
            return out
        endian, _tsresol = spec
        offset = 24
        idx = 1
        while True:
            rh = fh.read(16)
            if len(rh) < 16:
                break
            _ts_sec, _ts_frac, incl_len, _orig_len = struct.unpack(endian + "IIII", rh)
            if incl_len > 0x00FFFFFF:  # implausible; stop rather than guess
                break
            out[idx] = offset + 16
            offset += 16 + incl_len
            fh.seek(incl_len, 1)
            idx += 1
    return out


def _index_pcapng(path: Path) -> Dict[int, int]:
    """Walk pcapng blocks, returning {packet_no(1-based): offset}."""
    out: Dict[int, int] = {}
    idx = 1
    with open(path, "rb") as fh:
        while True:
            head = fh.read(8)
            if len(head) < 8:
                break
            (btype,) = struct.unpack("<I", head[:4])
            (total_len,) = struct.unpack("<I", head[4:8])
            if total_len < 12:
                break
            body_at = fh.tell()
            if btype == _PCAPNG_EPB:
                # interface_id(4) ts_high(4) ts_low(4) cap_len(4) orig_len(4) data
                fixed = fh.read(20)
                if len(fixed) < 20:
                    break
                cap_len = struct.unpack("<I", fixed[16:20])[0]
                out[idx] = fh.tell()
                idx += 1
            elif btype == _PCAPNG_SPB:
                # original_len(4) then packet data
                fixed = fh.read(4)
                if len(fixed) < 4:
                    break
                out[idx] = fh.tell()
                idx += 1
            fh.seek(body_at + total_len - 4, 0)
    return out


def build_offset_index(path: Path) -> Dict[int, int]:
    """
    Return {packet_no (1-based): exact byte offset of that packet's data}.

    Empty dict means offsets could not be determined; callers must then
    report byte_offset_exact=False instead of fabricating a value.
    """
    kind = detect_container(path)
    try:
        if kind == "pcap":
            return _index_pcap(path)
        if kind == "pcapng":
            return _index_pcapng(path)
    except (OSError, struct.error):
        return {}
    return {}


def capture_digest(path: Path) -> str:
    """SHA-256 of the whole capture file, used as the content address."""
    import hashlib

    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def first_capture_time(path: Path) -> Optional[float]:
    """Earliest packet timestamp, or None when unreadable."""
    import datetime as _dt

    try:
        packets = _first_packets(path, 1)
    except Exception:
        return None
    if not packets:
        return None
    t = float(packets[0])
    return t


def _first_packets(path: Path, count: int):
    """Cheap timestamp read that does not depend on scapy."""
    kind = detect_container(path)
    stamps = []
    try:
        if kind == "pcap":
            with open(path, "rb") as fh:
                gh = fh.read(24)
                spec = _PCAP_MAGICS.get(gh[:4])
                if spec is None:
                    return []
                endian, div = spec
                for _ in range(count):
                    rh = fh.read(16)
                    if len(rh) < 16:
                        break
                    ts_sec, ts_frac, incl_len, _ = struct.unpack(endian + "IIII", rh)
                    stamps.append(ts_sec + (ts_frac / (1e9 if div == 1 else 1e6)))
                    fh.seek(incl_len, 1)
        elif kind == "pcapng":
            # tsresol defaults to microseconds; we only need an order-of-magnitude
            with open(path, "rb") as fh:
                while len(stamps) < count:
                    head = fh.read(8)
                    if len(head) < 8:
                        break
                    (btype,) = struct.unpack("<I", head[:4])
                    (total_len,) = struct.unpack("<I", head[4:8])
                    if total_len < 12:
                        break
                    body_at = fh.tell()
                    if btype == _PCAPNG_EPB:
                        fixed = fh.read(20)
                        if len(fixed) < 20:
                            break
                        hi, lo = struct.unpack("<II", fixed[4:12])
                        raw = (hi << 32) | lo
                        stamps.append(raw / 1e6)
                    fh.seek(body_at + total_len - 4, 0)
    except (OSError, struct.error):
        return []
    return stamps
