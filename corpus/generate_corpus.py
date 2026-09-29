#!/usr/bin/env python3
"""
SIH26159 SecureMailScope — synthetic corpus generator.

Builds the 5 labeled scenario captures in `corpus/scenarios/` with NO third-party
dependencies (no scapy / tshark required). PCAP (libpcap) files are written byte-by-byte.

TLS bytes are REAL, not faked: scenarios that need a genuine TLS handshake are
produced by running a loopback TCP capture proxy in front of a local `ssl` server,
recording both directions to disk. That guarantees the ClientHello/ServerHello/
Certificate/ChangeCipherSpec/Finished records are cryptographically genuine, so the
parser and rule engine have something real to grade.

Scenarios (labels match `docs/03` rule IDs):
  1. stripped.pcap            SMTP: STARTTLS advertised, issued, then refused (454) -> plaintext continues  [SMS-ENF-002]
  2. advertised-unused.pcap   SMTP: STARTTLS advertised, never issued; session stays plaintext            [SMS-ENF-001]
  3. weak-cipher.pcap         IMAP: genuine TLS 1.2 handshake, non-PFS CBC suite (no forward secrecy)     [SMS-CIPH-002]
  4. weak-key.pcap            POP3: genuine TLS 1.2 handshake, RSA-1024 leaf certificate                   [SMS-KEY-001]
  5. no-tls.pcap              POP3: implicit-TLS port spoken in cleartext, no TLS at all                    [SMS-ENF-002 family]

Usage:  python3 corpus/generate_corpus.py
Output: corpus/scenarios/*.pcap + corpus/scenarios/LABELS.md + corpus/scenarios/oracle.md
"""

from __future__ import annotations

import datetime as _dt
import os
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCENARIOS = HERE / "scenarios"

# --------------------------------------------------------------------------
# Minimal PCAP writer (classic libpcap format, linktype 1 = Ethernet)
# --------------------------------------------------------------------------

LINKTYPE_ETHERNET = 1
SNAPLEN = 262144

# Deterministic clock: 2026-01-01T00:00:00Z. The corpus must be byte-reproducible
# so that corpus/expected/ hashes are stable and `make verify` can prove
# report reproducibility (D5). Never use the wall clock here.
BASE_TS = 1767225600.0
_t_cursor = [BASE_TS]


def _ts() -> float:
    _t_cursor[0] += 0.0003
    return _t_cursor[0]


class PcapWriter:
    def __init__(self, path: Path):
        self.path = path
        self.f = open(path, "wb")
        self._write_header()
        self._t0 = _ts()
        self.n = 0

    def _write_header(self) -> None:
        # magic, ver 2.4, thiszone 0, sigfigs 0, snaplen, network(1=Ethernet)
        self.f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, SNAPLEN, LINKTYPE_ETHERNET))

    def _eth(self, src: bytes, dst: bytes, ethertype: int, payload: bytes) -> bytes:
        return dst + src + struct.pack("!H", ethertype) + payload

    def _ipv4(self, src: str, dst: str, payload: bytes, ident: int) -> bytes:
        def ip2b(a: str) -> bytes:
            return bytes(int(x) for x in a.split("."))

        total = 20 + len(payload)
        hdr = struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0x00, total, ident & 0xFFFF, 0x4000, 64, 6, 0, ip2b(src), ip2b(dst),
        )
        return hdr + payload

    def _tcp(self, sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes) -> bytes:
        # 20-byte TCP header: sport, dport, seq, ack, data_offset<<4|reserved, flags,
        # window, checksum, urgent  ->  "!HHIIBBHHH" (9 fields = exactly 20 bytes)
        hdr = struct.pack(
            "!HHIIBBHHH",
            sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
            (5 << 4), flags, 8192, 0, 0,
        )
        return hdr + payload

    def packet(self, ts: float, src_mac, dst_mac, sip, dip, sport, dport, seq, ack, flags, payload=b""):
        # build innermost-first: TCP -> IPv4 -> Ethernet
        tcp = self._tcp(sport, dport, seq, ack, flags, payload)
        frame = self._eth(src_mac, dst_mac, 0x0800, self._ipv4(sip, dip, tcp, self.n))
        sec = int(ts)
        usec = int((ts - sec) * 1_000_000)
        self.f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
        self.f.write(frame)
        self.n += 1

    def close(self):
        self.f.close()
        return self.path


# TCP flag bits
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10

MAC_C = bytes.fromhex("020000000001")   # "client"
MAC_S = bytes.fromhex("020000000002")   # "server"
CLIENT_IP, SERVER_IP = "198.51.100.10", "198.51.100.20"


class Conversation:
    """Replays a scripted client<->server byte dialog into a PcapWriter."""

    def __init__(self, w: PcapWriter, client_port: int, server_port: int):
        self.w, self.cp, self.sp = w, client_port, server_port
        self.cseq, self.sseq = 1000, 5000
        self.t = _ts()

    def _tick(self):
        self.t += 0.0004

    def c2s(self, data: bytes, flags: int = PSH | ACK):
        self.w.packet(self.t, MAC_C, MAC_S, CLIENT_IP, SERVER_IP, self.cp, self.sp,
                      self.cseq, self.sseq, flags, data)
        self.cseq += len(data)
        self._tick()

    def s2c(self, data: bytes, flags: int = PSH | ACK):
        self.w.packet(self.t, MAC_S, MAC_C, SERVER_IP, CLIENT_IP, self.sp, self.cp,
                      self.sseq, self.cseq, flags, data)
        self.sseq += len(data)
        self._tick()

    def handshake(self):
        self.c2s(b"", SYN)
        self.s2c(b"", SYN | ACK)
        self.c2s(b"", ACK)

    def teardown(self):
        self.c2s(b"", FIN | ACK)
        self.s2c(b"", FIN | ACK)
        self.c2s(b"", ACK)


# --------------------------------------------------------------------------
# Plaintext mail protocol dialogs
# --------------------------------------------------------------------------

SMTP_GREET = b"220 mail.lab.example ESMTP Postfix\r\n"
SMTP_EHLO_OK = (b"250-mail.lab.example\r\n"
                b"250-PIPELINING\r\n"
                b"250-SIZE 10240000\r\n"
                b"250-STARTTLS\r\n"
                b"250-ENHANCEDSTATUSCODES\r\n"
                b"250 8BITMIME\r\n")
SMTP_454 = b"454 4.7.0 TLS not available\r\n"


def _b(s: str) -> bytes:
    return s.encode()


# --------------------------------------------------------------------------
# Real TLS via loopback capture proxy
# --------------------------------------------------------------------------

FIXTURES = HERE / ".fixtures"


def _make_cert(cn: str, key_size: int) -> tuple[str, str]:
    """
    Self-signed leaf cert -> (certfile, keyfile), using the `cryptography` lib.

    RSA key generation is not seedable, so the material is generated once and
    cached under corpus/.fixtures/ (gitignored -- these are throwaway lab keys,
    never secrets). Reusing the cache makes the corpus byte-reproducible across
    runs, which is what `make verify` depends on. Validity dates and serial are
    pinned to fixed values for the same reason.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime

    FIXTURES.mkdir(parents=True, exist_ok=True)
    cf, kf = FIXTURES / f"{cn}-{key_size}.cert.pem", FIXTURES / f"{cn}-{key_size}.key.pem"
    if cf.exists() and kf.exists():
        return str(cf), str(kf)

    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    not_before = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(0x0C0FFEE0 + key_size)
        .not_valid_before(not_before)
        .not_valid_after(not_before + datetime.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    kf.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    cf.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return str(cf), str(kf)


def _tls_server(certfile: str, keyfile: str, port: int, banner: bytes,
                tls12: bool = True) -> None:
    """Minimal TLS server that sends a plaintext banner, then completes a handshake."""
    ctx = _server_ctx(certfile, keyfile, tls12=tls12)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)

    def _run():
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        try:
            conn.sendall(banner)
            tls = ctx.wrap_socket(conn, server_side=True)
            try:
                tls.recv(4096)
            except OSError:
                pass
            try:
                tls.unwrap()          # close_notify -> clean shutdown record
            except (ssl.SSLError, OSError):
                pass
            tls.close()
        except (ssl.SSLError, OSError):
            pass
        finally:
            try:
                srv.close()
            except OSError:
                pass

    threading.Thread(target=_run, daemon=True).start()


def _tls_capture(path: Path, client_port: int, server_port: int,
                 certfile: str, keyfile: str, banner: bytes, probe: bytes,
                 ciphers: str, tls12: bool = True) -> Path:
    """
    Record a genuine TLS conversation to `path`, from the client's point of view.

    The client half is driven with in-memory BIOs (ssl.MemoryBIO) rather than
    wrap_socket(). That is required: wrap_socket() hands the raw fd straight to
    OpenSSL via SSL_set_fd, so all handshake I/O bypasses Python and cannot be
    observed. With MemoryBIO every byte handed to / read from the socket is
    recorded verbatim, giving an exact, genuine ClientHello / ServerHello /
    Certificate / Finished transcript.
    """
    w = PcapWriter(path)
    t = _ts()
    cseq, sseq = 1000, 5000

    def emit(from_client: bool, data: bytes) -> None:
        nonlocal t, cseq, sseq
        t += 0.0003
        if from_client:
            w.packet(t, MAC_C, MAC_S, CLIENT_IP, SERVER_IP,
                     client_port, server_port, cseq, sseq, PSH | ACK, data)
            cseq += len(data)
        else:
            w.packet(t, MAC_S, MAC_C, SERVER_IP, CLIENT_IP,
                     server_port, client_port, sseq, cseq, PSH | ACK, data)
            sseq += len(data)

    port = _free_port()
    _tls_server(certfile, keyfile, port, banner, tls12=tls12)
    time.sleep(0.2)  # let the listener bind

    cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cctx.check_hostname = False
    cctx.verify_mode = ssl.CERT_NONE
    cctx.set_ciphers(ciphers)
    if tls12:
        cctx.minimum_version = ssl.TLSVersion.TLSv1_2
        cctx.maximum_version = ssl.TLSVersion.TLSv1_2

    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    sock.settimeout(10.0)
    cin, cout = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = cctx.wrap_bio(cin, cout, server_hostname="mail.lab.example")

    def flush() -> None:
        """Move ciphertext from the SSL engine out onto the wire."""
        data = cout.read()
        if data:
            emit(True, data)
            sock.sendall(data)

    def pump() -> None:
        """Move ciphertext from the wire into the SSL engine."""
        data = sock.recv(16384)
        if data:
            emit(False, data)
            cin.write(data)

    try:
        banner_rx = sock.recv(4096)          # plaintext greeting, before handshake
        if banner_rx:
            emit(False, banner_rx)

        # --- drive the handshake to completion ---
        while True:
            try:
                obj.do_handshake()
                break
            except ssl.SSLWantReadError:
                flush()
                pump()
            except ssl.SSLWantWriteError:  # pragma: no cover - memory BIO
                flush()
        flush()

        # --- application data ---
        obj.write(probe)
        flush()
        try:
            pump()
        except (ssl.SSLError, OSError):
            pass

        # --- close_notify for a clean shutdown record ---
        try:
            obj.unwrap()
        except (ssl.SSLWantReadError, ssl.SSLZeroReturnError):
            pass
        except (ssl.SSLError, OSError):
            pass
        flush()
    except (ssl.SSLError, OSError) as e:
        print(f"    (tls note: {e})")
    finally:
        try:
            sock.close()
        except OSError:
            pass
        w.close()
    return path


def _server_ctx(certfile: str, keyfile: str, tls12: bool = True) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # SECLEVEL=0 so the server will *offer* deliberately-weak material.
    # This is a lab fixture, not production config.
    ctx.set_ciphers("ALL:@SECLEVEL=0")
    ctx.load_cert_chain(certfile, keyfile)
    if tls12:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


# --------------------------------------------------------------------------
# Scenario builders
# --------------------------------------------------------------------------

def s1_stripped() -> Path:
    """SMTP: STARTTLS advertised, client issues it, server refuses (454), plaintext continues."""
    p = SCENARIOS / "stripped.pcap"
    w = PcapWriter(p)
    c = Conversation(w, 49152, 25)
    c.handshake()
    c.s2c(SMTP_GREET)
    c.c2s(_b("EHLO forensics-client\r\n"))
    c.s2c(SMTP_EHLO_OK)
    c.c2s(_b("STARTTLS\r\n"))
    c.s2c(SMTP_454)                      # <-- refusal: the strip
    c.c2s(_b("MAIL FROM:<alice@lab.example>\r\n"))
    c.s2c(_b("250 2.1.0 Ok\r\n"))
    c.c2s(_b("RCPT TO:<bob@peer.example>\r\n"))
    c.s2c(_b("250 2.1.5 Ok\r\n"))
    c.c2s(_b("DATA\r\n"))
    c.s2c(_b("354 End data with <CR><LF>.<CR><LF>\r\n"))
    c.c2s(_b("Subject: quarterly\r\n\r\nplaintext body continues after refusal\r\n.\r\n"))
    c.s2c(_b("250 2.0.0 Ok: queued\r\n"))
    c.c2s(_b("QUIT\r\n"))
    c.s2c(_b("221 2.0.0 Bye\r\n"))
    c.teardown()
    w.close()
    return p


def s2_advertised_unused() -> Path:
    """SMTP: STARTTLS advertised, never issued; session stays plaintext."""
    p = SCENARIOS / "advertised-unused.pcap"
    w = PcapWriter(p)
    c = Conversation(w, 49320, 25)
    c.handshake()
    c.s2c(SMTP_GREET)
    c.c2s(_b("EHLO forensics-client\r\n"))
    c.s2c(SMTP_EHLO_OK)
    # no STARTTLS issued -> plaintext continues
    c.c2s(_b("MAIL FROM:<carol@lab.example>\r\n"))
    c.s2c(_b("250 2.1.0 Ok\r\n"))
    c.c2s(_b("RCPT TO:<dave@peer.example>\r\n"))
    c.s2c(_b("250 2.1.5 Ok\r\n"))
    c.c2s(_b("QUIT\r\n"))
    c.s2c(_b("221 2.0.0 Bye\r\n"))
    c.teardown()
    w.close()
    return p


def s3_weak_cipher() -> Path:
    """IMAP: genuine TLS 1.2 handshake negotiating a non-PFS CBC suite."""
    cert, key = _make_cert("mail.lab.example", 2048)
    return _tls_capture(
        SCENARIOS / "weak-cipher.pcap", 49500, 993, cert, key,
        banner=b"* OK [CAPABILITY IMAP4rev1] WeakLab ready\r\n",
        probe=b"a001 CAPABILITY\r\n",
        ciphers="AES128-SHA:@SECLEVEL=0",   # static RSA kex => NO forward secrecy
    )


def s4_weak_key() -> Path:
    """POP3: genuine TLS 1.2 handshake with an RSA-1024 leaf certificate."""
    cert, key = _make_cert("mail.lab.example", 1024)
    return _tls_capture(
        SCENARIOS / "weak-key.pcap", 49600, 995, cert, key,
        banner=b"+OK WeakLab POP3 ready\r\n",
        probe=b"USER alice\r\n",
        ciphers="DEFAULT:@SECLEVEL=0",
    )


def s5_no_tls() -> Path:
    """POP3 spoken in the clear on an implicit-TLS port: no TLS at all."""
    p = SCENARIOS / "no-tls.pcap"
    w = PcapWriter(p)
    c = Conversation(w, 49700, 995)
    c.handshake()
    c.s2c(b"+OK ClearLab POP3 ready\r\n")
    c.c2s(_b("USER alice\r\n"))
    c.s2c(b"+OK\r\n")
    c.c2s(_b("PASS secret\r\n"))
    c.s2c(b"+OK maildrop locked and ready\r\n")
    c.c2s(_b("STAT\r\n"))
    c.s2c(b"+OK 2 320\r\n")
    c.c2s(_b("QUIT\r\n"))
    c.s2c(b"+OK Bye\r\n")
    c.teardown()
    w.close()
    return p


SCENARIOS_BUILD = [
    ("stripped.pcap", s1_stripped, "SMS-ENF-002", "high"),
    ("advertised-unused.pcap", s2_advertised_unused, "SMS-ENF-001", "medium"),
    ("weak-cipher.pcap", s3_weak_cipher, "SMS-CIPH-002", "medium"),
    ("weak-key.pcap", s4_weak_key, "SMS-KEY-001", "high"),
    ("no-tls.pcap", s5_no_tls, "SMS-ENF-002", "high"),
]


def main() -> None:
    SCENARIOS.mkdir(parents=True, exist_ok=True)
    (HERE / "expected").mkdir(exist_ok=True)
    (HERE / "live").mkdir(exist_ok=True)

    print("Generating synthetic corpus (no scapy/tshark required)...\n")
    made = []
    for name, fn, rule, sev in SCENARIOS_BUILD:
        print(f"  - {name:<26} [{rule} / {sev}]")
        try:
            made.append((fn(), rule, sev))
        except Exception as e:  # noqa: BLE001
            print(f"      FAILED: {e}")

    labels = [
        "# Corpus scenarios — expected labels\n",
        "Generated by `corpus/generate_corpus.py`. TLS bytes are genuine: a real",
        "loopback `ssl` handshake driven through in-memory BIOs, so ClientHello /",
        "ServerHello / Certificate / ServerKeyExchange are actual wire bytes.\n",
        "| File | Expected finding | Severity | Service | Notes |",
        "|---|---|---|---|---|",
    ]
    notes = {
        "stripped.pcap": "STARTTLS advertised + issued, refused with 454, plaintext continues",
        "advertised-unused.pcap": "STARTTLS advertised, never issued",
        "weak-cipher.pcap": "real TLS1.2, static-RSA suite 0x002f (no forward secrecy)",
        "weak-key.pcap": "real TLS1.2, RSA-1024 leaf cert",
        "no-tls.pcap": "POP3 in the clear on port 995",
    }
    svc = {"stripped.pcap": "smtp", "advertised-unused.pcap": "smtp",
           "weak-cipher.pcap": "imap", "weak-key.pcap": "pop3", "no-tls.pcap": "pop3"}
    for path, rule, sev in made:
        labels.append(
            f"| `{path.name}` | `{rule}` | {sev} | {svc.get(path.name, '?')} "
            f"| {notes.get(path.name, '')} |")

    labels += [
        "",
        "## Reproducibility",
        "",
        "The three plaintext scenarios are byte-reproducible (fixed clock, no RNG).",
        "The two TLS scenarios are **not** byte-reproducible: a genuine handshake",
        "embeds a fresh ServerHello `random` and an ECDHE key share on every run.",
        "Normalising those would mean faking the handshake, so it is not done.",
        "",
        "Therefore the committed `.pcap` files are the **frozen fixtures**. Regenerate",
        "once, then treat them as read-only inputs. `make verify` must re-run the",
        "pipeline against these files -- never the generator -- which is what D5",
        "report reproducibility actually requires (same capture + same package_ver",
        "=> same report SHA-256).",
        "",
        "`expected/corpus.sha256` pins the fixture digests. Verify with:",
        "`shasum -a 256 -c expected/corpus.sha256` (run from `corpus/`).",
    ]
    (SCENARIOS / "LABELS.md").write_text("\n".join(labels) + "\n")

    # Pin the SHA-256 of this run so drift is detectable. Kept comment-free
    # because macOS `shasum -c` rejects comment lines.
    import hashlib
    lines = []
    for path, _rule, _sev in made:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  scenarios/{path.name}")
    (HERE / "expected" / "corpus.sha256").write_text("\n".join(lines) + "\n")

    print(f"\nDone: {len(made)}/5 scenarios -> {SCENARIOS}")
    print(f"Pinned SHA-256 -> {HERE / 'expected' / 'corpus.sha256'}")
    print("Note: TLS captures embed fresh handshake randomness -- these files are now frozen fixtures.")
    print("Next: `make verify` re-runs the pipeline against them (never the generator).")


if __name__ == "__main__":
    main()
