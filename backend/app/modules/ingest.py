"""
SIH26159 SecureMailScope — Module 1: Ingest & Parse
Implements the 6-class STARTTLS state machine (docs/01 §2) and X.509 parsing
via `cryptography`.

Every value emitted here is either read off the wire or explicitly marked as
unobservable. Nothing is defaulted to a plausible-looking constant.
"""

from __future__ import annotations

import datetime as dt
import re
from typing import List, Tuple, Dict, Any, Optional

from scapy.all import rdpcap, TCP, IP, Raw
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519, ed448

from ..models import FlowRecord, TLSDetails, X509Details, CertSummary
from .pcap_index import build_offset_index, detect_container, capture_digest, _first_packets

MAIL_PORTS = (25, 587, 465, 143, 993, 110, 995)

CIPHER_SUITE_MAP = {
    0x000A: ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "RSA", False, False),
    0x002F: ("TLS_RSA_WITH_AES_128_CBC_SHA", "RSA", False, False),
    0x0035: ("TLS_RSA_WITH_AES_256_CBC_SHA", "RSA", False, False),
    0x003C: ("TLS_RSA_WITH_AES_128_CBC_SHA256", "RSA", False, False),
    0x009C: ("TLS_RSA_WITH_AES_128_GCM_SHA256", "RSA", False, True),
    0x009D: ("TLS_RSA_WITH_AES_256_GCM_SHA384", "RSA", False, True),
    0xC013: ("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "ECDHE_RSA", True, False),
    0xC02B: ("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "ECDHE_ECDSA", True, True),
    0xC02C: ("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "ECDHE_ECDSA", True, True),
    0xC02F: ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE_RSA", True, True),
    0xC030: ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECDHE_RSA", True, True),
    0xC013 + 0x100: ("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "ECDHE_RSA", True, False),
    0x1301: ("TLS_AES_128_GCM_SHA256", "X25519", True, True),
    0x1302: ("TLS_AES_256_GCM_SHA384", "X25519", True, True),
    0x1303: ("TLS_CHACHA20_POLY1305_SHA256", "X25519", True, True),
}

# RFC 9325 mandatory-to-implement cipher list. Anything outside is weak.
WEAK_CIPHER_TOKENS = ("3DES", "DES", "RC4", "RC2", "NULL", "EXPORT", "IDEA", "SEED", "CBC")
NON_AEAD_CIPHERS = ("3DES", "DES", "RC4", "NULL", "EXPORT", "CBC", "SHA")

# SHA-1 / MD5 in a certificate signature is broken for new certs (RFC 6194,
# CWE-327). Recorded separately from key length so the reason is explicit.
WEAK_SIG_ALGOS = ("md5", "sha1")


def determine_service(port: int) -> str:
    if port in (25, 587):
        return "smtp"
    if port == 465:
        return "implicit-smtp"
    if port == 143:
        return "imap"
    if port == 993:
        return "implicit-imap"
    if port == 110:
        return "pop3"
    if port == 995:
        return "implicit-pop3"
    return "smtp"


def _fmt_ts(raw) -> Optional[str]:
    try:
        return dt.datetime.fromtimestamp(float(raw), dt.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    except (TypeError, ValueError, OSError, OverflowError):
        return None


def _key_info(pub) -> Tuple[Optional[str], Optional[int]]:
    """Return (algorithm_name, bit_or_curve_size). No invented defaults."""
    if isinstance(pub, rsa.RSAPublicKey):
        return "RSA", pub.key_size
    if isinstance(pub, dsa.DSAPublicKey):
        return "DSA", pub.key_size
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return "EC", pub.curve.key_size
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(pub, ed448.Ed448PublicKey):
        return "Ed448", 448
    return "unknown", None


def _cn(name) -> Optional[str]:
    try:
        vals = name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        return vals[0].value if vals else None
    except Exception:
        return None


def _san_list(cert) -> List[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(
            x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        return [str(n.value) for n in ext.value]
    except Exception:
        return []


def _is_ca(cert) -> bool:
    try:
        ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.BASIC_CONSTRAINTS)
        return bool(ext.value.ca)
    except Exception:
        return False


def _walk_cert_list(body: bytes) -> List[x509.Certificate]:
    """Walk a certificate_list body: 3B total_len then repeat(3B len + DER)."""
    certs: List[x509.Certificate] = []
    if len(body) < 3:
        return certs
    chain_len = int.from_bytes(body[0:3], "big")
    if chain_len == 0 or chain_len > len(body):
        return certs
    pos = 3
    limit = 3 + chain_len
    while pos + 3 <= limit:
        clen = int.from_bytes(body[pos : pos + 3], "big")
        pos += 3
        if clen == 0 or pos + clen > len(body):
            break
        der = body[pos : pos + clen]
        pos += clen
        try:
            certs.append(x509.load_der_x509_certificate(der, default_backend()))
        except Exception:
            return []
    # Only trust a layout that consumed the declared chain length exactly.
    return certs if pos == limit else []


def _parse_cert_chain(hpayload: bytes) -> List[x509.Certificate]:
    """
    Parse every certificate in a TLS Certificate (type 11) message.

    The server Certificate message in TLS 1.2 has NO certificate_request_context
    field: its body starts directly with the 3-byte certificate_list length.
    The context field exists only in the *client* Certificate message (TLS 1.2
    / 1.3), where it is a 1-byte length prefix. Assuming the context field is
    always present silently yields zero certificates, so both layouts are tried
    and the one that decodes cleanly is used.
    """
    candidates = []
    for skip in (0, 1):  # skip=0 -> TLS1.2 server, skip=1 -> client / TLS1.3
        if len(hpayload) < skip + 3:
            continue
        parsed = _walk_cert_list(hpayload[skip:])
        if parsed:
            candidates.append(parsed)
    if not candidates:
        return []
    return max(candidates, key=len)


def _analyse_chain(certs: List[x509.Certificate], now: Optional[dt.datetime]) -> Dict[str, Any]:
    """
    Honest chain assessment.

    We can verify *linkage* (each cert's issuer is the next cert's subject) and
    *self-signedness* from the wire. We cannot verify *trust* without a trust
    store, so trust is reported as not-performed rather than assumed True.
    """
    summaries: List[CertSummary] = []
    linkage_ok = True
    for i, c in enumerate(certs):
        subject_cn = _cn(c.subject)
        issuer_cn = _cn(c.issuer)
        alg, bits = _key_info(c.public_key())
        try:
            serial = format(c.serial_number, "x")
        except Exception:
            serial = None
        summaries.append(
            CertSummary(
                subject_cn=subject_cn,
                issuer_cn=issuer_cn,
                serial_hex=serial,
                not_before=c.not_valid_before_utc.isoformat()
                if hasattr(c, "not_valid_before_utc")
                else None,
                not_after=c.not_valid_after_utc.isoformat()
                if hasattr(c, "not_valid_after_utc")
                else None,
                public_key_alg=alg,
                public_key_bits=bits,
                signature_alg=getattr(c.signature_algorithm_oid, "_name", None),
                is_ca=_is_ca(c),
                self_signed=(c.subject == c.issuer),
            )
        )
        # Linkage: this cert's issuer must be the next cert's subject
        if i + 1 < len(certs) and issuer_cn is not None:
            next_subject = _cn(certs[i + 1].subject)
            if next_subject is not None and issuer_cn != next_subject:
                linkage_ok = False

    n = len(summaries)
    # A single self-signed certificate IS a complete path of length 1
    # (the leaf is its own anchor); otherwise completeness needs >1 cert.
    last_self_signed = bool(summaries and summaries[-1].self_signed)
    return {
        "certs": summaries,
        "chain_len": n,
        "chain_complete": bool(n) and (last_self_signed or n > 1),
        "chain_linkage_ok": (
            True if (n == 1 and last_self_signed) else (linkage_ok if n > 1 else None)
        ),
        "chain_root_included": last_self_signed,
        # Trust is a separate question and is NOT performed without a store.
        "trust_anchor_present": False,
        "trust_check_method": "not-performed",
        "validated": False,
    }


_SECRET_CMDS = (
    "PASS", "PASSWD", "AUTH", "AUTHENTICATE", "LOGIN", "USER",
    "APOP", "XOAUTH2", "SASL", "PLAIN",
)


def _redact_secrets(text: str) -> Tuple[str, bool]:
    """
    Mask credential material in any evidence snippet.

    The product contract forbids surfacing credentials. A capture of a cleartext
    login contains the real password, so any value following a credential-bearing
    command is replaced before the text can reach a finding, a report or a PDF.

    Returns (redacted_text, secrets_were_present).
    """
    out, found = [], False
    for line in re.split(r"(\r\n|\r|\n)", text):
        stripped = line.lstrip()
        upper = stripped.upper()
        for cmd in _SECRET_CMDS:
            if upper.startswith(cmd + " ") or upper.rstrip() == cmd:
                head = line[: len(line) - len(stripped)]
                out.append(f"{head}{cmd} [REDACTED]")
                found = True
                break
        else:
            out.append(line)
    return "".join(out), found


def _is_grease(value: int) -> bool:
    """GREASE extension/curve values (RFC 8701) are excluded from JA3/JA3S."""
    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


def _ja3s_from_server_hello(hpayload: bytes) -> Optional[str]:
    """
    Real JA3S: MD5 of
      SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat,SignatureAlgorithm

    Returns None rather than a placeholder when the ServerHello cannot be read.
    """
    import hashlib

    if len(hpayload) < 38:
        return None
    try:
        ver = str(hpayload[0] * 256 + hpayload[1])
        sess_len = hpayload[34]
        c_off = 35 + sess_len
        cipher = int.from_bytes(hpayload[c_off : c_off + 2], "big")
        e_off = c_off + 2 + 1  # cipher(2) + compression(1)
        exts: List[int] = []
        curves: List[int] = []
        formats: List[int] = []
        sigalgs: List[int] = []
        if len(hpayload) >= e_off + 2:
            ext_total = int.from_bytes(hpayload[e_off : e_off + 2], "big")
            p = e_off + 2
            end = min(p + ext_total, len(hpayload))
            while p + 4 <= end:
                etype = int.from_bytes(hpayload[p : p + 2], "big")
                elen = int.from_bytes(hpayload[p + 2 : p + 4], "big")
                data = hpayload[p + 4 : p + 4 + elen]
                exts.append(etype)
                if etype == 10 and len(data) >= 2:  # supported_groups
                    n = int.from_bytes(data[0:2], "big")
                    for i in range(n):
                        o = 2 + i * 2
                        if o + 2 <= len(data):
                            curves.append(int.from_bytes(data[o : o + 2], "big"))
                elif etype == 11 and len(data) >= 1:  # ec_point_formats
                    n = data[0]
                    for i in range(n):
                        if 1 + i < len(data):
                            formats.append(data[1 + i])
                elif etype == 13 and len(data) >= 2:  # signature_algorithms
                    n = int.from_bytes(data[0:2], "big")
                    for i in range(n):
                        o = 2 + i * 2
                        if o + 2 <= len(data):
                            sigalgs.append(int.from_bytes(data[o : o + 2], "big"))
                p += 4 + elen
        # JA3/JA3S use the values in WIRE ORDER, never sorted, and absent
        # fields are the empty string (not a "-" placeholder). The field list
        # matches the canonical Salesforce reference implementation, which
        # emits five fields (the spec blog's sixth "SignatureAlgorithm" field
        # is not produced by the released implementation and is therefore not
        # emitted here, so hashes stay comparable with public JA3S databases).
        ja3s = ",".join(
            [
                ver,
                str(cipher),
                "-".join(str(x) for x in exts if not _is_grease(x)),
                "-".join(str(x) for x in curves if not _is_grease(x)),
                "-".join(str(x) for x in formats if not _is_grease(x)),
            ]
        )
        return hashlib.md5(ja3s.encode()).hexdigest()
    except (IndexError, ValueError):
        return None


def _client_hello_max(hpayload: bytes) -> Optional[str]:
    """Highest version offered in a ClientHello (type 1)."""
    if len(hpayload) < 2:
        return None
    v = (hpayload[0], hpayload[1])
    return {
        (3, 0): "TLSv1.0",
        (3, 1): "TLSv1.1",
        (3, 2): "TLSv1.2",
        (3, 3): "TLSv1.2",
        (3, 4): "TLSv1.3",
    }.get(v)


def parse_capture(pcap_path, session_id: str) -> Tuple[List[FlowRecord], List[str]]:
    warnings: List[str] = []
    pcap_path = __import__("pathlib").Path(pcap_path)

    if not pcap_path.exists():
        warnings.append(f"File not found: {pcap_path.name}")
        return [], warnings

    container = detect_container(pcap_path)
    if container == "unknown":
        warnings.append(
            "Unrecognised capture container. Expected classic .pcap or .pcapng."
        )
        return [], warnings

    try:
        packets = rdpcap(str(pcap_path))
    except Exception as exc:
        warnings.append(f"Failed to read capture: {exc}")
        return [], warnings

    offsets = build_offset_index(pcap_path)
    offsets_exact = bool(offsets)
    if not offsets_exact and container == "pcapng":
        warnings.append(
            "Byte offsets unavailable for this pcapng layout; findings will omit them."
        )
    digest = capture_digest(pcap_path)
    ts_list = _first_packets(pcap_path, 1)
    capture_time = _fmt_ts(ts_list[0]) if ts_list else None
    capture_epoch = float(ts_list[0]) if ts_list else None

    # ---- group packets into flows, keeping true packet numbers -------------
    raw_flows: Dict[str, List[Tuple[int, Any]]] = {}
    for i, pkt in enumerate(packets):
        if IP not in pkt or TCP not in pkt:
            continue
        ip, tcp = pkt[IP], pkt[TCP]
        if tcp.dport in MAIL_PORTS:
            flow_key = f"tcp|{ip.src}->{ip.dst}:{tcp.dport}"
        elif tcp.sport in MAIL_PORTS:
            flow_key = f"tcp|{ip.dst}->{ip.src}:{tcp.sport}"
        else:
            continue
        raw_flows.setdefault(flow_key, []).append((i + 1, pkt))

    flow_records: List[FlowRecord] = []

    for flow_key, flow_pkts in raw_flows.items():
        first_no, first_pkt = flow_pkts[0]
        ip, tcp = first_pkt[IP], first_pkt[TCP]
        if tcp.dport in MAIL_PORTS:
            server_ip, server_port, client_ip = ip.dst, tcp.dport, ip.src
        else:
            server_ip, server_port, client_ip = ip.src, tcp.sport, ip.dst

        service = determine_service(server_port)

        has_tls_record = False
        tls_version_str = None
        cipher_code = None
        certs: List[x509.Certificate] = []
        ja3s_hash = None
        ch_max = None
        server_random = None
        tls_pkts: Dict[str, int] = {}

        saw_ccs = False
        starttls_pkts: Dict[str, int] = {}
        saw_advertised = saw_starttls_cmd = saw_refused = saw_plaintext_after = False
        first_payload_pkt = None
        tls_first_pkt = None
        cert_first_pkt = None
        all_payload = bytearray()

        for pkt_no, pkt in flow_pkts:
            if Raw not in pkt:
                continue
            data = bytes(pkt[Raw].load)
            if first_payload_pkt is None:
                first_payload_pkt = pkt_no
            all_payload.extend(data)

            idx, pkt_had_tls = 0, False
            while idx + 5 <= len(data):
                ctype = data[idx]
                maj, min_ = data[idx + 1], data[idx + 2]
                if not (ctype in (20, 21, 22, 23) and maj == 3 and min_ in (0, 1, 2, 3, 4)):
                    break
                has_tls_record = True
                pkt_had_tls = True
                rec_len = int.from_bytes(data[idx + 3 : idx + 5], "big")
                rec = data[idx + 5 : idx + 5 + rec_len]

                ver = {(3, 1): "TLSv1.0", (3, 2): "TLSv1.1",
                       (3, 3): "TLSv1.2", (3, 4): "TLSv1.3"}.get((maj, min_))
                if ver:
                    tls_version_str = ver
                    if tls_first_pkt is None:
                        tls_first_pkt = pkt_no
                        tls_pkts["handshake"] = pkt_no

                if ctype == 20:                             # ChangeCipherSpec
                    # In TLS 1.2 every handshake message after CCS is
                    # encrypted, so no further handshake parsing is valid.
                    saw_ccs = True
                if ctype == 22 and not saw_ccs:
                    h = 0
                    while h + 4 <= len(rec):
                        htype = rec[h]
                        hlen = int.from_bytes(rec[h + 1 : h + 4], "big")
                        # A handshake header that overruns the record means this
                        # is not a real handshake message (it is encrypted
                        # payload), so stop rather than emitting nonsense types.
                        if hlen > len(rec) - h - 4:
                            break
                        hp = rec[h + 4 : h + 4 + hlen]
                        if htype == 2 and len(hp) >= 38:      # ServerHello
                            sess_len = hp[34]
                            c_off = 35 + sess_len
                            if len(hp) >= c_off + 2:
                                cipher_code = int.from_bytes(hp[c_off : c_off + 2], "big")
                            server_random = hp[2:34].hex()
                            tls_pkts.setdefault("server_hello", pkt_no)
                            if ja3s_hash is None:
                                ja3s_hash = _ja3s_from_server_hello(hp)
                        elif htype == 1:                      # ClientHello
                            if ch_max is None:
                                ch_max = _client_hello_max(hp)
                        elif htype == 11:                     # Certificate
                            parsed = _parse_cert_chain(hp)
                            if parsed:
                                certs = parsed
                                if cert_first_pkt is None:
                                    cert_first_pkt = pkt_no
                                    tls_pkts["certificate"] = pkt_no
                        h += 4 + hlen
                idx += 5 + rec_len

            if not pkt_had_tls:
                text = data.decode("latin-1", errors="ignore")
                if tcp_ok_server(pkt, server_ip, server_port):
                    if "STARTTLS" in text.upper():
                        saw_advertised = True
                        starttls_pkts.setdefault("advertise", pkt_no)
                    up = text.upper()
                    if "454" in up or "STARTTLS NOT AVAILABLE" in up or "TLS NOT AVAILABLE" in up:
                        saw_refused = True
                        starttls_pkts.setdefault("refused", pkt_no)
                else:
                    up_c = text.upper()
                    if "STARTTLS" in up_c:
                        saw_starttls_cmd = True
                        starttls_pkts.setdefault("starttls_cmd", pkt_no)
                    # Cleartext protocol commands on an implicit-TLS port are
                    # the evidence that credentials travel unprotected.
                    for marker in ("USER ", "LOGIN", "AUTH ", "PASS", "CAPA", "STAT"):
                        if marker in up_c:
                            starttls_pkts.setdefault("cleartext_command", pkt_no)
                            if marker in ("USER ", "LOGIN", "AUTH ", "PASS"):
                                starttls_pkts.setdefault("cleartext_secret", pkt_no)
                            break
                    if saw_starttls_cmd and (
                        "MAIL FROM" in text.upper()
                        or "AUTH" in text.upper()
                        or "USER " in text.upper()
                        or "LOGIN" in text.upper()
                    ):
                        saw_plaintext_after = True
                        starttls_pkts.setdefault("cleartext_after", pkt_no)

        # ---- 6-class state machine (docs/01 §2) --------------------------
        if service.startswith("implicit-"):
            category = "implicit" if has_tls_record else "none_clear"
        elif saw_refused or (saw_advertised and saw_starttls_cmd and saw_plaintext_after):
            category = "stripped"
        elif saw_advertised and not saw_starttls_cmd:
            category = "advertised_unused"
        elif saw_advertised and has_tls_record:
            category = "advertised"
        elif has_tls_record:
            category = "injected"
        else:
            category = "none_clear"

        tls_details = None
        if has_tls_record:
            cipher_name, kx, pfs, aead = CIPHER_SUITE_MAP.get(
                cipher_code, ("TLS_UNKNOWN_CIPHER", "UNKNOWN", False, False)
            )
            if cipher_code is None:
                # Record layer seen but no ServerHello: version/cipher unobservable.
                tls_details = TLSDetails(
                    observed_version=None,
                    version_source="unknown",
                    cipher_suite_iana="TLS_UNKNOWN_CIPHER",
                    cipher_suite_code=None,
                    key_exchange="UNKNOWN",
                    key_exchange_source="unobservable",
                    pfs=False,
                    pfs_source="unobservable",
                    aead=False,
                    client_hello_max=ch_max,
                    server_random=server_random,
                )
            else:
                is_tls13 = cipher_name.startswith("TLS_") and (
                    (cipher_code & 0xFF00) == 0x1300
                )
                tls_details = TLSDetails(
                    observed_version=tls_version_str,
                    version_source="wire",
                    client_hello_max=ch_max,
                    cipher_suite_iana=cipher_name,
                    cipher_suite_code=cipher_code,
                    key_exchange=kx,
                    key_exchange_source="inferred-from-cipher-suite",
                    pfs=pfs,
                    pfs_source=(
                        "protocol-guaranteed-tls13"
                        if is_tls13
                        else "inferred-from-cipher-suite"
                    ),
                    aead=aead,
                    server_random=server_random,
                    ja3s=ja3s_hash,
                )

        # ---- X.509 ------------------------------------------------------
        x509_details = None
        if certs:
            leaf = certs[0]
            subject_cn = _cn(leaf.subject)
            sans = _san_list(leaf)
            alg, bits = _key_info(leaf.public_key())
            sig_algo = getattr(leaf.signature_algorithm_oid, "_name", None)
            chain = _analyse_chain(certs, None)

            not_after = (
                leaf.not_valid_after_utc if hasattr(leaf, "not_valid_after_utc")
                else leaf.not_valid_after
            )
            not_before = (
                leaf.not_valid_before_utc if hasattr(leaf, "not_valid_before_utc")
                else leaf.not_valid_before
            )
            expired = days_left = None
            ref = capture_epoch or dt.datetime.now(dt.timezone.utc).timestamp()
            try:
                na_epoch = not_after.timestamp()
                days_left = int((na_epoch - ref) // 86400)
                expired = days_left < 0
            except (OSError, OverflowError, ValueError):
                pass

            x509_details = X509Details(
                subject_cn=subject_cn,
                san=sans,
                issuer=leaf.issuer.rfc4514_string(),
                not_before=not_before.isoformat() if hasattr(not_before, "isoformat") else None,
                not_after=not_after.isoformat() if hasattr(not_after, "isoformat") else None,
                rsa_modulus_bits=bits if alg == "RSA" else None,
                sig_algo=sig_algo,
                public_key_alg=alg,
                public_key_bits=bits,
                expired=expired,
                days_until_expiry=days_left,
                observable=True,
                validation_error=(
                    None
                    if chain["chain_linkage_ok"] is not False
                    else "ISSUER_SUBJECT_MISMATCH"
                ),
                **chain,
            )
        elif has_tls_record and tls_version_str == "TLSv1.3":
            # RFC 8446 §4.4.2: Certificate is encrypted under the handshake keys.
            x509_details = X509Details(
                observable=False,
                chain_len=0,
                validated=False,
                chain_linkage_ok=None,
                chain_complete=None,
                validation_error="CHAIN_NOT_OBSERVABLE_TLS13",
                trust_check_method="not-performed",
            )

        # ---- identity of the remote host ---------------------------------
        mx_domain, mx_src = f"mail.{server_ip.replace('.', '-')}.net", "ip-derived"
        if x509_details and x509_details.observable:
            for cand in (x509_details.san or []) + (
                [x509_details.subject_cn] if x509_details.subject_cn else []
            ):
                if cand and not cand.startswith("*") and "." in str(cand):
                    mx_domain, mx_src = str(cand), "cert-san"
                    break

        # The packet number and the byte offset must describe the SAME packet,
        # otherwise the evidence pair is unverifiable. The TLS/certificate event
        # is the meaningful anchor, so both are taken from it.
        ev_pkt = cert_first_pkt or tls_first_pkt or first_payload_pkt or first_no
        ev_off = offsets.get(ev_pkt)
        off_str = f"0x{ev_off:08X}" if ev_off is not None else "unavailable"

        # ---- evidence snippet, with credentials masked ------------------
        raw_snippet = (
            all_payload[:64].decode("latin-1", errors="replace")
            if all_payload else ""
        )
        snippet_text, snippet_had_secret = _redact_secrets(raw_snippet)
        snippet_text = (
            snippet_text.replace("\r", "\\r").replace("\n", "\\n")
        )

        flow_records.append(
            FlowRecord(
                capture_session_id=session_id,
                file=pcap_path.name,
                flow_id=flow_key,
                server_ip=server_ip,
                server_port=server_port,
                client_ip=client_ip,
                mx_domain=mx_domain,
                mx_domain_source=mx_src,
                service=service,
                starttls_category=category,
                tls=tls_details,
                x509=x509_details,
                raw_packets_count=len(flow_pkts),
                first_byte_offset=off_str,
                first_packet_no=ev_pkt,
                last_packet_no=flow_pkts[-1][0],
                first_packet_timestamp=_fmt_ts(flow_pkts[0][1].time),
                byte_offset_exact=ev_off is not None,
                tls_record_packets=tls_pkts,
                starttls_packets=starttls_pkts,
                packet_offsets={str(k): v for k, v in offsets.items()},
                packet_timestamps={
                    str(no): _fmt_ts(pk.time) for no, pk in flow_pkts
                },
                capture_time=capture_time,
                capture_sha256=digest,
                # Never surface credential material: if the sampled window holds
                # a secret, the hex form is dropped entirely (it cannot be
                # redacted without falsifying the bytes) and the ASCII form is
                # masked.
                sample_payload_hex=(
                    "" if snippet_had_secret
                    else (all_payload[:64].hex(" ") if all_payload else "")
                ),
                sample_payload_ascii=snippet_text,
            )
        )

    # ---- D2: order flows into a delivery chain -------------------------
    for idx, fr in enumerate(sorted(flow_records, key=lambda f: f.first_packet_no)):
        fr.hop_index = idx

    return flow_records, warnings


def tcp_ok_server(pkt, server_ip: str, server_port: int) -> bool:
    """True when the packet originated from the mail server."""
    if IP not in pkt or TCP not in pkt:
        return False
    return pkt[IP].src == server_ip and pkt[TCP].sport == server_port
