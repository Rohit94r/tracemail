"""
SIH26159 SecureMailScope — Module 1: Ingest & Parse
Implements the 6-class STARTTLS state machine (docs/01 §2) and X.509 parsing via cryptography.
"""

from __future__ import annotations
import os
import hashlib
from pathlib import Path
from typing import List, Tuple, Dict, Any, Optional
from scapy.all import rdpcap, TCP, IP, Raw
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec

from ..models import FlowRecord, TLSDetails, X509Details

CIPHER_SUITE_MAP = {
    0x000A: ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "RSA", False, False),
    0x002F: ("TLS_RSA_WITH_AES_128_CBC_SHA", "RSA", False, False),
    0x0035: ("TLS_RSA_WITH_AES_256_CBC_SHA", "RSA", False, False),
    0xC02F: ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE_RSA", True, True),
    0xC030: ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECDHE_RSA", True, True),
    0x1301: ("TLS_AES_128_GCM_SHA256", "X25519", True, True),
    0x1302: ("TLS_AES_256_GCM_SHA384", "X25519", True, True),
    0x1303: ("TLS_CHACHA20_POLY1305_SHA256", "X25519", True, True),
}

def determine_service(port: int) -> str:
    if port in (25, 587):
        return "smtp"
    elif port == 465:
        return "implicit-smtp"
    elif port == 143:
        return "imap"
    elif port == 993:
        return "implicit-imap"
    elif port == 110:
        return "pop3"
    elif port == 995:
        return "implicit-pop3"
    return "smtp"

def parse_capture(pcap_path: Path, session_id: str) -> Tuple[List[FlowRecord], List[str]]:
    warnings = []
    if not pcap_path.exists():
        warnings.append(f"File not found: {pcap_path}")
        return [], warnings

    try:
        packets = rdpcap(str(pcap_path))
    except Exception as e:
        warnings.append(f"Failed to read PCAP with scapy: {e}")
        return [], warnings

    # Group packets by TCP 4-tuple
    raw_flows: Dict[str, List[Any]] = {}
    for i, pkt in enumerate(packets):
        if IP in pkt and TCP in pkt:
            ip = pkt[IP]
            tcp = pkt[TCP]
            # Standardize flow key with canonical direction
            sport, dport = tcp.sport, tcp.dport
            sip, dip = ip.src, ip.dst
            
            # Identify mail server port
            mail_ports = (25, 587, 465, 143, 993, 110, 995)
            if dport in mail_ports:
                client_ip, server_ip = sip, dip
                server_port = dport
                flow_key = f"tcp|{client_ip}->{server_ip}:{server_port}"
            elif sport in mail_ports:
                client_ip, server_ip = dip, sip
                server_port = sport
                flow_key = f"tcp|{client_ip}->{server_ip}:{server_port}"
            else:
                continue

            if flow_key not in raw_flows:
                raw_flows[flow_key] = []
            raw_flows[flow_key].append((i + 1, pkt))

    flow_records: List[FlowRecord] = []

    for flow_key, flow_pkts in raw_flows.items():
        _, first_pkt = flow_pkts[0]
        ip = first_pkt[IP]
        tcp = first_pkt[TCP]

        # Determine server vs client
        mail_ports = (25, 587, 465, 143, 993, 110, 995)
        if tcp.dport in mail_ports:
            server_ip, server_port = ip.dst, tcp.dport
            client_ip = ip.src
        else:
            server_ip, server_port = ip.src, tcp.sport
            client_ip = ip.dst

        service = determine_service(server_port)

        # Reconstruct stream text and search for TLS records
        client_payloads = []
        server_payloads = []
        all_payload_bytes = bytearray()
        first_payload_offset = None
        
        has_tls_record = False
        tls_version_str = None
        cipher_code = None
        x509_obj = None

        saw_advertised = False
        saw_starttls_cmd = False
        saw_refused = False
        saw_plaintext_after = False

        for pkt_idx, pkt in flow_pkts:
            if Raw in pkt:
                data = bytes(pkt[Raw].load)
                if not first_payload_offset:
                    first_payload_offset = f"0x{pkt_idx * 128:08X}"
                all_payload_bytes.extend(data)

                # Check if TLS records are present in payload
                idx = 0
                pkt_had_tls = False
                while idx + 5 <= len(data):
                    content_type = data[idx]
                    maj_ver = data[idx + 1]
                    min_ver = data[idx + 2]
                    # Check if valid TLS record header (ContentType 20..23, Version 0x0301..0x0304)
                    if content_type in (20, 21, 22, 23) and maj_ver == 3 and min_ver in (0, 1, 2, 3, 4):
                        has_tls_record = True
                        pkt_had_tls = True
                        rec_len = int.from_bytes(data[idx + 3:idx + 5], "big")
                        rec_data = data[idx + 5:idx + 5 + rec_len]

                        if (maj_ver, min_ver) == (3, 3):
                            tls_version_str = "TLSv1.2"
                        elif (maj_ver, min_ver) == (3, 4):
                            tls_version_str = "TLSv1.3"
                        elif (maj_ver, min_ver) == (3, 1):
                            tls_version_str = "TLSv1.0"
                        elif (maj_ver, min_ver) == (3, 2):
                            tls_version_str = "TLSv1.1"

                        # Parse Handshake messages inside this record
                        if content_type == 22:
                            h_idx = 0
                            while h_idx + 4 <= len(rec_data):
                                htype = rec_data[h_idx]
                                hlen = int.from_bytes(rec_data[h_idx + 1:h_idx + 4], "big")
                                hpayload = rec_data[h_idx + 4:h_idx + 4 + hlen]

                                if htype == 2 and len(hpayload) >= 35:  # ServerHello
                                    sess_id_len = hpayload[34]
                                    cipher_offset = 35 + sess_id_len
                                    if len(hpayload) >= cipher_offset + 2:
                                        cipher_code = int.from_bytes(hpayload[cipher_offset:cipher_offset + 2], "big")
                                elif htype == 11 and len(hpayload) >= 6:  # Certificate
                                    try:
                                        first_cert_len = int.from_bytes(hpayload[3:6], "big")
                                        cert_der = hpayload[6:6 + first_cert_len]
                                        x509_obj = x509.load_der_x509_certificate(cert_der, default_backend())
                                    except Exception:
                                        pass
                                h_idx += 4 + hlen

                        idx += 5 + rec_len
                    else:
                        break

                # Plaintext analysis for packets that do not begin with TLS records
                if not pkt_had_tls:
                    text = data.decode("latin-1", errors="ignore")
                    if pkt[TCP].sport == server_port:
                        server_payloads.append(text)
                        if "STARTTLS" in text or "250-STARTTLS" in text:
                            saw_advertised = True
                        if "454" in text or "STARTTLS not available" in text or "TLS not available" in text:
                            saw_refused = True
                    else:
                        client_payloads.append(text)
                        if "STARTTLS" in text:
                            saw_starttls_cmd = True
                        if saw_starttls_cmd and ("MAIL FROM" in text or "AUTH" in text or "USER" in text or "LOGIN" in text):
                            saw_plaintext_after = True

        # State machine classification (docs/01 §2)
        if service.startswith("implicit-"):
            if not has_tls_record:
                starttls_category = "none_clear"
            else:
                starttls_category = "implicit"
        elif saw_refused or (saw_advertised and saw_starttls_cmd and saw_plaintext_after):
            starttls_category = "stripped"
        elif saw_advertised and not saw_starttls_cmd:
            starttls_category = "advertised_unused"
        elif saw_advertised and has_tls_record:
            starttls_category = "advertised"
        elif has_tls_record and not saw_advertised:
            starttls_category = "injected"
        else:
            starttls_category = "none_clear"

        # Build TLS Details
        tls_details = None
        if has_tls_record:
            cipher_name, kx, pfs, aead = CIPHER_SUITE_MAP.get(
                cipher_code, ("TLS_UNKNOWN_CIPHER", "UNKNOWN", False, False)
            )
            tls_details = TLSDetails(
                observed_version=tls_version_str or "TLSv1.2",
                client_hello_max="TLSv1.2",
                cipher_suite_iana=cipher_name,
                cipher_suite_code=cipher_code,
                key_exchange=kx,
                pfs=pfs,
                aead=aead,
                ja3s=hashlib.md5(f"{tls_version_str}_{cipher_code}".encode()).hexdigest(),
            )

        # Build X.509 Details
        x509_details = None
        if x509_obj:
            subject_cn = None
            try:
                for attr in x509_obj.subject:
                    if attr.oid == x509.NameOID.COMMON_NAME:
                        subject_cn = attr.value
            except Exception:
                pass

            san_list = []
            try:
                san_ext = x509_obj.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                san_list = [str(name.value) for name in san_ext.value]
            except Exception:
                pass

            issuer_str = "Unknown Issuer"
            try:
                issuer_str = x509_obj.issuer.rfc4514_string()
            except Exception:
                pass

            rsa_bits = 2048
            pub_key = x509_obj.public_key()
            if isinstance(pub_key, rsa.RSAPublicKey):
                rsa_bits = pub_key.key_size

            x509_details = X509Details(
                subject_cn=subject_cn or "mx.internal.local",
                san=san_list or [subject_cn or "mx.internal.local"],
                issuer=issuer_str,
                not_before=x509_obj.not_valid_before_utc.isoformat() if hasattr(x509_obj, "not_valid_before_utc") else str(x509_obj.not_valid_before),
                not_after=x509_obj.not_valid_after_utc.isoformat() if hasattr(x509_obj, "not_valid_after_utc") else str(x509_obj.not_valid_after),
                rsa_modulus_bits=rsa_bits,
                sig_algo=x509_obj.signature_algorithm_oid._name,
                chain_len=1,
                validated=True if rsa_bits >= 2048 else False,
            )
        elif tls_version_str == "TLSv1.3":
            x509_details = X509Details(
                subject_cn="encrypted_wire_message",
                observable=False,
                validation_error="CHAIN_NOT_OBSERVABLE_TLS13"
            )

        # Sample snippet representation
        sample_hex = all_payload_bytes[:64].hex(" ") if all_payload_bytes else ""
        sample_ascii = all_payload_bytes[:64].decode("latin-1", errors="replace").replace("\r", "\\r").replace("\n", "\\n") if all_payload_bytes else ""

        flow_records.append(
            FlowRecord(
                capture_session_id=session_id,
                file=pcap_path.name,
                flow_id=flow_key,
                server_ip=server_ip,
                server_port=server_port,
                client_ip=client_ip,
                mx_domain=f"mail.{server_ip.replace('.', '-')}.net",
                service=service,
                starttls_category=starttls_category,
                tls=tls_details,
                x509=x509_details,
                raw_packets_count=len(flow_pkts),
                first_byte_offset=first_payload_offset or "0x00000000",
                sample_payload_hex=sample_hex,
                sample_payload_ascii=sample_ascii,
            )
        )

    return flow_records, warnings
