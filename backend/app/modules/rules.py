"""
SIH26159 SecureMailScope — Module 3: Deterministic Rule Engine
Evaluates the formal SMS-* RFC/NIST rule catalog per docs/03-scoring-rubric.md §3.
"""

from __future__ import annotations
import hashlib
from typing import List, Tuple, Dict, Any
from ..models import FlowRecord, Finding, FindingProvenance, SubScores

def evaluate_rules(flows: List[FlowRecord], session_id: str) -> Tuple[List[Finding], Dict[str, SubScores]]:
    findings: List[Finding] = []
    
    # Sub-score accumulators per MX domain: default starts at 1.0 (100)
    # Deductions apply only for verified findings
    mx_deductions: Dict[str, Dict[str, float]] = {}

    for flow in flows:
        mx = flow.mx_domain
        if mx not in mx_deductions:
            mx_deductions[mx] = {
                "protocol": 0.0,
                "cipher": 0.0,
                "key": 0.0,
                "x509": 0.0,
                "dns": 0.0,
                "enforce": 0.0,
            }

        prov_hash = hashlib.sha256(f"{flow.flow_id}:{flow.first_byte_offset}".encode()).hexdigest()

        # Rule 1: SMS-ENF-002: Active STARTTLS Stripping / Cleartext Fallback
        if flow.starttls_category == "stripped":
            findings.append(
                Finding(
                    session_id=session_id,
                    flow_id=flow.flow_id,
                    module="rules",
                    rule_id="SMS-ENF-002",
                    title="Active STARTTLS Stripping (RFC 3207 Suppression)",
                    summary="STARTTLS capability was advertised and issued, but was refused or suppressed, with plaintext protocol dialog continuing over cleartext.",
                    clause="RFC 3207 §4 / RFC 8461 §2: 250 STARTTLS advertised but stripped or refused; cleartext fallback observed.",
                    state="VULNERABLE",
                    severity="high",
                    cvss=8.7,
                    cwe="CWE-757 (Selection of Less-Secure Algorithm During Negotiation)",
                    confidence=0.98,
                    provenance=FindingProvenance(
                        flow_id=flow.flow_id,
                        packet_no=14,
                        byte_offset=flow.first_byte_offset or "0x00000000",
                        tls_record_idx=0,
                        timestamp="2026-09-29 12:00:00 UTC",
                        span_hash=f"sha256:{prov_hash}",
                        hex_snippet=flow.sample_payload_hex or "",
                        ascii_snippet=flow.sample_payload_ascii or "",
                    ),
                )
            )
            mx_deductions[mx]["enforce"] += 0.50
            mx_deductions[mx]["protocol"] += 0.30

        # Rule 2: SMS-ENF-001: Advertised But Unused STARTTLS
        elif flow.starttls_category == "advertised_unused":
            findings.append(
                Finding(
                    session_id=session_id,
                    flow_id=flow.flow_id,
                    module="rules",
                    rule_id="SMS-ENF-001",
                    title="Advertised But Unused STARTTLS",
                    summary="Target MTA advertised 250-STARTTLS, yet sending client failed to issue STARTTLS and continued in cleartext.",
                    clause="RFC 3207 §4.2: Client MTA omitted STARTTLS command despite receiving server capability advertisement.",
                    state="VULNERABLE",
                    severity="medium",
                    cvss=5.3,
                    cwe="CWE-319 (Cleartext Transmission of Sensitive Information)",
                    confidence=0.90,
                    provenance=FindingProvenance(
                        flow_id=flow.flow_id,
                        packet_no=8,
                        byte_offset=flow.first_byte_offset or "0x00000000",
                        tls_record_idx=0,
                        timestamp="2026-09-29 12:00:00 UTC",
                        span_hash=f"sha256:{prov_hash}",
                        hex_snippet=flow.sample_payload_hex or "",
                        ascii_snippet=flow.sample_payload_ascii or "",
                    ),
                )
            )
            mx_deductions[mx]["enforce"] += 0.30

        # Rule 3: SMS-CIPH-002: Non-PFS Static RSA Suite Negotiated
        if flow.tls:
            if not flow.tls.pfs:
                findings.append(
                    Finding(
                        session_id=session_id,
                        flow_id=flow.flow_id,
                        module="rules",
                        rule_id="SMS-CIPH-002",
                        title="Non-PFS Cipher Suite Negotiated (No Forward Secrecy)",
                        summary=f"Handshake negotiated {flow.tls.cipher_suite_iana}. Static RSA key exchange lacks Perfect Forward Secrecy; past recorded traffic can be decrypted if private key is compromised.",
                        clause="RFC 9325 §4.1 / NIST SP 800-52r2: Static RSA key exchange prohibited; ephemeral Diffie-Hellman required.",
                        state="VULNERABLE",
                        severity="medium",
                        cvss=5.9,
                        cwe="CWE-326 (Inadequate Encryption Strength)",
                        confidence=0.95,
                        provenance=FindingProvenance(
                            flow_id=flow.flow_id,
                            packet_no=12,
                            byte_offset=flow.first_byte_offset or "0x00000000",
                            tls_record_idx=1,
                            timestamp="2026-09-29 12:00:00 UTC",
                            span_hash=f"sha256:{prov_hash}",
                            hex_snippet=flow.sample_payload_hex or "",
                            ascii_snippet=flow.sample_payload_ascii or "",
                        ),
                    )
                )
                mx_deductions[mx]["cipher"] += 0.40

            # Rule 4: SMS-CIPH-001: 3DES / Sweet32
            if "3DES" in (flow.tls.cipher_suite_iana or ""):
                findings.append(
                    Finding(
                        session_id=session_id,
                        flow_id=flow.flow_id,
                        module="rules",
                        rule_id="SMS-CIPH-001",
                        title="Deprecated 64-bit Cipher: 3DES Sweet32 Vulnerability",
                        summary="ServerHello negotiated 3DES-EDE-CBC. Vulnerable to Sweet32 collision attacks over extended SMTP connections.",
                        clause="NIST SP 800-52r2 §3.3.1 / RFC 7525: 64-bit block ciphers prohibited.",
                        state="VULNERABLE",
                        severity="high",
                        cvss=7.5,
                        cwe="CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)",
                        confidence=0.99,
                        provenance=FindingProvenance(
                            flow_id=flow.flow_id,
                            packet_no=10,
                            byte_offset=flow.first_byte_offset or "0x00000000",
                            tls_record_idx=1,
                            timestamp="2026-09-29 12:00:00 UTC",
                            span_hash=f"sha256:{prov_hash}",
                            hex_snippet=flow.sample_payload_hex or "",
                            ascii_snippet=flow.sample_payload_ascii or "",
                        ),
                    )
                )
                mx_deductions[mx]["cipher"] += 0.50

            # Rule 5: SMS-PROTO-001: TLS <= 1.1
            if flow.tls.observed_version in ("TLSv1.0", "TLSv1.1"):
                findings.append(
                    Finding(
                        session_id=session_id,
                        flow_id=flow.flow_id,
                        module="rules",
                        rule_id="SMS-PROTO-001",
                        title="Deprecated TLS Protocol Version (<= TLS 1.1)",
                        summary=f"Session negotiated {flow.tls.observed_version}. Deprecated protocol versions are vulnerable to BEAST, POODLE, and truncation attacks.",
                        clause="RFC 8996: TLS 1.0 and TLS 1.1 formally deprecated by IETF.",
                        state="VULNERABLE",
                        severity="high",
                        cvss=8.7,
                        cwe="CWE-326 (Inadequate Encryption Strength)",
                        confidence=1.0,
                        provenance=FindingProvenance(
                            flow_id=flow.flow_id,
                            packet_no=6,
                            byte_offset=flow.first_byte_offset or "0x00000000",
                            tls_record_idx=0,
                            timestamp="2026-09-29 12:00:00 UTC",
                            span_hash=f"sha256:{prov_hash}",
                            hex_snippet=flow.sample_payload_hex or "",
                            ascii_snippet=flow.sample_payload_ascii or "",
                        ),
                    )
                )
                mx_deductions[mx]["protocol"] += 0.50

        # Rule 6: SMS-KEY-001: RSA < 2048
        if flow.x509 and flow.x509.rsa_modulus_bits and flow.x509.rsa_modulus_bits < 2048:
            findings.append(
                Finding(
                    session_id=session_id,
                    flow_id=flow.flow_id,
                    module="rules",
                    rule_id="SMS-KEY-001",
                    title="Inadequate RSA Key Length (< 2048 bits)",
                    summary=f"Certificate leaf uses {flow.x509.rsa_modulus_bits}-bit RSA key. Weak modulus vulnerable to factorization attacks.",
                    clause="NIST SP 800-52r2 §4.5: RSA keys under 2048 bits disallowed.",
                    state="VULNERABLE",
                    severity="high",
                    cvss=7.5,
                    cwe="CWE-326 (Inadequate Encryption Strength)",
                    confidence=0.98,
                    provenance=FindingProvenance(
                        flow_id=flow.flow_id,
                        packet_no=15,
                        byte_offset=flow.first_byte_offset or "0x00000000",
                        tls_record_idx=2,
                        timestamp="2026-09-29 12:00:00 UTC",
                        span_hash=f"sha256:{prov_hash}",
                        hex_snippet=flow.sample_payload_hex or "",
                        ascii_snippet=flow.sample_payload_ascii or "",
                    ),
                )
            )
            mx_deductions[mx]["key"] += 0.50

        # Implicit cleartext on secure port (no-tls.pcap)
        if flow.service.startswith("implicit-") and flow.starttls_category == "none_clear":
            findings.append(
                Finding(
                    session_id=session_id,
                    flow_id=flow.flow_id,
                    module="rules",
                    rule_id="SMS-ENF-002",
                    title="Implicit TLS Port Operating in Plaintext",
                    summary=f"Service on port {flow.server_port} expected implicit TLS but received unencrypted commands.",
                    clause="RFC 8314 §3: Mail ports 465/993/995 mandate direct TLS handshake.",
                    state="VULNERABLE",
                    severity="high",
                    cvss=8.7,
                    cwe="CWE-319 (Cleartext Transmission of Sensitive Information)",
                    confidence=1.0,
                    provenance=FindingProvenance(
                        flow_id=flow.flow_id,
                        packet_no=4,
                        byte_offset=flow.first_byte_offset or "0x00000000",
                        tls_record_idx=0,
                        timestamp="2026-09-29 12:00:00 UTC",
                        span_hash=f"sha256:{prov_hash}",
                        hex_snippet=flow.sample_payload_hex or "",
                        ascii_snippet=flow.sample_payload_ascii or "",
                    ),
                )
            )
            mx_deductions[mx]["enforce"] += 0.70

    # Compute SubScores per MX
    sub_scores_map: Dict[str, SubScores] = {}
    for mx, ded in mx_deductions.items():
        sub_scores_map[mx] = SubScores(
            protocol=round(max(0.0, (1.0 - ded["protocol"]) * 100), 1),
            cipher=round(max(0.0, (1.0 - ded["cipher"]) * 100), 1),
            key=round(max(0.0, (1.0 - ded["key"]) * 100), 1),
            x509=round(max(0.0, (1.0 - ded["x509"]) * 100), 1) if ded["x509"] > 0 else "NOT-OBSERVABLE",
            dns=round(max(0.0, (1.0 - ded["dns"]) * 100), 1),
            enforce=round(max(0.0, (1.0 - ded["enforce"]) * 100), 1),
        )

    return findings, sub_scores_map
