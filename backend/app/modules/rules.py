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

        def evidence(*anchors: str) -> FindingProvenance:
            """
            Build provenance from the real packet that anchors the evidence.

            `anchors` are ordered event names; the first one actually observed
            in this flow wins. Packet number, byte offset and timestamp all come
            from the same packet, so the triple is internally consistent and can
            be checked against the capture file. When the exact byte offset is
            not known it is reported as unavailable rather than guessed.
            """
            pkt = None
            for name in anchors:
                pkt = (
                    flow.starttls_packets.get(name)
                    or flow.tls_record_packets.get(name)
                )
                if pkt:
                    break
            if not pkt:
                pkt = flow.first_packet_no
            off = flow.packet_offsets.get(str(pkt))
            return FindingProvenance(
                flow_id=flow.flow_id,
                packet_no=pkt,
                byte_offset=(
                    f"0x{off:08X}" if off is not None else "unavailable"
                ),
                tls_record_idx=0,
                timestamp=(
                    flow.packet_timestamps.get(str(pkt))
                    or flow.first_packet_timestamp
                ),
                span_hash=f"sha256:{prov_hash}",
                hex_snippet=flow.sample_payload_hex or "",
                ascii_snippet=flow.sample_payload_ascii or "",
                byte_offset_exact=off is not None,
            )

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
                    provenance=evidence("refused", "cleartext_after", "starttls_cmd", "advertise"),
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
                    provenance=evidence("starttls_cmd", "advertise", "cleartext_after"),
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
                        provenance=evidence("server_hello", "handshake"),
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
                        provenance=evidence("server_hello", "handshake"),
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
                        provenance=evidence("advertise", "refused"),
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
                    provenance=evidence("certificate", "server_hello", "handshake"),
                )
            )
            mx_deductions[mx]["key"] += 0.50

        # Rule 7: SMS-KEY-002: SHA-1 / MD5 certificate signature
        sig = (flow.x509.sig_algo or "").lower() if flow.x509 else ""
        weak_sig = any(t in sig for t in ("sha1", "md5", "md2"))
        if flow.x509 and flow.x509.observable and weak_sig:
            findings.append(
                Finding(
                    session_id=session_id,
                    flow_id=flow.flow_id,
                    module="rules",
                    rule_id="SMS-KEY-002",
                    title=f"Weak Certificate Signature Algorithm ({flow.x509.sig_algo})",
                    summary=(
                        f"The leaf certificate is signed with {flow.x509.sig_algo}. "
                        "SHA-1 and MD5 are collision-vulnerable and rejected by "
                        "current CA/Browser Forum baseline requirements."
                    ),
                    clause="NIST SP 800-131A §3: SHA-1 disallowed for digital signature after 2013.",
                    state="VULNERABLE",
                    severity="medium",
                    cvss=5.9,
                    cwe="CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)",
                    confidence=0.98,
                    provenance=evidence("certificate", "server_hello", "handshake"),
                )
            )
            mx_deductions[mx]["key"] += 0.20

        # Rule 8: SMS-X509-002: expired or self-issued leaf
        if flow.x509 and flow.x509.observable:
            x509_certs = flow.x509.certs or []
            leaf_self_issued = bool(x509_certs and x509_certs[0].self_signed)
            if flow.x509.expired is True or leaf_self_issued:
                why = (
                    "the certificate expired on "
                    f"{flow.x509.not_after}"
                    if flow.x509.expired is True
                    else "the certificate is self-issued (self-signed)"
                )
                findings.append(
                    Finding(
                        session_id=session_id,
                        flow_id=flow.flow_id,
                        module="rules",
                        rule_id="SMS-X509-002",
                        title="Expired or Self-Issued Certificate in Chain",
                        summary=(
                            f"The presented leaf certificate is unusable as a trust "
                            f"anchor because {why}. A client that does not enforce "
                            "chain validation will still complete the handshake."
                        ),
                        clause="RFC 5280 §6: certificate validity must be checked against the trust anchor.",
                        state="VULNERABLE",
                        severity="high",
                        cvss=7.4,
                        cwe="CWE-298 (Improper Validation of Certificate Expiration)",
                        confidence=0.99,
                        provenance=evidence("certificate", "server_hello", "handshake"),
                    )
                )
                mx_deductions[mx]["x509"] += 0.40

            # Rule 9: SMS-X509-001: chain not validated / unobservable.
            # Tri-state: an unobservable chain is NOT-OBSERVABLE, never "clean".
            if flow.x509 is not None and not flow.x509.observable:
                findings.append(
                    Finding(
                        session_id=session_id,
                        flow_id=flow.flow_id,
                        module="rules",
                        rule_id="SMS-X509-001",
                        title="Certificate Chain Not Observable",
                        summary=(
                            "The server used TLS 1.3, where the Certificate message is "
                            "encrypted under the handshake keys (RFC 8446 §4.4.2), so no "
                            "certificate could be read from this capture. Chain integrity "
                            "is NOT-OBSERVABLE and widens the confidence interval."
                        ),
                        clause="RFC 8446 §4.4.2: Certificate is encrypted in TLS 1.3; RFC 5280 §6 chain validation unobservable.",
                        state="NOT-OBSERVABLE",
                        severity="medium",
                        cvss=5.9,
                        cwe="CWE-295 (Improper Certificate Validation)",
                        confidence=0.95,
                        provenance=evidence("server_hello", "handshake"),
                    )
                )
            elif (
                flow.x509 is not None
                and flow.x509.observable
                and flow.x509.trust_check_method == "not-performed"
            ):
                findings.append(
                    Finding(
                        session_id=session_id,
                        flow_id=flow.flow_id,
                        module="rules",
                        rule_id="SMS-X509-001",
                        title="Certificate Chain Not Validated Against a Trust Anchor",
                        summary=(
                            f"{flow.x509.chain_len} certificate(s) were observed"
                            + (
                                f" and chain linkage verified"
                                if flow.x509.chain_linkage_ok
                                else " but issuer/subject linkage did NOT verify"
                            )
                            + ". SecureMailScope performs this check passively and has "
                            "no trust store, so trust was not evaluated and is reported "
                            "as NOT-OBSERVABLE rather than assumed valid."
                        ),
                        clause="RFC 5280 §6: path validation requires a trust anchor; not performed here.",
                        state="NOT-OBSERVABLE",
                        severity="medium",
                        cvss=5.9,
                        cwe="CWE-295 (Improper Certificate Validation)",
                        confidence=0.90,
                        provenance=evidence("certificate", "server_hello", "handshake"),
                    )
                )

        # Rule 10: SMS-CIPH-001: non-AEAD block cipher in use
        if flow.tls and flow.tls.cipher_suite_iana and not flow.tls.aead:
            is_cbc = any(
                tag in flow.tls.cipher_suite_iana
                for tag in ("_CBC", "_CBC_SHA", "_RC4", "_DES", "_3DES", "_RC2")
            )
            if is_cbc:
                findings.append(
                    Finding(
                        session_id=session_id,
                        flow_id=flow.flow_id,
                        module="rules",
                        rule_id="SMS-CIPH-001",
                        title="Non-AEAD Block Cipher Negotiated",
                        summary=(
                            f"The session negotiated {flow.tls.cipher_suite_iana}, a "
                            "CBC/legacy block cipher without authenticated encryption. "
                            "It is exposed to padding-oracle attacks and, for 64-bit "
                            "ciphers, to Sweet32 birthday collisions."
                        ),
                        clause="NIST SP 800-52r2 §4.2: only AEAD modes are permitted for new implementations.",
                        state="VULNERABLE",
                        severity="high",
                        cvss=7.5,
                        cwe="CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)",
                        confidence=0.98,
                        provenance=evidence("server_hello", "handshake"),
                    )
                )
                mx_deductions[mx]["cipher"] += 0.50

        # Implicit cleartext on secure port (no-tls.pcap)
        if flow.service.startswith("implicit-") and flow.starttls_category == "none_clear":
            findings.append(
                Finding(
                    session_id=session_id,
                    flow_id=flow.flow_id,
                    module="rules",
                    rule_id="SMS-ENF-005",
                    title="Implicit TLS Port Operating in Plaintext",
                    summary=(
                        f"Service on port {flow.server_port} is defined to require a "
                        "direct TLS handshake, but the session ran in cleartext"
                        + (
                            " with credentials transmitted unprotected."
                            if flow.starttls_packets.get("cleartext_secret")
                            else "."
                        )
                    ),
                    clause="RFC 8314 §3: Mail ports 465/993/995 mandate direct TLS handshake.",
                    state="VULNERABLE",
                    severity="high",
                    cvss=8.7,
                    cwe="CWE-319 (Cleartext Transmission of Sensitive Information)",
                    confidence=1.0,
                    provenance=evidence(
                        "cleartext_secret", "cleartext_command",
                        "refused", "advertise",
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
