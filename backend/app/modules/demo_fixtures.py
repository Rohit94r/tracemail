"""
SIH26159 SecureMailScope — Deterministic demonstration fixtures.

A single PCAP cannot contain a multi-day relay history, a published MTA-STS
policy, or a baseline time series. Those surfaces are therefore backed by the
fixed fixtures below so every screen and deliverable is present and populated in
an air-gapped demo.

Rules honoured here:
  * Fully deterministic - identical bytes on every run, so report hashes and
    ``make verify`` stay reproducible.
  * Self-describing   - every record carries ``data_source="demo_fixture"``.
  * Never scored      - the rule engine and posture scorer never read these;
    they only populate screens that have no observed equivalent.
"""

from __future__ import annotations

from typing import Any, Dict, List

from .provenance import DEMO

# ---------------------------------------------------------------------------
# D2: multi-hop delivery topology (what a full mail path looks like)
# ---------------------------------------------------------------------------

DEMO_DELIVERY_HOPS: List[Dict[str, Any]] = [
    {
        "id": "hop0",
        "label": "mx1.corp.net",
        "type": "INTERNAL_MX",
        "grade": "Grade A",
        "score": 88.0,
        "data_source": DEMO,
        "role": "origin",
    },
    {
        "id": "hop1",
        "label": "aspmx.l.google.com",
        "type": "PEER_MX",
        "grade": "Grade A",
        "score": 98.0,
        "data_source": DEMO,
        "role": "transit",
    },
    {
        "id": "hop2",
        "label": "mail.protection.outlook.com",
        "type": "PEER_MX",
        "grade": "Grade A",
        "score": 92.0,
        "data_source": DEMO,
        "role": "transit",
    },
    {
        "id": "hop3",
        "label": "relay-gw.partner.net",
        "type": "PARTNER_RELAY",
        "grade": "Grade E",
        "score": 42.0,
        "data_source": DEMO,
        "role": "transit",
    },
]

DEMO_DELIVERY_EDGES: List[Dict[str, Any]] = [
    {
        "source": "hop0",
        "target": "hop1",
        "volume": 2450,
        "percentage": 48.0,
        "status": "ENCRYPTED_TLS13",
        "is_weakest": False,
        "data_source": DEMO,
    },
    {
        "source": "hop0",
        "target": "hop2",
        "volume": 1220,
        "percentage": 24.0,
        "status": "ENCRYPTED_TLS13",
        "is_weakest": False,
        "data_source": DEMO,
    },
    {
        "source": "hop0",
        "target": "hop3",
        "volume": 890,
        "percentage": 17.4,
        "status": "STRIPPED_CLEARTEXT",
        "is_weakest": True,
        "data_source": DEMO,
    },
]

# ---------------------------------------------------------------------------
# DNS policy records: MTA-STS (RFC 8461), DANE/TLSA (RFC 7672), SPF/DKIM/DMARC
# ---------------------------------------------------------------------------

DEMO_DNS_POLICY: Dict[str, Dict[str, Any]] = {
    "mx1.corp.net": {
        "mx": "mx1.corp.net",
        "mta_sts": {
            "mode": "enforce",
            "mxid": "corp-2026",
            "max_age": 604800,
            "policy_uri": "https://mta-sts.corp.net/.well-known/mta-sts.txt",
            "data_source": DEMO,
        },
        "dane": {
            "present": True,
            "tlsa_count": 3,
            "usage": "3",
            "selector": "1",
            "match_type": "1",
            "end_entity_cer_sha256": "a1b2c3d4e5f6...",
            "data_source": DEMO,
        },
        "spf": {"present": True, "all": "fail", "data_source": DEMO},
        "dkim": {"present": True, "selector": "s1", "data_source": DEMO},
        "dmarc": {"present": True, "policy": "reject", "data_source": DEMO},
        "data_source": DEMO,
    },
    "relay-gw.partner.net": {
        "mx": "relay-gw.partner.net",
        "mta_sts": {
            "mode": "none",
            "mxid": None,
            "max_age": 0,
            "policy_uri": None,
            "data_source": DEMO,
        },
        "dane": {
            "present": False,
            "tlsa_count": 0,
            "usage": None,
            "selector": None,
            "match_type": None,
            "end_entity_cer_sha256": None,
            "data_source": DEMO,
        },
        "spf": {"present": True, "all": "softfail", "data_source": DEMO},
        "dkim": {"present": False, "selector": None, "data_source": DEMO},
        "dmarc": {"present": True, "policy": "none", "data_source": DEMO},
        "data_source": DEMO,
    },
    "mail.lab.example": {
        "mx": "mail.lab.example",
        "mta_sts": {
            "mode": "testing",
            "mxid": "lab-2026",
            "max_age": 86400,
            "policy_uri": "https://mta-sts.lab.example/.well-known/mta-sts.txt",
            "data_source": DEMO,
        },
        "dane": {
            "present": True,
            "tlsa_count": 1,
            "usage": "3",
            "selector": "2",
            "match_type": "1",
            "end_entity_cer_sha256": "deadbeefcafe...",
            "data_source": DEMO,
        },
        "spf": {"present": True, "all": "pass", "data_source": DEMO},
        "dkim": {"present": True, "selector": "lab", "data_source": DEMO},
        "dmarc": {"present": True, "policy": "quarantine", "data_source": DEMO},
        "data_source": DEMO,
    },
}

# ---------------------------------------------------------------------------
# Anomaly baseline: 30 days of prior observations, used only to give the
# statistical detector a comparison population. Fixed values, no training.
# ---------------------------------------------------------------------------

def anomaly_baseline(mx: str, n_days: int = 30) -> Dict[str, Any]:
    """Deterministic pseudo-baseline derived from the MX name."""
    seed = sum(ord(c) for c in mx) or 1
    daily_cleartext = [
        round(((seed * (i + 3)) % 17) / 10.0, 2) for i in range(n_days)
    ]
    return {
        "mx": mx,
        "n_days": n_days,
        "daily_cleartext_ratio": daily_cleartext,
        "mean": round(sum(daily_cleartext) / n_days, 3),
        "stdev": 0.62,
        "data_source": DEMO,
    }


# ---------------------------------------------------------------------------
# Attack Lens (D6): threat classes keyed by the rule IDs that drive them
# ---------------------------------------------------------------------------

DEMO_ATTACK_CLASSES = [
    {
        "attack_class": "Active BGP Hijack & Cleartext STARTTLS Stripping",
        "likelihood": "HIGH",
        "driver_rule_ids": ["SMS-ENF-002", "SMS-ENF-001", "SMS-ENF-004"],
        "preconditions": [
            "Sending MTA negotiates TLS opportunistically",
            "No MTA-STS enforce policy on the receiving domain",
        ],
        "impact": "Full message body and credentials observed in cleartext.",
        "data_source": DEMO,
    },
    {
        "attack_class": "Sweet32 Birthday Attack Session Key Recovery",
        "likelihood": "MEDIUM",
        "driver_rule_ids": ["SMS-CIPH-001", "SMS-CIPH-002"],
        "preconditions": ["64-bit block cipher negotiated", "Long-lived connection"],
        "impact": "Partial plaintext recovery after ~32 GiB of ciphertext.",
        "data_source": DEMO,
    },
    {
        "attack_class": "RackSpace Key Factorisation (RSA)",
        "likelihood": "HIGH",
        "driver_rule_ids": ["SMS-KEY-001"],
        "preconditions": ["RSA modulus below 2048 bits"],
        "impact": "Mailbox content and credentials decryptable.",
        "data_source": DEMO,
    },
    {
        "attack_class": "Certificate Impersonation / MITM Proxying",
        "likelihood": "MEDIUM",
        "driver_rule_ids": ["SMS-X509-001", "SMS-X509-002"],
        "preconditions": [
            "Chain not validated against a trust anchor",
            "Expired or self-issued leaf accepted",
        ],
        "impact": "Attacker terminates TLS with a self-signed certificate.",
        "data_source": DEMO,
    },
    {
        "attack_class": "Downgrade to Deprecated TLS",
        "likelihood": "MEDIUM",
        "driver_rule_ids": ["SMS-PROTO-001", "SMS-PROTO-002"],
        "preconditions": ["TLS 1.0/1.1 still accepted"],
        "impact": "BEAST / POODLE / truncation exposure.",
        "data_source": DEMO,
    },
]

# ---------------------------------------------------------------------------
# Remediation playbooks keyed by rule ID
# ---------------------------------------------------------------------------

PLAYBOOK: Dict[str, Dict[str, str]] = {
    "SMS-ENF-002": {
        "mta": "postfix",
        "directive": "smtpd_tls_security_level = dane",
        "action": "Require mandatory TLS and reject sessions that fall back to cleartext.",
    },
    "SMS-ENF-001": {
        "mta": "postfix",
        "directive": "smtpd_tls_wrappermode = yes",
        "action": "Enforce STARTTLS for every session; disable opportunistic plaintext.",
    },
    "SMS-ENF-005": {
        "mta": "postfix",
        "directive": "smtpd_tls_security_level = may",
        "action": "Publish an implicit-TLS listener on 465/993/995; do not serve these ports in cleartext.",
    },
    "SMS-ENF-004": {
        "mta": "postfix",
        "directive": "smtp_tls_sts_mandatory = yes",
        "action": "Enforce MTA-STS so policy-violating senders are rejected.",
    },
    "SMS-CIPH-001": {
        "mta": "postfix",
        "directive": "smtpd_tls_exclude_ciphers = 3DES, DES, RC4, MD5, aNULL, eNULL",
        "action": "Disable 64-bit block ciphers, NULL ciphers and export suites.",
    },
    "SMS-CIPH-002": {
        "mta": "postfix",
        "directive": "tls_eecdh_auto_curves = X25519:secp384r1",
        "action": "Require ephemeral (DHE/ECDHE) key exchange for forward secrecy.",
    },
    "SMS-CIPH-003": {
        "mta": "postfix",
        "directive": "tls_preempt_cipherlist = on",
        "action": "Prefer AEAD suites and rotate session keys to avoid nonce reuse.",
    },
    "SMS-KEY-001": {
        "mta": "global",
        "directive": "tls_certificate_key_bits = 2048",
        "action": "Reissue the leaf certificate with at least a 2048-bit key.",
    },
    "SMS-KEY-002": {
        "mta": "global",
        "directive": "tls_certificate_signature_algorithms = sha256+sha384",
        "action": "Re-sign the certificate chain with SHA-256 or stronger; retire SHA-1/MD5.",
    },
    "SMS-PROTO-001": {
        "mta": "postfix",
        "directive": "tls_protocols = TLSv1.2 TLSv1.3",
        "action": "Disable TLS 1.0/1.1, deprecated by RFC 8996.",
    },
    "SMS-PROTO-002": {
        "mta": "postfix",
        "directive": "tls_protocols = TLSv1.3",
        "action": "Remove the downgrade path by offering a single modern protocol.",
    },
    "SMS-X509-001": {
        "mta": "global",
        "directive": "smtp_tls_CApath = /etc/ssl/certs",
        "action": "Validate the presented chain against a local trust store and pin the expected issuer.",
    },
    "SMS-X509-002": {
        "mta": "global",
        "directive": "certbot renew --deploy-hook 'systemctl reload postfix'",
        "action": "Renew the expired or self-issued certificate and automate renewal.",
    },
    "SMS-DNS-001": {
        "mta": "dns",
        "directive": "_mta-sts.<domain>. TXT v=STSv1; id=...",
        "action": "Publish an MTA-STS policy with mode=enforce.",
    },
    "SMS-DNS-002": {
        "mta": "dns",
        "directive": "_25._tcp.<mx> IN TLSA 3 1 1 <sha256>",
        "action": "Publish a DANE TLSA record for the MX and enable DANE on the sender.",
    },
    "SMS-RADAR-001": {
        "mta": "postfix",
        "directive": "smtpd_tls_security_level = dane",
        "action": "Investigate systematic stripping; pin the sender to DANE or MTA-STS.",
    },
}
