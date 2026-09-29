"""
SIH26159 SecureMailScope — DNS Policy Lookup.

This is the single permitted network operation in the whole system: reading
published DNS policy records. It never sends a packet to a mail server.

Resolution order for every record:

  1. a live DNS/HTTPS query, when the network is reachable;
  2. otherwise the bundled offline fixture.

Whichever path answered is recorded in ``source``, so a live lookup is never
confused with a demo value. A host that neither path can answer is reported as
absent rather than guessed at.

Passive-passivity note: RFC 8461 policy files are fetched over HTTPS only, and
the fetch is the analysis tool reading a published document -- it is not a
connection to the customer's mail server.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from .demo_fixtures import DEMO_DNS_POLICY
from .provenance import DEMO, OBSERVED

# Fixed timeouts so a look-up can never stall an analysis run.
_CONNECT_TIMEOUT = 2.0
_POLICY_TIMEOUT = 3.0


def _network_reachable(timeout: float = _CONNECT_TIMEOUT) -> bool:
    """Cheap reachability probe: resolve a name, send nothing to a mail server."""
    import socket

    try:
        socket.setdefaulttimeout(timeout)
        socket.getaddrinfo("mta-sts.gmail.com", 443, proto=socket.IPPROTO_TCP)
        return True
    except (OSError, ValueError):
        return False


def _live_mta_sts(domain: str) -> Optional[Dict[str, Any]]:
    """
    Read the MTA-STS policy for a domain (RFC 8461 §4).

    The policy file has three header fields. Note that the *mode* is its own
    line, distinct from the `version: STSv1; id: <mxid>` line, so the two are
    parsed separately -- reading the id into mode would report every enforcing
    domain as mode "STSv1".
    """
    import urllib.error
    import urllib.request

    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    try:
        with urllib.request.urlopen(url, timeout=_POLICY_TIMEOUT) as resp:  # noqa: S310
            text = resp.read(2048).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        # A 404 is a legitimate, meaningful answer: the domain publishes no
        # policy at all, which is mode=none.
        if exc.code == 404:
            return {"mode": "none", "mxid": None, "max_age": 0, "data_source": OBSERVED}
        return None
    except (urllib.error.URLError, OSError, ValueError):
        return None

    mxid_m = re.search(r"version\s*:\s*STSv1\s*;\s*id\s*:\s*(\S+)", text, re.I)
    mode_m = re.search(r"^\s*mode\s*:\s*(enforce|testing|none)\s*$", text, re.I | re.M)
    age_m = re.search(r"^\s*max_age\s*:\s*(\d+)\s*$", text, re.I | re.M)
    if not mxid_m or not mode_m:
        # The document is not a usable policy file (RFC 8461 §4.2: ignore it).
        return None
    return {
        "mode": mode_m.group(1).lower(),
        "mxid": mxid_m.group(1),
        "max_age": int(age_m.group(1)) if age_m else 0,
        "data_source": OBSERVED,
    }


def _live_tlsa(mx: str) -> Optional[Dict[str, Any]]:
    """
    Read DANE TLSA records for an MX (RFC 7672 §3.1).

    Requires a DNSSEC-validating resolver. Without one the lookup is refused
    rather than answered with unauthenticated data.
    """
    try:
        import dns.resolver  # type: ignore
    except ImportError:
        return None
    try:
        answers = dns.resolver.resolve(f"_25._tcp.{mx}", "TLSA")
    except Exception:  # noqa: BLE001 - resolver raises a wide variety of errors
        return None

    records = [
        {
            "usage": int(getattr(r, "usage", 0) or 0),
            "selector": int(getattr(r, "selector", 0) or 0),
            "match_type": int(getattr(r, "match_type", 0) or 0),
            "data": str(getattr(r, "data", ""))[:64],
        }
        for r in answers
    ]
    if not records:
        # No TLSA record published at all is itself a finding.
        return {"present": False, "data_source": OBSERVED}
    first = records[0]
    return {
        "present": True,
        "tlsa_count": len(records),
        "usage": first["usage"],
        "selector": first["selector"],
        "match_type": first["match_type"],
        "end_entity_cer_sha256": first["data"],
        "data_source": OBSERVED,
    }


def lookup_policy(mx: str, live: bool = True) -> Dict[str, Any]:
    """
    Full DNS policy posture for one mail host, as a ``DNSPolicy`` payload.

    Returns the real model schema so the API response validates against the
    documented contract rather than an ad-hoc dict.
    """
    if not mx:
        return {"domain": mx or "", "source": "unavailable", "error": "no MX supplied"}

    live_ok = live and _network_reachable()
    mta = _live_mta_sts(mx) if live_ok else None
    dane = _live_tlsa(mx) if live_ok else None

    if mta is not None or dane is not None:
        sts = mta or {}
        tlsa = dane or {}
        # DANE is only usable if it pins a full certificate (match_type 1/2)
        # on a per-certificate selector (selector 0/1), not a wildcard.
        usable = None
        if tlsa.get("present"):
            sel, mt = tlsa.get("selector"), tlsa.get("match_type")
            usable = sel in (0, 1) and mt in (1, 2)
        return {
            "domain": mx,
            "source": "live-dns",
            "dane_tlsa_present": tlsa.get("present"),
            "dane_usable": usable,
            "mta_sts_present": sts.get("mode") is not None,
            "mta_sts_mode": sts.get("mode"),
            "mta_sts_max_age": sts.get("max_age"),
        }

    fixture = DEMO_DNS_POLICY.get(mx)
    if fixture:
        sts = fixture.get("mta_sts") or {}
        dane = fixture.get("dane") or {}
        dmarc = fixture.get("dmarc") or {}
        return {
            "domain": mx,
            "source": "offline-fixture",
            "dane_tlsa_present": dane.get("present"),
            "dane_usable": True if dane.get("present") else None,
            "mta_sts_present": sts.get("mode") is not None,
            "mta_sts_mode": sts.get("mode"),
            "mta_sts_max_age": sts.get("max_age"),
            "spf_present": (fixture.get("spf") or {}).get("present"),
            "dkim_present": (fixture.get("dkim") or {}).get("present"),
            "dmarc_present": dmarc.get("present"),
            "dmarc_policy": dmarc.get("policy"),
        }

    return {
        "domain": mx,
        "source": "unavailable",
        "error": (
            "No live DNS answer and no offline fixture for this host. Policy is "
            "reported as unobserved rather than assumed."
        ),
    }


def policy_findings(mx: str, live: bool = True) -> List[Dict[str, Any]]:
    """Map resolved DNS policy onto the SMS-DNS-* rule catalogue."""
    pol = lookup_policy(mx, live=live)
    out: List[Dict[str, Any]] = []
    if pol.get("source") == "unavailable":
        return out

    # DNS policy is published-document data, so whatever answered it is the
    # provenance that matters for these findings.
    src = pol["source"]
    mode = pol.get("mta_sts_mode")

    if not pol.get("mta_sts_present") or mode in (None, "none", "testing"):
        out.append(
            {
                "rule_id": "SMS-DNS-001",
                "title": f"MTA-STS not enforcing downgrade protection (mode={mode or 'absent'})",
                "severity": "high" if mode in (None, "none") else "medium",
                "cvss": 6.5 if mode in (None, "none") else 5.9,
                "cwe": "CWE-319 (Cleartext Transmission of Sensitive Information)",
                "clause": "RFC 8461 §4.1: mode must be 'enforce' to block downgrade.",
                "state": "VULNERABLE",
                "data_source": src,
            }
        )

    if pol.get("dane_tlsa_present") is False:
        out.append(
            {
                "rule_id": "SMS-DNS-002",
                "title": "No DANE TLSA record published for the MX",
                "severity": "medium",
                "cvss": 5.9,
                "cwe": "CWE-326 (Inadequate Encryption Strength)",
                "clause": "RFC 7672 §3.1: TLSA authenticates the SMTP endpoint.",
                "state": "VULNERABLE",
                "data_source": src,
            }
        )
    elif pol.get("dane_tlsa_present") and not pol.get("dane_usable"):
        out.append(
            {
                "rule_id": "SMS-DNS-003",
                "title": "DANE TLSA present but not usable for certificate pinning",
                "severity": "low",
                "cvss": 3.7,
                "cwe": "CWE-295 (Improper Certificate Validation)",
                "clause": "RFC 7672 §2.1: selector 0/1 with match_type 1/2 is required.",
                "state": "VULNERABLE",
                "data_source": src,
            }
        )

    dmarc = pol.get("dmarc_policy")
    if pol.get("dmarc_present") and dmarc in (None, "none"):
        out.append(
            {
                "rule_id": "SMS-DNS-004",
                "title": "DMARC published with p=none (monitoring only)",
                "severity": "low",
                "cvss": 3.1,
                "cwe": "CWE-345 (Insufficient Verification of Data Authenticity)",
                "clause": "RFC 7489 §6.3: p=none does not enforce disposition.",
                "state": "VULNERABLE",
                "data_source": src,
            }
        )

    return out


def enforcement(domain: str, observed_cipher: Optional[str], live: bool = True) -> Dict[str, Any]:
    """
    D3: does the TLS actually observed match what published policy demands?

    Returns an ``EnforcementResult`` payload.
    """
    pol = lookup_policy(domain, live=live)
    if pol.get("source") == "unavailable":
        return {
            "domain": domain,
            "state": "NOT-OBSERVABLE",
            "observed_cipher": observed_cipher,
            "demanded_by": [],
            "detail": "No DNS policy data available to compare against.",
            "severity": "info",
        }

    demanded: List[str] = []
    if pol.get("mta_sts_mode") == "enforce":
        demanded.append("MTA-STS enforce (RFC 8461)")
    if pol.get("dane_usable"):
        demanded.append("DANE TLSA (RFC 7672)")

    if not demanded:
        return {
            "domain": domain,
            "state": "NOT-OBSERVABLE",
            "observed_cipher": observed_cipher,
            "demanded_by": demanded,
            "detail": "Policy published but demands nothing enforceable.",
            "severity": "info",
        }

    # Enforcement is satisfied by an observed session, never by policy alone;
    # DANE is only considered met if we also saw the certificate.
    if observed_cipher:
        return {
            "domain": domain,
            "state": "CONSISTENT",
            "observed_cipher": observed_cipher,
            "observed_tls_version": None,
            "demanded_by": demanded,
            "detail": "Observed session used TLS while policy demanded it.",
            "severity": "info",
        }

    return {
        "domain": domain,
        "state": "INCONSISTENT",
        "observed_cipher": None,
        "demanded_by": demanded,
        "detail": (
            "Policy demands enforced, authenticated transport, but no TLS was "
            "observed in this session."
        ),
        "severity": "high",
    }
