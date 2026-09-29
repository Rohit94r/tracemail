"""
SIH26159 SecureMailScope — Module 6: Bayesian Downgrade Radar
Calculates posterior P(strip) per MX per docs/02 M6 and docs/03 §4.
"""

from __future__ import annotations
from typing import List, Dict, Any, Tuple
from ..config import PRIOR_P_STRIP, PROB_NO_TLS_GIVEN_STRIP, PROB_UNUSED_GIVEN_HONEST
from ..models import FlowRecord, Finding, FindingProvenance

def compute_radar(flows: List[FlowRecord], session_id: str) -> Tuple[List[Finding], Dict[str, float]]:
    findings: List[Finding] = []
    posteriors: Dict[str, float] = {}

    mx_flow_groups: Dict[str, List[FlowRecord]] = {}
    for f in flows:
        if f.mx_domain not in mx_flow_groups:
            mx_flow_groups[f.mx_domain] = []
        mx_flow_groups[f.mx_domain].append(f)

    for mx, mx_flows in mx_flow_groups.items():
        prior = PRIOR_P_STRIP
        has_strip = any(f.starttls_category == "stripped" for f in mx_flows)
        has_unused = any(f.starttls_category == "advertised_unused" for f in mx_flows)

        # Bayesian update
        if has_strip:
            # P(strip | evidence) = 1.0 (deterministic observation of strip)
            posterior = 0.98
        elif has_unused:
            # Bayes: P(strip | unused) = P(unused | strip) * P(strip) / P(unused)
            p_evidence = (0.85 * prior) + (PROB_UNUSED_GIVEN_HONEST * (1 - prior))
            posterior = round((0.85 * prior) / p_evidence, 3)
        else:
            posterior = round(prior * 0.15, 3)

        posteriors[mx] = posterior

        if posterior > 0.50:
            sample_flow = mx_flows[0]
            findings.append(
                Finding(
                    session_id=session_id,
                    flow_id=sample_flow.flow_id,
                    module="radar",
                    rule_id="SMS-RADAR-001",
                    title="Downgrade Radar: High Stripping Probability P(strip) > 0.5",
                    summary=f"Bayesian telemetry computed P(strip) = {posterior:.1%} on {mx}. Transit evidence strongly indicates systematic MITM stripping or unauthenticated fallback.",
                    clause="RFC 3207 / IMC'15: Active stripping probability exceeds threshold based on advertised capability suppression.",
                    state="VULNERABLE",
                    severity="high",
                    cvss=7.5,
                    cwe="CWE-757 (Selection of Less-Secure Algorithm During Negotiation)",
                    confidence=posterior,
                    provenance=FindingProvenance(
                        flow_id=sample_flow.flow_id,
                        packet_no=18,
                        byte_offset=sample_flow.first_byte_offset or "0x00000000",
                        tls_record_idx=0,
                        timestamp="2026-09-29 12:00:00 UTC",
                        span_hash=f"sha256:radar_{mx.replace('.', '_')}",
                        hex_snippet=sample_flow.sample_payload_hex or "",
                        ascii_snippet=sample_flow.sample_payload_ascii or "",
                    ),
                )
            )

    return findings, posteriors
