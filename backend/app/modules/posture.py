"""
SIH26159 SecureMailScope — Module 4: Confidence-Bounded Posture Scoring
Calculates composite 0–100 score, 95% Confidence Intervals, and Grade letters per docs/03-scoring-rubric.md §1–2.
"""

from __future__ import annotations
import math
from typing import Dict, List, Tuple
from ..config import WEIGHTS, X509_TLS13_CONF_FLOOR, CIPHER_PROTO_DEFAULT_CONF, ENFORCE_DNS_DEFAULT_CONF
from ..models import SubScores, PostureScore

def compute_posture(mx: str, sub_scores: Any, findings: List[Any]) -> PostureScore:
    # If sub_scores is a mapping of mx -> SubScores, resolve for this mx
    if isinstance(sub_scores, dict):
        if mx in sub_scores:
            sub_scores = sub_scores[mx]
        elif any(isinstance(v, (SubScores, dict)) for v in sub_scores.values()):
            sub_scores = next(iter(sub_scores.values()))

    # Resolve numeric values for sub-scores
    if isinstance(sub_scores, dict):
        proto_val = float(sub_scores.get("protocol", 100.0))
        ciph_val = float(sub_scores.get("cipher", 100.0))
        key_val = float(sub_scores.get("key", 100.0))
        raw_x509 = sub_scores.get("x509", 85.0)
        x509_val = raw_x509 if isinstance(raw_x509, (int, float)) else 85.0
        dns_val = float(sub_scores.get("dns", 85.0))
        enf_val = float(sub_scores.get("enforce", 80.0))
        is_x509_unobservable = (raw_x509 == "NOT-OBSERVABLE")
        sub_scores_obj = SubScores(
            protocol=proto_val,
            cipher=ciph_val,
            key=key_val,
            x509=raw_x509,
            dns=dns_val,
            enforce=enf_val,
        )
    elif hasattr(sub_scores, "protocol"):
        proto_val = sub_scores.protocol
        ciph_val = sub_scores.cipher
        key_val = sub_scores.key
        raw_x509 = sub_scores.x509
        x509_val = raw_x509 if isinstance(raw_x509, (int, float)) else 85.0
        dns_val = sub_scores.dns
        enf_val = sub_scores.enforce
        is_x509_unobservable = (raw_x509 == "NOT-OBSERVABLE")
        sub_scores_obj = sub_scores
    else:
        proto_val = ciph_val = key_val = 100.0
        dns_val = enf_val = 80.0
        raw_x509 = "NOT-OBSERVABLE"
        x509_val = 85.0
        is_x509_unobservable = True
        sub_scores_obj = SubScores(protocol=100.0, cipher=100.0, key=100.0, x509=raw_x509, dns=80.0, enforce=80.0)

    # Weighted mean (mu)
    mu = (
        WEIGHTS["protocol"] * proto_val +
        WEIGHTS["cipher"] * ciph_val +
        WEIGHTS["key"] * key_val +
        WEIGHTS["x509"] * (x509_val if isinstance(x509_val, (int, float)) else 85.0) +
        WEIGHTS["dns"] * dns_val +
        WEIGHTS["enforce"] * enf_val
    )
    mu = round(min(100.0, max(0.0, mu)), 1)

    # Sub-confidences
    conf_x509 = X509_TLS13_CONF_FLOOR if is_x509_unobservable else 0.90
    conf_proto = CIPHER_PROTO_DEFAULT_CONF
    conf_ciph = CIPHER_PROTO_DEFAULT_CONF
    conf_key = 0.90
    conf_dns = ENFORCE_DNS_DEFAULT_CONF
    conf_enf = 0.95

    # Variance calculation: sigma_i = 7.5 * (1 - sub_conf_i)
    var_sum = (
        (WEIGHTS["protocol"] * 7.5 * (1 - conf_proto)) ** 2 +
        (WEIGHTS["cipher"] * 7.5 * (1 - conf_ciph)) ** 2 +
        (WEIGHTS["key"] * 7.5 * (1 - conf_key)) ** 2 +
        (WEIGHTS["x509"] * 7.5 * (1 - conf_x509)) ** 2 +
        (WEIGHTS["dns"] * 7.5 * (1 - conf_dns)) ** 2 +
        (WEIGHTS["enforce"] * 7.5 * (1 - conf_enf)) ** 2
    )
    sigma = math.sqrt(var_sum) * 4.5  # scaling for human-interpretable CI band

    ci_low = round(max(0.0, mu - 1.96 * sigma), 1)
    ci_high = round(min(100.0, mu + 1.96 * sigma), 1)

    # Grade determination (docs/03 §3)
    if mu >= 90:
        grade = "Grade A"
    elif mu >= 70:
        grade = "Grade B"
    elif mu >= 50:
        grade = "Grade C"
    elif mu >= 30:
        grade = "Grade D"
    else:
        grade = "Grade E"

    confidence_label = "chain not-observable (TLS 1.3)" if is_x509_unobservable else "high confidence"

    # Tri-state summary counts
    vuln_count = len([f for f in findings if getattr(f, "state", "") == "VULNERABLE"])
    secure_count = len([f for f in findings if getattr(f, "state", "") == "SECURE"])
    not_obs_count = 1 if is_x509_unobservable else 0

    return PostureScore(
        mx=mx,
        index=mu,
        ci_low=ci_low,
        ci_high=ci_high,
        grade=grade,
        confidence_label=confidence_label,
        sub_scores=sub_scores_obj,
        tri_state_summary={"SECURE": secure_count, "VULNERABLE": vuln_count, "NOT-OBSERVABLE": not_obs_count},
        rubric={"active_rules": [getattr(f, "rule_id", "") for f in findings]},
    )
