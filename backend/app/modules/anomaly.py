"""
SIH26159 SecureMailScope — Deterministic Anomaly Detection (D3).

Statistical, threshold-based and fully reproducible. There is no trained model
and nothing is fitted at inference time: each signal is a documented comparison
of this session's observed values against a fixed reference population, and the
combined result is a fixed weighted sum. The same capture always yields the
same report, which is what reproducibility requires.

The reference population is a demo fixture, so it is a *comparison* baseline,
not a measurement of the customer's own history. Every signal therefore carries
the reference value it was compared against, and ``scope`` records what the
reference actually is. Signals are heuristic: they rank and flag, they never
change a rule-engine score.
"""

from __future__ import annotations

import statistics
from typing import Any, Dict, List

from ..models import AnomalyReport, AnomalySignal
from .demo_fixtures import anomaly_baseline
from .provenance import DEMO, DERIVED, OBSERVED

# Fixed weights and thresholds. Deterministic by construction.
_WEIGHTS = {
    "cleartext_ratio": 0.40,
    "cipher_downgrade": 0.25,
    "certificate_anomaly": 0.20,
    "interhop_jitter": 0.15,
}

_TH_MODIFIED_Z = 3.0   # robust z-score beyond this is an outlier
_TH_CLEAR_PCT = 25.0   # % of flows with no transport protection
_TH_JITTER_PCT = 40.0  # inter-arrival spread across hops
_TH_KEY_BITS = 1024    # key below this is anomalous regardless of baseline
_LEGACY_VERSIONS = {"TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"}


def _robust_z(value: float, sample: List[float]) -> float:
    """
    Robust z-score via median and MAD (Iglewicz & Hoaglin).

    Preferred over a plain z-score because a baseline that is itself skewed
    would otherwise push ordinary values past a mean/stdev threshold.
    """
    if len(sample) < 3:
        return 0.0
    med = statistics.median(sample)
    mad = statistics.median([abs(v - med) for v in sample])
    # 0.6745 scales MAD to a normal-consistent stdev estimate; 1.4826 inverts it.
    scale = mad * 1.4826
    if scale <= 0:
        return 0.0
    return round((value - med) / scale, 3)


def _epoch(ts: Any) -> float | None:
    import datetime as _dt

    if isinstance(ts, (int, float)):
        return float(ts)
    if isinstance(ts, _dt.datetime):
        return ts.timestamp()
    try:
        return _dt.datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp()
    except (ValueError, AttributeError):
        return None


def detect_anomalies(flows: List[Any], session_id: str) -> AnomalyReport:
    """
    Run the deterministic detector over the flows of one session.

    Observed side is always the capture under analysis; the reference side is
    the fixed demo baseline for the MX.
    """
    if not flows:
        return AnomalyReport(
            scope="no flows observed for this session",
            baseline_flows=0,
            anomalous_flows=0,
            signals=[],
            flagged_flow_ids=[],
            method_note=(
                "No flows to analyse; an empty report is returned rather than a "
                "placeholder score."
            ),
        )

    signals: List[AnomalySignal] = []
    total = len(flows)
    flow_ids = [getattr(f, "flow_id", None) or f"flow-{i}" for i, f in enumerate(flows)]
    flagged: List[str] = []
    mx = getattr(flows[0], "mx_domain", "") or "unknown"
    base = anomaly_baseline(mx)
    ref_pct = [round(v * 100.0, 2) for v in base["daily_cleartext_ratio"]]

    # ---- 1. cleartext ratio vs the reference population -------------------
    clear_idx = [
        i
        for i, f in enumerate(flows)
        if getattr(f, "starttls_category", None) in ("stripped", "none_clear")
        or getattr(f, "tls", None) is None
    ]
    clear_pct = round(100.0 * len(clear_idx) / total, 1)
    z = _robust_z(clear_pct, ref_pct)
    if clear_pct >= _TH_CLEAR_PCT or abs(z) >= _TH_MODIFIED_Z:
        direction = "high" if clear_pct >= _TH_CLEAR_PCT else "low"
        signals.append(
            AnomalySignal(
                feature="cleartext_ratio",
                value=clear_pct,
                expected_range=(
                    f"reference median {round(statistics.median(ref_pct), 1)}% "
                    f"(range {round(min(ref_pct), 1)}-{round(max(ref_pct), 1)}%)"
                ),
                z_score=z,
                direction=direction,
                method="robust_zscore_median_mad",
                explanation=(
                    f"{len(clear_idx)} of {total} flows carried no transport "
                    f"protection ({clear_pct}%), against a "
                    f"{DEMO} reference distribution of {base['n_days']} days for "
                    f"this MX. Fires the fixed {_TH_CLEAR_PCT}% floor or a "
                    f"modified z of {_TH_MODIFIED_Z}."
                ),
            )
        )
        flagged += [flow_ids[i] for i in clear_idx]

    # ---- 2. protocol / cipher downgrade -----------------------------------
    legacy_idx = [
        i for i, f in enumerate(flows)
        if (t := getattr(f, "tls", None)) and t.observed_version in _LEGACY_VERSIONS
    ]
    non_pfs_idx = [
        i for i, f in enumerate(flows)
        if (t := getattr(f, "tls", None)) and not t.pfs
    ]
    if legacy_idx or non_pfs_idx:
        if legacy_idx:
            observed = flows[legacy_idx[0]].tls.observed_version
            method = "threshold_deprecated_protocol"
            expl = (
                f"{len(legacy_idx)} flow(s) negotiated a deprecated protocol "
                f"version ({observed}); RFC 8996 deprecates it."
            )
        else:
            observed = flows[non_pfs_idx[0]].tls.cipher_suite_iana
            method = "threshold_missing_forward_secrecy"
            expl = (
                f"{len(non_pfs_idx)} flow(s) negotiated a suite without forward "
                "secrecy, so a later key compromise exposes past sessions."
            )
        signals.append(
            AnomalySignal(
                feature="cipher_downgrade",
                value=float(len(set(legacy_idx or non_pfs_idx))),
                expected_range="TLSv1.3 with AEAD and ephemeral key exchange",
                z_score=0.0,
                direction="high",
                method=method,
                explanation=expl,
            )
        )
        flagged += [flow_ids[i] for i in set(legacy_idx + non_pfs_idx)]

    # ---- 3. certificate anomaly -------------------------------------------
    weak_idx = [
        i for i, f in enumerate(flows)
        if (x := getattr(f, "x509", None))
        and getattr(x, "observable", False)
        and (bits := getattr(x, "public_key_bits", 0) or 0)
        and bits < _TH_KEY_BITS
    ]
    self_issued_idx = [
        i for i, f in enumerate(flows)
        if (x := getattr(f, "x509", None))
        and getattr(x, "observable", False)
        and (certs := getattr(x, "certs", None))
        and certs
        and certs[0].self_signed
    ]
    if weak_idx or self_issued_idx:
        bits = getattr(flows[weak_idx[0]].x509, "public_key_bits", None) if weak_idx else None
        value = float(bits) if bits else float(len(self_issued_idx))
        signals.append(
            AnomalySignal(
                feature="certificate_anomaly",
                value=value,
                expected_range=f"RSA >= 2048-bit, issuer-issued leaf",
                z_score=0.0,
                direction="high",
                method="threshold_absolute_keysize",
                explanation=(
                    f"{len(weak_idx)} flow(s) presented a sub-{_TH_KEY_BITS}-bit "
                    f"key and {len(self_issued_idx)} presented a self-issued leaf."
                ),
            )
        )
        flagged += [flow_ids[i] for i in set(weak_idx + self_issued_idx)]

    # ---- 4. inter-hop arrival jitter --------------------------------------
    epochs = [(i, e) for i, f in enumerate(flows) if (e := _epoch(getattr(f, "first_packet_timestamp", None))) is not None]
    if len(epochs) >= 3:
        ordered = sorted(epochs, key=lambda p: p[1])
        gaps = [b[1] - a[1] for a, b in zip(ordered, ordered[1:]) if b[1] >= a[1]]
        if gaps and statistics.mean(gaps) > 0:
            spread = 100.0 * (max(gaps) - min(gaps)) / statistics.mean(gaps)
            if spread >= _TH_JITTER_PCT:
                signals.append(
                    AnomalySignal(
                        feature="interhop_jitter",
                        value=round(spread, 1),
                        expected_range=f"inter-hop spread < {_TH_JITTER_PCT}%",
                        z_score=0.0,
                        direction="high",
                        method="threshold_interval_spread",
                        explanation=(
                            f"{len(gaps)} inter-hop gaps span a {spread:.1f}% "
                            "spread, above the fixed jitter threshold. Bursty or "
                            "replayed hop timing is a known strip indicator."
                        ),
                    )
                )

    seen: set = set()
    flagged = [f for f in flagged if not (f in seen or seen.add(f))]

    return AnomalyReport(
        scope=(
            f"session {session_id}: {total} observed flow(s) for MX {mx}, "
            f"compared against a {DEMO} reference distribution "
            f"(data_source={DERIVED}; observed side is {OBSERVED})"
        ),
        baseline_flows=total,
        anomalous_flows=len(flagged),
        signals=signals,
        flagged_flow_ids=flagged,
        method_note=(
            "Fixed-threshold comparison against a deterministic reference "
            f"population. Combined weighting {_WEIGHTS}. No trained model, no "
            "inference-time fitting, no randomness: identical input yields "
            "identical output. Heuristic only; does not affect rule scoring."
        ),
    )
