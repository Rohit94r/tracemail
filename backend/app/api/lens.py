"""
SIH26159 SecureMailScope — Attack Lens (D6).

Threat forecasting. Each attack class in the catalog declares the rule IDs that
drive it; a class is only offered for a session when at least one of its driver
rules actually fired, and its likelihood is computed from the severity and
confidence of those findings rather than asserted.

The catalog itself is a fixed reference (it describes standing attack classes,
not observations), so it is returned with ``data_source="demo_fixture"``; the
per-session likelihood and the driving findings are ``observed``.
"""

from fastapi import APIRouter
from pydantic import BaseModel
from typing import List, Optional

from ..modules.demo_fixtures import DEMO_ATTACK_CLASSES
from ..modules.provenance import DEMO, DERIVED, OBSERVED
from ..modules.report_builder import build_report

router = APIRouter(prefix="/api/v1/lens", tags=["Attack Lens"])

_SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}


class Forecast(BaseModel):
    attack_class: str
    likelihood: str
    likelihood_score: float
    confidence: str
    rationale: str
    driver_rule_ids: List[str]
    driver_finding_ids: List[str]
    preconditions: List[str]
    impact: str
    data_source: str


@router.get("/{session_id}", response_model=List[Forecast])
def get_attack_forecasts(session_id: str):
    report = build_report(session_id)
    findings = report.get("findings", [])
    by_rule: dict = {}
    for f in findings:
        by_rule.setdefault(f["rule_id"], []).append(f)

    out: List[Forecast] = []
    for klass in DEMO_ATTACK_CLASSES:
        drivers = [
            (rid, group) for rid, group in by_rule.items()
            if rid in klass["driver_rule_ids"]
        ]
        if not drivers:
            continue

        # Likelihood rises with the worst driver severity and scales with the
        # mean confidence of the findings that triggered the class.
        worst = max(
            (_SEVERITY_RANK.get(f["severity"], 0) for _, g in drivers for f in g),
            default=0,
        )
        conf = sum(f.get("confidence") or 0.0 for _, g in drivers for f in g)
        conf /= sum(len(g) for _, g in drivers) or 1.0
        score = round(min(100.0, (worst / 3.0) * 70.0 + conf * 30.0), 1)
        likelihood = (
            "HIGH" if score >= 70 else "MEDIUM" if score >= 40 else "LOW"
        )

        driver_rules = sorted(r for r, _ in drivers)
        driver_ids = [f"rule:{r}" for r in driver_rules]
        rationale = (
            f"Triggered by {len(findings)} finding(s) in this session "
            f"({', '.join(driver_rules)}). Worst driver severity ranks "
            f"{worst}/3 with mean finding confidence {conf:.0%}."
        )

        out.append(
            Forecast(
                attack_class=klass["attack_class"],
                likelihood=likelihood,
                likelihood_score=score,
                confidence=f"{conf:.0%}",
                rationale=rationale,
                driver_rule_ids=driver_rules,
                driver_finding_ids=driver_ids,
                preconditions=klass["preconditions"],
                impact=klass["impact"],
                data_source=f"{OBSERVED} (likelihood) + {DEMO} (attack catalog)",
            )
        )

    out.sort(key=lambda f: -f.likelihood_score)
    return out
