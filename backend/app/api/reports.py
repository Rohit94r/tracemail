"""
SIH26159 SecureMailScope — Reports & Remediation API.

Serves the JSON / HTML / PDF renderings of the canonical report document, its
content-addressed SHA-256 seal, and rule-driven remediation playbooks.
"""

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, Response

from ..config import PACKAGE_VER
from ..modules.demo_fixtures import PLAYBOOK
from ..modules.report_builder import (
    build_report,
    render_html,
    render_pdf,
    verify_report_hash,
)
from ..state import FINDINGS_CACHE

router = APIRouter(prefix="/api/v1/reports", tags=["Reports"])


@router.get("/{session_id}.json")
def get_report_json(session_id: str):
    """Canonical report document, including its content-addressed seal."""
    return build_report(session_id)


@router.get("/{session_id}.html", response_class=HTMLResponse)
def get_report_html(session_id: str):
    return render_html(build_report(session_id))


@router.get("/{session_id}.pdf")
def get_report_pdf(session_id: str) -> Response:
    """PDF export, sealed with the same content hash as the JSON/HTML."""
    report = build_report(session_id)
    pdf = render_pdf(report)
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="securemailscope-{session_id}.pdf"'
            ),
            "X-Content-SHA256": report["content_sha256"],
        },
    )


@router.get("/{session_id}/hash")
def get_report_hash(session_id: str):
    report = build_report(session_id)
    return {
        "session_id": session_id,
        "sha256": report["content_sha256"],
        "content_sha256": report["content_sha256"],
        "package_ver": PACKAGE_VER,
        "algorithm": "SHA-256 over canonical JSON report body",
        "verified": verify_report_hash(report),
        "seal_scope": "json+html+pdf",
    }


@router.post("/{session_id}/playbook")
def generate_playbook(session_id: str):
    """
    Remediation directives for the rules this session actually triggered,
    plus the full catalog so the deliverable is never empty.
    """
    report = build_report(session_id)
    triggered = {f["rule_id"] for f in report.get("findings", [])}

    directives = [
        {
            "rule_id": rule_id,
            "mta": entry["mta"],
            "directive": entry["directive"],
            "action": entry["action"],
            "triggered_in_session": rule_id in triggered,
        }
        for rule_id, entry in PLAYBOOK.items()
    ]
    return {
        "session_id": session_id,
        "package_ver": PACKAGE_VER,
        "triggered_count": len(triggered & set(PLAYBOOK)),
        "remediation_directives": sorted(
            directives, key=lambda d: (not d["triggered_in_session"], d["rule_id"])
        ),
    }
