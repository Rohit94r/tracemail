"""
SIH26159 SecureMailScope — Report Builder (JSON / HTML / PDF).

Builds one canonical report document per session from the values actually
computed for that session, then seals it.

Sealing is content-addressed: the SHA-256 is taken over the canonical JSON
serialisation, so the digest depends only on the content, never on wall-clock
time, dict ordering or the renderer. Re-running the pipeline on the same capture
with the same ``package_ver`` therefore reproduces the same seal, which is what
``make verify`` asserts.
"""

from __future__ import annotations

import hashlib
import html
import json
from typing import Any, Dict, List, Optional

from ..config import PACKAGE_VER
from ..state import FINDINGS_CACHE, FLOW_CACHE, MX_CACHE
from .demo_fixtures import PLAYBOOK
from .provenance import DERIVED, OBSERVED

_STATE_LABEL = {
    "VULNERABLE": "#dc2626",
    "SECURE": "#16a34a",
    "NOT-OBSERVABLE": "#a16207",
}


def _session_facts(session_id: str) -> Dict[str, Any]:
    """Collect everything known about a session, with provenance labels."""
    findings = FINDINGS_CACHE.get(session_id) or []
    flows = FLOW_CACHE.get(session_id) or []
    postures = MX_CACHE.get(session_id) or []

    primary = postures[0] if postures else None
    ordered = sorted(
        findings,
        key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(
            getattr(f, "severity", "low"), 4
        ),
    )

    return {
        "session_id": session_id,
        "package_ver": PACKAGE_VER,
        "flow_count": len(flows),
        "posture": primary,
        "postures": postures,
        "findings": ordered,
        "flows": flows,
        "data_source": OBSERVED if (flows or findings or postures) else DERIVED,
    }


def build_report(session_id: str) -> Dict[str, Any]:
    """
    Canonical report document.

    The dict returned here is the ONLY hashed representation. HTML and PDF are
    renderings of it, so all three agree on the same verdict and the same seal.
    """
    facts = _session_facts(session_id)
    posture = facts["posture"]

    flows_summary = []
    for flow in facts["flows"]:
        flows_summary.append(
            {
                "flow_id": flow.flow_id,
                "hop_index": flow.hop_index,
                "service": flow.service,
                "server": f"{flow.server_ip}:{flow.server_port}",
                "mx_domain": flow.mx_domain,
                "mx_domain_source": flow.mx_domain_source,
                "starttls_category": flow.starttls_category,
                "tls_version": flow.tls.observed_version if flow.tls else None,
                "cipher": flow.tls.cipher_suite_iana if flow.tls else None,
                "pfs": flow.tls.pfs if flow.tls else None,
                "aead": flow.tls.aead if flow.tls else None,
                "ja3s": flow.tls.ja3s if flow.tls else None,
                "public_key_alg": (
                    flow.x509.public_key_alg if flow.x509 else None
                ),
                "public_key_bits": (
                    flow.x509.public_key_bits if flow.x509 else None
                ),
                "signature_alg": flow.x509.sig_algo if flow.x509 else None,
                "not_after": flow.x509.not_after if flow.x509 else None,
                "chain_len": flow.x509.chain_len if flow.x509 else None,
                "trust_check_method": (
                    flow.x509.trust_check_method if flow.x509 else None
                ),
                "first_packet_no": flow.first_packet_no,
                "first_byte_offset": flow.first_byte_offset,
                "first_packet_timestamp": flow.first_packet_timestamp,
                "capture_sha256": flow.capture_sha256,
            }
        )

    findings_payload = [
        {
            "rule_id": f.rule_id,
            "title": f.title,
            "state": f.state,
            "severity": f.severity,
            "cvss": f.cvss,
            "cwe": f.cwe,
            "clause": f.clause,
            "summary": f.summary,
            "confidence": f.confidence,
            "flow_id": f.flow_id,
            "evidence": {
                "packet_no": f.provenance.packet_no,
                "byte_offset": f.provenance.byte_offset,
                "byte_offset_exact": f.provenance.byte_offset_exact,
                "timestamp": f.provenance.timestamp,
                "span_hash": f.provenance.span_hash,
                "ascii_snippet": f.provenance.ascii_snippet,
            },
        }
        for f in facts["findings"]
    ]

    report: Dict[str, Any] = {
        "report_schema": "sms.report/1.4",
        "session_id": session_id,
        "package_ver": PACKAGE_VER,
        "air_gapped": True,
        "data_source": facts["data_source"],
        "summary": {
            "flow_count": facts["flow_count"],
            "finding_count": len(findings_payload),
            "critical_count": sum(
                1 for f in findings_payload if f["severity"] == "critical"
            ),
            "high_count": sum(
                1 for f in findings_payload if f["severity"] == "high"
            ),
            "vulnerable_count": sum(
                1 for f in findings_payload if f["state"] == "VULNERABLE"
            ),
        },
        "posture": (
            {
                "mx": posture.mx,
                "index": posture.index,
                "ci_low": posture.ci_low,
                "ci_high": posture.ci_high,
                "grade": posture.grade,
                "confidence_label": posture.confidence_label,
                "sub_scores": posture.sub_scores.model_dump(),
                "tri_state_summary": posture.tri_state_summary,
            }
            if posture
            else None
        ),
        "flows": flows_summary,
        "findings": findings_payload,
    }

    report["content_sha256"] = content_hash(report)
    return report


def canonical_bytes(report: Dict[str, Any]) -> bytes:
    """Stable byte representation used for sealing and verification."""
    payload = {k: v for k, v in report.items() if k != "content_sha256"}
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def content_hash(report: Dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(report)).hexdigest()


def verify_report_hash(report: Dict[str, Any]) -> bool:
    claimed = report.get("content_sha256")
    return bool(claimed) and claimed == content_hash(report)


def _esc(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def render_html(report: Dict[str, Any]) -> str:
    posture = report.get("posture")
    e = _esc

    if posture and posture.get("index") is not None:
        verdict = (
            f'{e(posture["grade"])} — {e(posture["index"])}/100 '
            f'[CI: {e(posture["ci_low"])}–{e(posture["ci_high"])}]'
        )
    else:
        verdict = "NOT-OBSERVABLE — no mail flows were found in this capture"

    rows = []
    for f in report.get("findings", []):
        ev = f.get("evidence", {})
        colour = _STATE_LABEL.get(f.get("state"), "#64748b")
        rows.append(
            f"""<tr>
  <td><span class="pill" style="background:{colour}">{e(f.get('state'))}</span></td>
  <td><b>{e(f.get('rule_id'))}</b><br><span class="muted">{e(f.get('title'))}</span></td>
  <td>{e(f.get('severity'))}<br><span class="muted">CVSS {e(f.get('cvss'))}</span></td>
  <td>{e(f.get('cwe'))}</td>
  <td>pkt <b>{e(ev.get('packet_no'))}</b><br>
      <span class="mono">{e(ev.get('byte_offset'))}</span><br>
      <span class="muted">{e(ev.get('timestamp'))}</span></td>
</tr>"""
        )

    flow_rows = []
    for fl in report.get("flows", []):
        flow_rows.append(
            f"""<tr>
  <td>{e(fl.get('hop_index'))}</td>
  <td>{e(fl.get('service'))}</td>
  <td>{e(fl.get('mx_domain'))}
      <span class="muted">({e(fl.get('mx_domain_source'))})</span></td>
  <td>{e(fl.get('starttls_category'))}</td>
  <td>{e(fl.get('tls_version'))}<br><span class="muted">{e(fl.get('cipher'))}</span></td>
  <td>{e(fl.get('public_key_alg'))} {e(fl.get('public_key_bits'))}
      <br><span class="muted">{e(fl.get('signature_alg'))}</span></td>
  <td class="mono">{e(fl.get('first_byte_offset'))}</td>
</tr>"""
        )

    playbook = [
        PLAYBOOK[f["rule_id"]]
        for f in report.get("findings", [])
        if f.get("rule_id") in PLAYBOOK
    ]
    playbook_rows = "".join(
        f"<tr><td><b>{e(p['directive'])}</b><br>"
        f"<span class='muted'>{e(p['action'])}</span></td></tr>"
        for p in playbook
    )

    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<title>SecureMailScope Audit Report — {e(report.get('session_id'))}</title>
<style>
 body {{ font-family: ui-sans-serif, system-ui, sans-serif; margin: 0;
        background: #0b0f19; color: #e2e8f0; }}
 .wrap {{ max-width: 1100px; margin: 0 auto; padding: 40px 28px 80px; }}
 h1 {{ font-size: 24px; margin: 0 0 4px; letter-spacing: .5px; }}
 h2 {{ font-size: 16px; margin: 32px 0 10px; color: #93c5fd;
       text-transform: uppercase; letter-spacing: 1px; }}
 .sub {{ color: #94a3b8; font-size: 13px; margin-bottom: 24px; }}
 .card {{ background: #111827; border: 1px solid #1f2937; border-radius: 10px;
          padding: 18px 20px; margin-bottom: 18px; }}
 .verdict {{ font-size: 30px; font-weight: 700; color: #f8fafc; }}
 .seal {{ font-family: ui-monospace, monospace; font-size: 12px; color: #7dd3fc;
          word-break: break-all; }}
 table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
 th {{ text-align: left; color: #94a3b8; font-weight: 600; padding: 8px 10px;
       border-bottom: 1px solid #1f2937; font-size: 11px;
       text-transform: uppercase; letter-spacing: .6px; }}
 td {{ padding: 10px; border-bottom: 1px solid #16202f; vertical-align: top; }}
 .pill {{ display: inline-block; padding: 2px 8px; border-radius: 99px;
          font-size: 10px; font-weight: 700; color: #fff; }}
 .muted {{ color: #64748b; font-size: 11px; }}
 .mono {{ font-family: ui-monospace, monospace; font-size: 11px; }}
 .tag {{ display:inline-block; padding:2px 9px; border-radius:99px;
         font-size:11px; background:#1e293b; color:#7dd3fc; margin-right:8px; }}
 footer {{ margin-top: 40px; color: #475569; font-size: 11px; }}
</style></head>
<body><div class="wrap">

<h1>SECUREMAILSCOPE — CRYPTOGRAPHIC POSTURE AUDIT</h1>
<div class="sub">Session <b>{e(report.get('session_id'))}</b> ·
  package {e(report.get('package_ver'))} · air-gapped, passive analysis</div>

<div class="card">
  <div class="verdict">{verdict}</div>
  <div class="sub" style="margin-top:6px">
    {report['summary']['flow_count']} flow(s) ·
    {report['summary']['finding_count']} finding(s) ·
    {report['summary']['vulnerable_count']} vulnerable ·
    {report['summary']['high_count']} high severity
  </div>
  <div>
    <span class="tag">PASSIVE — no packets sent</span>
    <span class="tag">NO DECRYPTION</span>
    <span class="tag">NO CREDENTIALS STORED</span>
    <span class="tag">data source: {e(report.get('data_source'))}</span>
  </div>
</div>

<h2>Evidence Seal</h2>
<div class="card">
  <div class="seal">sha256:{e(report.get('content_sha256'))}</div>
  <div class="muted" style="margin-top:6px">
    SHA-256 over the canonical JSON body of this report. Identical capture +
    identical package version reproduces this digest.
  </div>
</div>

<h2>Findings</h2>
<div class="card">
<table>
<tr><th>State</th><th>Rule</th><th>Severity</th><th>CWE</th><th>Evidence</th></tr>
{''.join(rows) or '<tr><td colspan="5" class="muted">No findings raised.</td></tr>'}
</table>
</div>

<h2>Observed Flows</h2>
<div class="card">
<table>
<tr><th>Hop</th><th>Service</th><th>MX</th><th>STARTTLS</th>
    <th>TLS</th><th>Certificate</th><th>Offset</th></tr>
{''.join(flow_rows) or '<tr><td colspan="7" class="muted">No flows.</td></tr>'}
</table>
</div>

<h2>Remediation</h2>
<div class="card">
<table>{playbook_rows or '<tr><td class="muted">No remediation directives apply.</td></tr>'}</table>
</div>

<footer>
Generated by SecureMailScope {e(report.get('package_ver'))} ·
data source: {e(report.get('data_source'))} ·
This tool never probes mail servers, never decrypts traffic and never reads
message content.
</footer>
</div></body></html>"""


def render_pdf(report: Dict[str, Any]) -> bytes:
    """
    Renders the report to PDF.

    WeasyPrint is the primary renderer. When it is unavailable (common on
    air-gapped hosts without system Pango/Cairo) the report is still produced by
    emitting a minimal, standards-conformant PDF 1.4 written directly, so the
    PDF deliverable is never missing and never faked.
    """
    try:
        from weasyprint import HTML  # type: ignore

        return HTML(string=render_html(report)).write_pdf()
    except Exception:
        return _fallback_pdf(report)


def _pdf_escape(text: str) -> str:
    return (
        text.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")
    )


def _fallback_pdf(report: Dict[str, Any]) -> bytes:
    """
    Minimal but valid PDF 1.4 writer with no external dependency.

    Object numbers are assigned up front so cross-references (Catalog -> Pages ->
    Page -> Contents/Font) are known before any bytes are written, which keeps
    the writer free of patch-up passes.
    """
    posture = report.get("posture") or {}
    if posture.get("index") is not None:
        verdict = (
            f'{posture.get("grade")} - {posture.get("index")}/100 '
            f'[CI {posture.get("ci_low")}-{posture.get("ci_high")}]'
        )
    else:
        verdict = "NOT-OBSERVABLE - no mail flows in capture"

    lines: List[str] = [
        "SECUREMAILSCOPE - CRYPTOGRAPHIC POSTURE AUDIT",
        "",
        f"Session: {report.get('session_id')}",
        f"Package: {report.get('package_ver')}",
        f"Data source: {report.get('data_source')}",
        "",
        f"VERDICT: {verdict}",
        "",
        f"Flows: {report['summary']['flow_count']}    "
        f"Findings: {report['summary']['finding_count']}    "
        f"Vulnerable: {report['summary']['vulnerable_count']}",
        "",
        f"Content SHA-256: {report.get('content_sha256')}",
        "",
        "-" * 74,
        "FINDINGS",
        "-" * 74,
    ]
    for f in report.get("findings", []):
        ev = f.get("evidence", {})
        lines.append(f'{f.get("rule_id")}  [{f.get("state")}]  {f.get("title")}')
        lines.append(
            f'    severity={f.get("severity")} cvss={f.get("cvss")} '
            f'packet={ev.get("packet_no")} offset={ev.get("byte_offset")}'
        )
    if not report.get("findings"):
        lines.append("No findings raised.")

    lines += ["", "-" * 74, "OBSERVED FLOWS", "-" * 74]
    if not report.get("flows"):
        lines.append("No mail flows observed.")
    else:
        for fl in report.get("flows", []):
            lines.append(
                f'hop {fl.get("hop_index")}  {fl.get("service")}  '
                f'{fl.get("mx_domain")}  {fl.get("starttls_category")}'
            )
            if fl.get("tls_version"):
                key = (
                    f'{fl.get("public_key_alg") or "?"}/'
                    f'{fl.get("public_key_bits") or "?"}'
                )
                lines.append(
                    f'    {fl.get("tls_version")} {fl.get("cipher")}  '
                    f'key={key}  sig={fl.get("signature_alg") or "?"}  '
                    f'offset={fl.get("first_byte_offset")}'
                )
            else:
                lines.append(
                    f'    no TLS observed - plaintext protocol'
                    f'  offset={fl.get("first_byte_offset")}'
                )

    lines += [
        "",
        "-" * 74,
        "Passive analysis: no packets sent, no decryption, no message content.",
    ]

    per_page = 62  # fits Letter at 9pt with 17pt leading
    pages = [lines[i:i + per_page] for i in range(0, len(lines), per_page)] or [[""]]

    CATALOG, PAGES, F_REG, F_BOLD = 1, 2, 3, 4
    first_page = 5
    n = len(pages)

    def content_stream(page_lines: List[str]) -> bytes:
        ops = ["BT", "/F2 15 Tf", "1 0 0 1 56 744 Tm", "17 TL"]
        for line in page_lines:
            bold = bool(line.strip()) and line == line.upper() and len(line) > 3
            ops.append(f"/{'F2' if bold else 'F1'} 9 Tf")
            ops.append(f"({_pdf_escape(line[:96])}) Tj")
            ops.append("T*")
        ops.append("ET")
        return "\n".join(ops).encode("latin-1", "replace")

    streams = [content_stream(pg) for pg in pages]

    # page i -> object first_page + 2*i, its stream -> first_page + 2*i + 1
    objects: Dict[int, bytes] = {
        CATALOG: b"<< /Type /Catalog /Pages " + str(PAGES).encode() + b" 0 R >>",
        F_REG: (
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
            b"/Encoding /WinAnsiEncoding >>"
        ),
        F_BOLD: (
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold "
            b"/Encoding /WinAnsiEncoding >>"
        ),
    }

    kids = b" ".join(
        str(first_page + 2 * i).encode() + b" 0 R" for i in range(n)
    )
    objects[PAGES] = (
        b"<< /Type /Pages /Count "
        + str(n).encode()
        + b" /Kids ["
        + kids
        + b"] >>"
    )

    for i, stream in enumerate(streams):
        page_obj = first_page + 2 * i
        stream_obj = page_obj + 1
        objects[page_obj] = (
            b"<< /Type /Page /Parent "
            + str(PAGES).encode()
            + b" 0 R /MediaBox [0 0 612 792] "
            b"/Resources << /Font << /F1 "
            + str(F_REG).encode()
            + b" 0 R /F2 "
            + str(F_BOLD).encode()
            + b" 0 R >> >> /Contents "
            + str(stream_obj).encode()
            + b" 0 R >>"
        )
        objects[stream_obj] = (
            b"<< /Length "
            + str(len(stream)).encode()
            + b" >>\nstream\n"
            + stream
            + b"\nendstream"
        )

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets: Dict[int, int] = {}
    for num in sorted(objects):
        offsets[num] = len(out)
        out += str(num).encode() + b" 0 obj\n" + objects[num] + b"\nendobj\n"

    highest = max(objects)
    xref_at = len(out)
    out += b"xref\n0 " + str(highest + 1).encode() + b"\n"
    out += b"0000000000 65535 f \n"
    for num in range(1, highest + 1):
        out += ("%010d 00000 n \n" % offsets.get(num, 0)).encode()
    out += (
        b"trailer\n<< /Size "
        + str(highest + 1).encode()
        + b" /Root "
        + str(CATALOG).encode()
        + b" 0 R >>\nstartxref\n"
        + str(xref_at).encode()
        + b"\n%%EOF\n"
    )
    return bytes(out)
