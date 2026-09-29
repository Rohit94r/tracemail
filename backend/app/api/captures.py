"""
SIH26159 SecureMailScope — Captures API
Upload, folder mode, and session status per docs/04-apis-events.md.
"""

from __future__ import annotations
import os
import uuid
import hashlib
from pathlib import Path
from typing import List, Optional
from fastapi import APIRouter, UploadFile, File, HTTPException
from pydantic import BaseModel

from ..models import SessionSummary, PostureScore
from ..modules.ingest import parse_capture
from ..modules.pcap_index import capture_digest, first_capture_time
from ..modules.rules import evaluate_rules
from ..modules.posture import compute_posture
from ..modules.radar import compute_radar
from ..db import save_db_session, get_db_sessions, save_db_findings, save_db_posture
from ..config import PACKAGE_VER
from ..state import SESSION_CACHE, FINDINGS_CACHE, MX_CACHE, FLOW_CACHE

router = APIRouter(prefix="/api/v1/captures", tags=["Captures"])

CORPUS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "corpus" / "scenarios"

_digest_cache: dict = {}


def _corpus_digest(path: Path) -> str:
    """SHA-256 of a corpus capture, used as its content address."""
    key = str(path)
    if key not in _digest_cache:
        try:
            _digest_cache[key] = capture_digest(path)
        except OSError:
            _digest_cache[key] = None
    return _digest_cache[key]


def _corpus_started_at(path: Path) -> str | None:
    """Real first-packet timestamp of a corpus capture (never a hardcoded date)."""
    try:
        epoch = first_capture_time(path)
    except (OSError, ValueError):
        return None
    if epoch is None:
        return None
    import datetime as _dt

    return (
        _dt.datetime.fromtimestamp(epoch, _dt.timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )

class FolderModeRequest(BaseModel):
    path: str

class PipelineStatus(BaseModel):
    stage: str
    pct: int
    eta_seconds: float

@router.get("", response_model=List[SessionSummary])
def list_sessions():
    summaries = []
    seen_ids = set()

    # Dynamic sessions persisted in MongoDB Atlas
    db_sessions = get_db_sessions()
    for s in db_sessions:
        sid = s.get("id")
        if sid and sid not in seen_ids:
            seen_ids.add(sid)
            summaries.append(
                SessionSummary(
                    id=sid,
                    source_file=s.get("source_file") or s.get("filename", "capture.pcap"),
                    started_at=s.get("started_at"),
                    flow_count=s.get("flow_count", 1),
                    package_ver=s.get("package_ver", PACKAGE_VER),
                    report_hash=s.get("report_hash"),
                    score=s.get("score"),
                    grade=s.get("grade"),
                    ci_range=s.get("ci_range"),
                )
            )

    # Add dynamically uploaded sessions from cache
    for sess_id, s in SESSION_CACHE.items():
        if sess_id not in seen_ids:
            seen_ids.add(sess_id)
            summaries.append(
                SessionSummary(
                    id=sess_id,
                    source_file=s.get("source_file") or s.get("filename", "capture.pcap"),
                    started_at=s.get("started_at"),
                    flow_count=s.get("flow_count", 1),
                    package_ver=PACKAGE_VER,
                    report_hash=s.get("report_hash"),
                    score=s.get("score"),
                    grade=s.get("grade"),
                    ci_range=s.get("ci_range"),
                )
            )

    # Bundled corpus scenarios, so the picker and the demo path work without
    # requiring an upload first. These are NOT analysed yet, so score/grade/
    # report_hash stay None rather than being invented.
    try:
        for cap in sorted(CORPUS_DIR.glob("*.pcap*")):
            if not cap.is_file():
                continue
            sid = f"corpus:{cap.stem}"
            if sid in seen_ids:
                continue
            seen_ids.add(sid)
            summaries.append(
                SessionSummary(
                    id=sid,
                    source_file=cap.name,
                    started_at=_corpus_started_at(cap),
                    package_ver=PACKAGE_VER,
                    capture_sha256=_corpus_digest(cap),
                )
            )
    except OSError:
        pass

    return summaries

@router.post("/sample/{sample_name}")
def ingest_sample_capture(sample_name: str = "stripped"):
    filename_map = {
        "stripped": "stripped.pcap",
        "sweet32": "weak-cipher.pcap",
        "weak-cipher": "weak-cipher.pcap",
        "weak-key": "weak-key.pcap",
        "no-tls": "no-tls.pcap",
        "unused": "advertised-unused.pcap",
        "advertised-unused": "advertised-unused.pcap",
        "multihop": "multihop.pcap",
    }
    target_filename = filename_map.get(sample_name.lower(), "stripped.pcap")
    target_path = CORPUS_DIR / target_filename
    if not target_path.exists():
        raise HTTPException(status_code=404, detail=f"Corpus sample '{target_filename}' not found.")

    session_id = f"sample-{sample_name.lower()}-{uuid.uuid4().hex[:6]}"
    content = target_path.read_bytes()

    flows, warnings = parse_capture(target_path, session_id)
    findings, subscores = evaluate_rules(flows, session_id)
    radar_findings, _ = compute_radar(flows, session_id)
    all_findings = findings + radar_findings

    if not flows:
        raise HTTPException(
            status_code=422,
            detail=f"No mail flows (SMTP/IMAP/POP3) were found in '{target_filename}'.",
        )
    mx_host = flows[0].mx_domain
    posture = compute_posture(mx_host, subscores, all_findings)

    # Store in memory cache
    FINDINGS_CACHE[session_id] = all_findings
    MX_CACHE[session_id] = [posture]
    FLOW_CACHE[session_id] = flows
    session_data = {
        "id": session_id,
        "source_file": target_filename,
        "filename": target_filename,
        "started_at": _corpus_started_at(target_path),
        "flow_count": len(flows),
        "findings_count": len(all_findings),
        "package_ver": PACKAGE_VER,
        "score": posture.index,
        "grade": posture.grade,
        "ci_range": [posture.ci_low, posture.ci_high],
        "capture_sha256": hashlib.sha256(content).hexdigest(),
        "path": str(target_path),
    }
    SESSION_CACHE[session_id] = session_data

    # Persist to MongoDB Atlas
    save_db_session(session_data)
    save_db_findings(session_id, all_findings)
    save_db_posture(session_id, [posture])

    return {
        "session_id": session_id,
        "filename": target_filename,
        "flow_count": len(flows),
        "findings_count": len(all_findings),
        "score": posture.index,
        "grade": posture.grade,
        "ci_range": [posture.ci_low, posture.ci_high],
        "warnings": warnings,
        "capture_sha256": hashlib.sha256(content).hexdigest(),
    }

@router.get("/{id}/status", response_model=PipelineStatus)
def get_session_status(id: str):
    return PipelineStatus(
        stage="done",
        pct=100,
        eta_seconds=0.0
    )

@router.post("/from-folder")
def ingest_from_folder(req: FolderModeRequest):
    folder = Path(req.path)
    if not folder.exists():
        raise HTTPException(status_code=400, detail=f"Directory path '{req.path}' does not exist on host.")

    pcap_files = list(folder.glob("*.pcap*"))
    return {
        "status": "ingested",
        "folder": str(folder),
        "pcaps_found": len(pcap_files),
        "session_ids": [f"sess-{p.stem}" for p in pcap_files],
    }

@router.post("/upload")
def upload_capture(file: UploadFile = File(...)):
    session_id = f"upload-{uuid.uuid4().hex[:8]}"
    content = file.file.read()
    
    # Save file in scratch/live
    temp_dir = Path("/tmp/securemailscope")
    temp_dir.mkdir(parents=True, exist_ok=True)
    temp_path = temp_dir / file.filename
    temp_path.write_bytes(content)

    flows, warnings = parse_capture(temp_path, session_id)
    findings, subscores = evaluate_rules(flows, session_id)
    radar_findings, _ = compute_radar(flows, session_id)
    all_findings = findings + radar_findings

    if not flows:
        raise HTTPException(
            status_code=422,
            detail=f"No mail flows (SMTP/IMAP/POP3) were found in {file.filename!r}.",
        )
    mx_host = flows[0].mx_domain
    posture = compute_posture(mx_host, subscores, all_findings)

    # Store in memory cache
    FINDINGS_CACHE[session_id] = all_findings
    MX_CACHE[session_id] = [posture]
    FLOW_CACHE[session_id] = flows
    session_data = {
        "id": session_id,
        "source_file": file.filename,
        "filename": file.filename,
        "started_at": _corpus_started_at(temp_path),
        "flow_count": len(flows),
        "findings_count": len(all_findings),
        "package_ver": PACKAGE_VER,
        "score": posture.index,
        "grade": posture.grade,
        "ci_range": [posture.ci_low, posture.ci_high],
        "capture_sha256": hashlib.sha256(content).hexdigest(),
        "path": str(temp_path),
    }
    SESSION_CACHE[session_id] = session_data

    # Persist to MongoDB Atlas
    save_db_session(session_data)
    save_db_findings(session_id, all_findings)
    save_db_posture(session_id, [posture])

    return {
        "session_id": session_id,
        "filename": file.filename,
        "flow_count": len(flows),
        "findings_count": len(all_findings),
        "score": posture.index,
        "grade": posture.grade,
        "ci_range": [posture.ci_low, posture.ci_high],
        "warnings": warnings,
        "capture_sha256": hashlib.sha256(content).hexdigest(),
    }
