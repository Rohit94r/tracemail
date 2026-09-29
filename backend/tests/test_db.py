"""
SIH26159 SecureMailScope — MongoDB Integration Tests
Verifies MongoDB Atlas connectivity, collection isolation, session persistence, and query retrieval.
"""

import uuid
from backend.app.db import (
    ping_db,
    save_db_session,
    get_db_sessions,
    save_db_findings,
    get_db_findings,
    save_db_posture,
    get_db_posture,
)
from backend.app.models import Finding, FindingProvenance, PostureScore, SubScores

def test_mongo_ping():
    """Verify MongoDB Atlas cluster responds to ping command."""
    connected = ping_db()
    assert connected is True, "MongoDB Atlas ping failed; check MONGO_URI and network access."

def test_session_lifecycle():
    """Verify session creation and retrieval in raven_sessions collection."""
    test_id = f"test-sess-{uuid.uuid4().hex[:6]}"
    sample_session = {
        "id": test_id,
        "source_file": "test_sample.pcap",
        "started_at": "2026-09-29 16:00:00 UTC",
        "flow_count": 2,
        "package_ver": "v1.4.0-sih",
        "report_hash": "sha256:abc123test",
        "score": 85.5,
        "grade": "Grade A-",
        "ci_range": [80.0, 90.0],
    }

    save_db_session(sample_session)
    sessions = get_db_sessions()
    session_ids = [s["id"] for s in sessions]
    assert test_id in session_ids, f"Expected {test_id} to be retrieved from MongoDB"

    matching = next(s for s in sessions if s["id"] == test_id)
    assert matching["source_file"] == "test_sample.pcap"
    assert matching["score"] == 85.5

def test_findings_persistence():
    """Verify finding document insertion and querying in raven_findings collection."""
    test_sess = f"test-find-{uuid.uuid4().hex[:6]}"
    provenance = FindingProvenance(
        flow_id="tcp|192.168.1.1:1000->10.0.0.1:25",
        packet_no=4,
        byte_offset="0x0000002A",
        tls_record_idx=0,
        timestamp="2026-09-29 16:00:00 UTC",
        span_hash="sha256:abc",
        hex_snippet="45484c4f",
        ascii_snippet="EHLO test",
    )
    sample_finding = Finding(
        session_id=test_sess,
        flow_id="tcp|192.168.1.1:1000->10.0.0.1:25",
        module="enforce",
        rule_id="SMS-ENF-002",
        title="STARTTLS Command Stripped on Wire",
        summary="Adversary stripped STARTTLS response",
        clause="RFC 3207 §4",
        state="VULNERABLE",
        severity="critical",
        cvss=7.5,
        cwe="CWE-319",
        confidence=0.95,
        provenance=provenance,
    )

    save_db_findings(test_sess, [sample_finding])
    results = get_db_findings(test_sess)
    assert len(results) >= 1
    assert results[0]["rule_id"] == "SMS-ENF-002"
    assert results[0]["state"] == "VULNERABLE"

def test_posture_persistence():
    """Verify posture score persistence and retrieval in raven_scores collection."""
    test_sess = f"test-posture-{uuid.uuid4().hex[:6]}"
    sample_posture = PostureScore(
        mx="mail.test-mongo.com",
        index=78.4,
        ci_low=72.0,
        ci_high=84.0,
        grade="Grade B+",
        confidence_label="high confidence",
        sub_scores=SubScores(
            protocol=80.0,
            cipher=75.0,
            key=85.0,
            x509=70.0,
            dns=80.0,
            enforce=80.0,
        ),
        tri_state_summary={"SECURE": 100, "VULNERABLE": 5, "NOT-OBSERVABLE": 2},
        rubric={"active_rules": ["SMS-PROTO-001"]},
    )

    save_db_posture(test_sess, [sample_posture])
    results = get_db_posture(test_sess)
    assert len(results) >= 1
    assert results[0]["mx"] == "mail.test-mongo.com"
    assert results[0]["grade"] == "Grade B+"
