"""
SIH26159 SecureMailScope — End-to-End API & MongoDB Integration Tests
Verifies FastAPI endpoints interacting with MongoDB Atlas cluster 'vastraq'.
"""

from pathlib import Path
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.db import get_db

client = TestClient(app)
CORPUS_DIR = Path(__file__).resolve().parent.parent.parent / "corpus" / "scenarios"

def test_health_api_with_mongo():
    """Verify /api/v1/health checks MongoDB and reports status ok and net online."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["db_ok"] is True
    assert data["net"] == "online"

def test_list_captures():
    """Verify /api/v1/captures returns sessions including scenarios and MongoDB sessions."""
    response = client.get("/api/v1/captures")
    assert response.status_code == 200
    sessions = response.json()
    assert isinstance(sessions, list)
    assert len(sessions) > 0
    # Scenarios from corpus should be present
    scenario_ids = [s["id"] for s in sessions]
    assert any("stripped" in s_id for s_id in scenario_ids)

def test_upload_pcap_persists_to_mongo():
    """Upload a real corpus pcap and verify records land in MongoDB Atlas collections."""
    pcap_path = CORPUS_DIR / "stripped.pcap"
    assert pcap_path.exists()

    with open(pcap_path, "rb") as f:
        files = {"file": ("stripped.pcap", f, "application/vnd.tcpdump.pcap")}
        response = client.post("/api/v1/captures/upload", files=files)

    assert response.status_code == 200
    upload_data = response.json()
    session_id = upload_data["session_id"]
    assert session_id.startswith("upload-")
    assert upload_data["flow_count"] >= 1
    assert upload_data["findings_count"] >= 1

    # Verify session in MongoDB
    db = get_db()
    sess_doc = db.raven_sessions.find_one({"id": session_id})
    assert sess_doc is not None, f"Session {session_id} not found in MongoDB raven_sessions"
    assert sess_doc["flow_count"] >= 1

    # Verify findings in MongoDB
    findings_count = db.raven_findings.count_documents({"session_id": session_id})
    assert findings_count >= 1, f"No findings stored in raven_findings for {session_id}"

    # Verify posture score in MongoDB
    scores_count = db.raven_scores.count_documents({"session_id": session_id})
    assert scores_count >= 1, f"No scores stored in raven_scores for {session_id}"

    # Verify GET /api/v1/findings endpoint fetches from DB/cache
    findings_resp = client.get(f"/api/v1/findings?session_id={session_id}")
    assert findings_resp.status_code == 200
    findings = findings_resp.json()
    assert len(findings) >= 1
    rule_ids = [f["rule_id"] for f in findings]
    assert "SMS-ENF-002" in rule_ids

    # Verify GET /api/v1/mx endpoint fetches posture
    mx_resp = client.get(f"/api/v1/mx?session_id={session_id}")
    assert mx_resp.status_code == 200
    mx_list = mx_resp.json()
    assert len(mx_list) >= 1
    assert "grade" in mx_list[0]
