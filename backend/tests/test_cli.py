"""
SIH26159 SecureMailScope — CLI & Verification Unit Tests
Verifies headless scoring and D5 verification via the Python CLI.
"""

from pathlib import Path
from backend.app.cli import cmd_score, cmd_verify

CORPUS_DIR = Path(__file__).resolve().parent.parent.parent / "corpus" / "scenarios"

def test_cli_score_headless(capsys):
    """Verify headless scoring prints human-readable banner and returns exit code 0."""
    pcap = CORPUS_DIR / "stripped.pcap"
    assert pcap.exists()

    code = cmd_score(str(pcap), as_json=False)
    assert code == 0
    captured = capsys.readouterr()
    assert "RAVEN // SECUREMAILSCOPE" in captured.out
    assert "SMS-ENF-002" in captured.out
    assert "sha256:" in captured.out

def test_cli_score_json(capsys):
    """Verify headless scoring supports valid JSON serialization."""
    pcap = CORPUS_DIR / "weak-cipher.pcap"
    code = cmd_score(str(pcap), as_json=True)
    assert code == 0
    captured = capsys.readouterr()
    import json
    data = json.loads(captured.out)
    assert data["file"] == "weak-cipher.pcap"
    assert "posture" in data
    assert "SMS-CIPH-002" in [f["rule_id"] for f in data["findings"]]

def test_cli_d5_verification():
    """Verify D5 reproducibility across all 5 corpus fixtures."""
    code = cmd_verify()
    assert code == 0
