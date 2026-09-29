"""
SIH26159 SecureMailScope — Core Engine Unit Tests
Verifies rule engine, STARTTLS state machine, and posture scoring against frozen corpus fixtures.
"""

from pathlib import Path
from backend.app.modules.ingest import parse_capture
from backend.app.modules.rules import evaluate_rules
from backend.app.modules.posture import compute_posture
from backend.app.modules.radar import compute_radar

CORPUS_DIR = Path(__file__).resolve().parent.parent.parent / "corpus" / "scenarios"

def test_stripped_pcap():
    p = CORPUS_DIR / "stripped.pcap"
    assert p.exists(), f"Corpus fixture missing: {p}"
    
    flows, warnings = parse_capture(p, "test-stripped")
    assert len(flows) == 1, f"Expected 1 flow, got {len(flows)}"
    assert flows[0].starttls_category == "stripped", f"Expected stripped, got {flows[0].starttls_category}"

    findings, subscores = evaluate_rules(flows, "test-stripped")
    rule_ids = [f.rule_id for f in findings]
    assert "SMS-ENF-002" in rule_ids, f"Expected SMS-ENF-002 in {rule_ids}"

def test_weak_cipher_pcap():
    p = CORPUS_DIR / "weak-cipher.pcap"
    assert p.exists(), f"Corpus fixture missing: {p}"
    
    flows, warnings = parse_capture(p, "test-weak-cipher")
    assert len(flows) >= 1
    assert flows[0].tls is not None
    assert flows[0].tls.cipher_suite_iana == "TLS_RSA_WITH_AES_128_CBC_SHA"
    assert flows[0].tls.pfs is False

    findings, subscores = evaluate_rules(flows, "test-weak-cipher")
    rule_ids = [f.rule_id for f in findings]
    assert "SMS-CIPH-002" in rule_ids, f"Expected SMS-CIPH-002 in {rule_ids}"

def test_advertised_unused_pcap():
    p = CORPUS_DIR / "advertised-unused.pcap"
    assert p.exists()
    
    flows, warnings = parse_capture(p, "test-unused")
    assert len(flows) >= 1
    assert flows[0].starttls_category == "advertised_unused"

    findings, subscores = evaluate_rules(flows, "test-unused")
    rule_ids = [f.rule_id for f in findings]
    assert "SMS-ENF-001" in rule_ids, f"Expected SMS-ENF-001 in {rule_ids}"

def test_posture_calculation():
    p = CORPUS_DIR / "stripped.pcap"
    flows, _ = parse_capture(p, "test-posture")
    findings, subscores = evaluate_rules(flows, "test-posture")
    
    for mx, ss in subscores.items():
        score = compute_posture(mx, ss, findings)
        assert 0 <= score.index <= 100
        assert score.ci_low <= score.index <= score.ci_high
        assert score.grade in ["Grade A", "Grade B", "Grade C", "Grade D", "Grade E"]

if __name__ == "__main__":
    test_stripped_pcap()
    print("✓ test_stripped_pcap passed")
    test_weak_cipher_pcap()
    print("✓ test_weak_cipher_pcap passed")
    test_advertised_unused_pcap()
    print("✓ test_advertised_unused_pcap passed")
    test_posture_calculation()
    print("✓ test_posture_calculation passed")
    print("\nAll Core Engine Unit Tests PASSED!")
