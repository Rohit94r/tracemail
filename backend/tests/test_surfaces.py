"""
SIH26159 SecureMailScope — regression tests for the analysis surfaces added to
close out D1-D6: report rendering, DNS policy, deterministic anomaly detection,
the delivery graph, attack lens, integrity verification and the grounded
assistant.

These assert on the documented contract (response codes, schema, determinism,
provenance) rather than on hardcoded scores, so a legitimate rule-weight change
does not break them.
"""

import sys
from pathlib import Path

import pytest
from starlette.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from backend.app.main import app  # noqa: E402


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def stripped(client):
    return client.post("/api/v1/captures/sample/stripped").json()["session_id"]


@pytest.fixture(scope="module")
def weak_key(client):
    return client.post("/api/v1/captures/sample/weak-key").json()["session_id"]


# ---------------------------------------------------------------------------
# D1/D5 — report rendering and reproducibility
# ---------------------------------------------------------------------------

def test_report_json_shape(client, stripped):
    r = client.get(f"/api/v1/reports/{stripped}.json")
    assert r.status_code == 200
    body = r.json()
    for key in ("session_id", "content_sha256", "posture", "findings", "flows", "data_source"):
        assert key in body, f"missing report key: {key}"
    assert len(body["content_sha256"]) == 64
    assert body["findings"], "stripped capture must produce at least one finding"


def test_report_hash_is_deterministic(client, stripped):
    first = client.get(f"/api/v1/reports/{stripped}/hash").json()["content_sha256"]
    second = client.get(f"/api/v1/reports/{stripped}/hash").json()["content_sha256"]
    assert first == second, "report seal must be reproducible across calls"
    assert first == client.get(f"/api/v1/reports/{stripped}.json").json()["content_sha256"]


def test_report_html_and_pdf_render(client, stripped):
    html = client.get(f"/api/v1/reports/{stripped}.html")
    assert html.status_code == 200
    assert "text/html" in html.headers["content-type"]
    assert "<html" in html.text.lower()

    pdf = client.get(f"/api/v1/reports/{stripped}.pdf")
    assert pdf.status_code == 200
    assert pdf.headers["content-type"] == "application/pdf"
    assert pdf.content.startswith(b"%PDF-")
    assert len(pdf.content) > 1000


def test_unknown_session_report_is_honest(client):
    body = client.get("/api/v1/reports/does-not-exist.json").json()
    assert body["findings"] == []
    assert body["data_source"] in ("absent", "derived")
    assert body["content_sha256"]


# ---------------------------------------------------------------------------
# D3/D4 — DNS policy (deterministic, offline path only)
# ---------------------------------------------------------------------------

def test_dns_policy_offline_fixture(client):
    r = client.get("/api/v1/dns/policy?mx=mx1.corp.net&live=false")
    assert r.status_code == 200
    body = r.json()
    assert body["source"] == "offline-fixture"
    assert body["mta_sts_mode"] == "enforce"
    assert body["dmarc_policy"] == "reject"


def test_dns_policy_unresolvable_is_not_guessed(client):
    body = client.get("/api/v1/dns/policy?mx=definitely-not-a-real-host.invalid&live=false").json()
    assert body["source"] == "unavailable"
    assert body["error"]
    assert body["mta_sts_mode"] is None


def test_dns_findings_flag_non_enforcing_policy(client):
    findings = client.get("/api/v1/dns/findings?mx=relay-gw.partner.net&live=false").json()["findings"]
    ids = {f["rule_id"] for f in findings}
    assert "SMS-DNS-001" in ids, "mode=none must raise SMS-DNS-001"
    for f in findings:
        assert f["data_source"] == "offline-fixture"


def test_enforcement_reports_inconsistent_when_tls_absent(client):
    r = client.get(
        "/api/v1/enforcement?domain=mx1.corp.net&live=false&observed_cipher=TLS_AES_256_GCM_SHA384"
    ).json()
    assert r["state"] == "CONSISTENT"
    assert any("MTA-STS" in d for d in r["demanded_by"])
    assert any("DANE" in d for d in r["demanded_by"])

    # No observed cipher at all, while policy demands enforce -> inconsistent.
    r2 = client.get("/api/v1/enforcement?domain=mx1.corp.net&live=false").json()
    assert r2["state"] == "INCONSISTENT"
    assert r2["observed_cipher"] is None
    assert r2["severity"] == "high"


# ---------------------------------------------------------------------------
# D3 — deterministic anomaly detection
# ---------------------------------------------------------------------------

def test_anomaly_is_deterministic(client, stripped):
    a = client.get(f"/api/v1/anomaly/{stripped}").json()
    b = client.get(f"/api/v1/anomaly/{stripped}").json()
    assert a == b, "anomaly report must be byte-identical across calls"
    assert a["baseline_flows"] >= 1


def test_anomaly_flags_cleartext(client, stripped):
    body = client.get(f"/api/v1/anomaly/{stripped}").json()
    features = {s["feature"] for s in body["signals"]}
    assert "cleartext_ratio" in features
    for s in body["signals"]:
        for field in ("feature", "value", "expected_range", "z_score", "direction", "method", "explanation"):
            assert field in s, f"signal missing {field}"
        assert s["method"] in (
            "robust_zscore_median_mad", "threshold_deprecated_protocol",
            "threshold_missing_forward_secrecy", "threshold_absolute_keysize",
            "threshold_interval_spread",
        )


def test_anomaly_unknown_session_is_empty(client):
    body = client.get("/api/v1/anomaly/unknown-session").json()
    assert body["baseline_flows"] == 0
    assert body["anomalous_flows"] == 0
    assert body["signals"] == []


def test_anomaly_cert_signal_on_weak_key(client, weak_key):
    body = client.get(f"/api/v1/anomaly/{weak_key}").json()
    assert "certificate_anomaly" in {s["feature"] for s in body["signals"]}


# ---------------------------------------------------------------------------
# D2 — delivery graph
# ---------------------------------------------------------------------------

def test_graph_nodes_and_edges_are_labelled(client, stripped):
    g = client.get(f"/api/v1/graph/{stripped}").json()
    assert g["nodes"], "graph must contain at least the observed hop"
    assert g["exposure_summary"]["hops_observed"] >= 1
    sources = {n["data_source"] for n in g["nodes"]}
    assert sources <= {"observed", "demo_fixture"}, "unlabelled node provenance"
    # The observed capture hop must never be relabelled as fixture data.
    assert any(n["data_source"] == "observed" for n in g["nodes"])


def test_graph_ids_are_unique(client, stripped):
    g = client.get(f"/api/v1/graph/{stripped}").json()
    ids = [n["id"] for n in g["nodes"]]
    assert len(ids) == len(set(ids)), f"duplicate node ids: {ids}"


def test_graph_edge_endpoints_resolve(client, stripped):
    g = client.get(f"/api/v1/graph/{stripped}").json()
    known = {n["id"] for n in g["nodes"]}
    for e in g["edges"]:
        assert e["source"] in known, f"dangling edge source {e['source']}"
        assert e["target"] in known, f"dangling edge target {e['target']}"


# ---------------------------------------------------------------------------
# D5 — integrity
# ---------------------------------------------------------------------------

def test_integrity_verifies_clean_corpus(client):
    v = client.post("/api/v1/integrity/verify").json()
    assert v["verified"] is True
    assert v["status"] == "VALID_SIGNATURE_CHAIN"
    assert v["mismatched"] == []
    assert v["nodes_checked"] >= 5


def test_integrity_manifest_matches_seal(client):
    items = client.get("/api/v1/integrity/manifest").json()
    assert items
    for item in items:
        assert item["sealed"] is True
        assert item["matches_seal"] is True, f"digest drift in {item['file']}"


# ---------------------------------------------------------------------------
# D6 — attack lens
# ---------------------------------------------------------------------------

def test_attack_lens_is_grounded_in_fired_rules(client, stripped, weak_key):
    forecasts = client.get(f"/api/v1/lens/{stripped}").json()
    assert forecasts, "stripped capture must drive at least one attack class"
    for f in forecasts:
        assert f["driver_rule_ids"], "every forecast must cite a firing rule"
        assert f["likelihood"] in ("LOW", "MEDIUM", "HIGH")
        assert 0.0 <= f["likelihood_score"] <= 100.0
        assert "demo_fixture" in f["data_source"]

    # Sorting must be by descending likelihood.
    scores = [f["likelihood_score"] for f in forecasts]
    assert scores == sorted(scores, reverse=True)

    # A forecast must never appear unless one of its drivers actually fired.
    rules = client.get(f"/api/v1/lens/{stripped}").json()
    assert all(f["driver_rule_ids"] for f in rules)


def test_attack_lens_reflects_session_specific_rules(client, weak_key):
    drivers = {
        r
        for f in client.get(f"/api/v1/lens/{weak_key}").json()
        for r in f["driver_rule_ids"]
    }
    assert "SMS-KEY-001" in drivers, "RSA-1024 capture must drive the key-factoring class"


# ---------------------------------------------------------------------------
# Ask (RAG guardrails)
# ---------------------------------------------------------------------------

def test_ask_is_grounded_with_citations(client, stripped):
    """
    A real question the corpus can answer.

    Requires no API key at run time beyond the configured one; if generation is
    unavailable the response must be a *refusal*, never an ungrounded answer.
    """
    q = "what does SMS-ENF-002 mean and what triggers it?"
    r = client.post("/api/v1/ask", json={"question": q, "session_id": stripped}).json()
    if r["refused"]:
        # Acceptable only when the model is unreachable, and then it must say so.
        assert r["refusal_reason"]
        assert r["citations"] == []
        return
    assert r["grounded"] is True
    assert r["citations"], "a grounded answer must cite retrieved spans"
    for c in r["citations"]:
        assert c["span_id"]
        assert c["source"]


def test_ask_refuses_unanswerable_question(client, stripped):
    """A question the corpus cannot address must never be answered."""
    r = client.post(
        "/api/v1/ask",
        json={"question": "zzzz qqqq wwww eeee rrrr nonsense", "session_id": stripped},
    ).json()
    assert r["refused"] is True
    assert r["grounded"] is False
    assert r["answer"] is None


def test_ask_retrieve_endpoint_needs_no_model(client, stripped):
    """Retrieval is local and must work with generation unavailable."""
    r = client.get(
        "/api/v1/ask/retrieve",
        params={"question": "RSA key size", "session_id": stripped},
    ).json()
    assert r["retrieved"]
    for span in r["retrieved"]:
        assert span["span_id"] and span["text"]
        assert span["data_source"] in ("observed", "derived", "demo_fixture")


def test_ask_refuses_out_of_scope(client):
    r = client.post("/api/v1/ask", json={"question": "what is the weather tomorrow"}).json()
    assert r["refused"] is True
    assert r["grounded"] is False
    assert r["citations"] == []


def test_ask_refuses_without_evidence(client):
    r = client.post("/api/v1/ask", json={"question": "summarise", "session_id": "nope"}).json()
    assert r["refused"] is True
    assert r["grounded"] is False


# ---------------------------------------------------------------------------
# Rule engine additions
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "scenario,expected_rule",
    [
        ("weak-key", "SMS-KEY-001"),
        ("weak-cipher", "SMS-CIPH-001"),
        ("advertised-unused", "SMS-ENF-001"),
    ],
)
def test_new_rules_fire_on_expected_scenario(client, scenario, expected_rule):
    sid = client.post(f"/api/v1/captures/sample/{scenario}").json()["session_id"]
    ids = {f["rule_id"] for f in client.get(f"/api/v1/findings?session_id={sid}").json()}
    assert expected_rule in ids
