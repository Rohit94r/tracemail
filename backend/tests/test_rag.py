"""
SIH26159 SecureMailScope — RAG regression tests.

Split deliberately:

* **offline tests** always run. They cover retrieval, the cite-or-refuse
  verifier, and the guardrails, using a stub model so no network call and no
  API key is required.
* **live tests** are skipped unless GROQ_API_KEY is set. They confirm the real
  endpoint still answers in a grounded, cited form.

The verifier is the security control here, so it is tested adversarially: an
uncited claim, a fabricated citation, and a claim that contradicts its cited
source must all be rejected.
"""

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from backend.app.modules.rag import retriever  # noqa: E402
from backend.app.modules.rag import generator  # noqa: E402

SPANS = [
    {"span_id": "RFC3207-S4.2", "source": "RFC 3207 §4.2",
     "text": ("An active network attacker can inject a rogue STARTTLS command into "
              "the plaintext stream, causing clients to abort the connection or to "
              "send the session traffic in the clear, thereby stealing authentication "
              "information such as the user's username and password."),
     "data_source": "derived"},
    {"span_id": "NIST-SP800-52", "source": "NIST SP 800-52",
     "text": ("For a security strength of 112 bits or more, RSA public keys should "
              "be at least 2048 bits. Symmetric ciphers should provide forward secrecy."),
     "data_source": "derived"},
]


# ---------------------------------------------------------------------------
# Retrieval
# ---------------------------------------------------------------------------

def test_corpus_is_populated():
    spans = retriever.build_corpus()
    assert len(spans) > 20
    ids = {s.span_id for s in spans}
    assert "RFC3207-S4.2" in ids
    assert any(i.startswith("RUBRIC-SMS-") for i in ids), "rubric rows must be indexed"


def test_rubric_rows_are_indexed():
    rows = [s for s in retriever.build_corpus() if s.span_id == "RUBRIC-SMS-ENF-002"]
    assert rows, "SMS-ENF-002 must be retrievable"
    assert "stripped" in rows[0].text


def test_retrieval_ranks_the_right_span_first():
    hits = retriever.retrieve("rogue STARTTLS injection steals password", k=3)
    assert hits
    assert hits[0]["span_id"] == "RFC3207-S4.2"


def test_retrieval_finds_rubric_semantics():
    hits = retriever.retrieve("what triggers SMS-ENF-002?", k=3)
    assert any(h["span_id"] == "RUBRIC-SMS-ENF-002" for h in hits)


def test_retrieval_is_deterministic():
    a = retriever.retrieve("minimum RSA key size", k=5)
    b = retriever.retrieve("minimum RSA key size", k=5)
    assert [h["span_id"] for h in a] == [h["span_id"] for h in b]
    assert [h["score"] for h in a] == [h["score"] for h in b]


def test_retrieval_returns_nothing_for_unrelated_query():
    assert retriever.retrieve("zzzqqq nonexistent gibberish token", k=3) == []


# ---------------------------------------------------------------------------
# Cite-or-refuse verifier (the security control)
# ---------------------------------------------------------------------------

def test_verifier_keeps_a_supported_sentence():
    kept, rejected = generator._verify(
        ["An active network attacker can inject a rogue STARTTLS command [RFC3207-S4.2]."],
        SPANS,
    )
    assert len(kept) == 1
    assert rejected == []


def test_verifier_rejects_uncited_sentence():
    kept, rejected = generator._verify(
        ["An attacker can steal the password."], SPANS
    )
    assert kept == []
    assert rejected and rejected[0]["reason"] == "no citation"


def test_verifier_rejects_fabricated_citation():
    kept, rejected = generator._verify(
        ["The key must be 4096 bits [RFC9999-XX]."], SPANS
    )
    assert kept == []
    assert "unknown span" in rejected[0]["reason"]


def test_verifier_rejects_claim_absent_from_its_citation():
    kept, rejected = generator._verify(
        ["The message body is stored in cleartext on the relay [NIST-SP800-52]."], SPANS
    )
    assert kept == []
    assert rejected, "a claim not present in the cited span must be dropped"


def test_verifier_drops_only_the_bad_sentence():
    kept, rejected = generator._verify(
        [
            "An active network attacker can inject a rogue STARTTLS command [RFC3207-S4.2].",
            "The moon is made of green cheese [NIST-SP800-52].",
        ],
        SPANS,
    )
    assert len(kept) == 1
    assert len(rejected) == 1


def test_verifier_refuses_when_nothing_survives():
    kept, _ = generator._verify(["Completely unrelated claim [RFC3207-S4.2]."], SPANS)
    assert kept == [], "if no sentence is grounded the answer must be a refusal"


def test_verifier_ignores_zero_width_and_lenticular_brackets():
    dirty = (
        "An active network attacker can inject a rogue STARTTLS command "
        "[\u200bRFC3207\u2011S4.2\u3011]."
    )
    kept, _ = generator._verify([generator._clean(dirty)], SPANS)
    assert len(kept) == 1, "model formatting quirks must not silently break grounding"


def test_citations_are_deduplicated_and_resolvable():
    kept, _ = generator._verify(
        ["An active network attacker can inject a rogue STARTTLS command [RFC3207-S4.2]. "
         "The same is true of credentials [RFC3207-S4.2]."],
        SPANS,
    )
    cites = generator._citations(kept, SPANS)
    assert [c["span_id"] for c in cites] == ["RFC3207-S4.2"]


# ---------------------------------------------------------------------------
# Refusal paths without a model
# ---------------------------------------------------------------------------

def test_answer_refuses_without_api_key(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    res = generator.answer("rogue STARTTLS command injection steals the password")
    assert res["refused"] is True
    assert res["grounded"] is False
    assert "GROQ_API_KEY" in res["reason"]


def test_answer_refuses_when_retrieval_is_empty(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test-key-not-used")
    res = generator.answer("zzzqqq gibberish question with no corpus match")
    assert res["refused"] is True
    assert "no relevant evidence" in res["reason"]


def test_insufficient_evidence_marker_is_a_refusal(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test-key")

    class _Msg:
        content = "INSUFFICIENT_EVIDENCE"

    class _Choice:
        message = _Msg()

    class _Resp:
        choices = [_Choice()]

    class _Completions:
        def create(self, **kwargs):
            return _Resp()

    class _Chat:
        completions = _Completions()

    class _Client:
        chat = _Chat()

    monkeypatch.setattr(generator, "_groq_client", lambda: _Client())
    res = generator.answer("rogue STARTTLS command injection steals the password")
    assert res["refused"] is True
    assert "does not answer" in res["reason"]


# ---------------------------------------------------------------------------
# Live endpoint (opt-in)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    not os.getenv("GROQ_API_KEY"), reason="GROQ_API_KEY not set; skipping live RAG test"
)
def test_live_grounded_answer_is_cited():
    res = generator.answer("minimum recommended RSA public key size bits")
    assert res["refused"] is False, res.get("reason")
    assert res["grounded"] is True
    assert res["citations"], "a grounded answer must carry citations"
    for c in res["citations"]:
        assert c["span_id"]
    assert "[NIST-SP800-52]" in res["answer"] or "[RUBRIC-SMS-KEY-001]" in res["answer"]


@pytest.mark.skipif(
    not os.getenv("GROQ_API_KEY"), reason="GROQ_API_KEY not set; skipping live RAG test"
)
def test_live_out_of_scope_is_refused():
    res = generator.answer("zzzz qqqq wwww football championship winner")
    assert res["refused"] is True
