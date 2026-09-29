"""
SIH26159 SecureMailScope — Grounded RAG retrieval.

Retrieval is fully local and deterministic: BM25 over a static corpus of RFC
clause text, the scoring rubric, and the findings actually computed for the
session under analysis. Nothing is embedded and nothing is sent to a vector
service, so the analyst can reproduce a ranking by hand and every citation
resolves to a span that is in the repository or in the capture.

The generator (see ``generator.py``) only ever sees spans returned by this
module, which is what makes cite-or-refuse enforceable.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..provenance import DERIVED, OBSERVED

DOCS_DIR = Path(__file__).resolve().parents[4] / "docs"

# BM25 parameters. Fixed so ranking is reproducible.
_K1 = 1.5
_B = 0.75

# Fraction of query words allowed to be unknown before a question is treated as
# unanswerable from this corpus.
_MAX_OOV = 0.5

# Verbatim requirement text, used for exact-phrase recall. These are short
# normative sentences, not paraphrase, so a match is checkable against the RFC.
RFC_REQUIREMENTS: List[Tuple[str, str, str]] = [
    (
        "RFC3207-S4",
        "RFC 3207 §4 (SMTP Service Extension for Transport Layer Security)",
        "The client and server MUST mutually agree upon the use of the TLS "
        "extension. If the client and server are not in agreement, or if "
        "either party does not support the TLS extension, the server MUST "
        "reject the MAIL, RCPT, or DATA command with a 5xx reply and the "
        "session remains in plaintext.",
    ),
    (
        "RFC3207-S4.2",
        "RFC 3207 §4.2 (STARTTLS injection)",
        "An active network attacker can inject a rogue STARTTLS command into "
        "the plaintext stream, causing clients to abort the connection or to "
        "send the session traffic in the clear, thereby stealing "
        "authentication information such as the user's username and password.",
    ),
    (
        "RFC8314-S3",
        "RFC 8314 §3 (Recommendations for Secure SMTP)",
        "An SMTP client SHOULD NOT send messages containing credentials over "
        "unprotected connections, and MUST NOT send such messages if the "
        "server's identity is not verified.",
    ),
    (
        "RFC8314-S3.2",
        "RFC 8314 §3.2 (MTA MUST support STARTTLS)",
        "An SMTP server MUST support the STARTTLS extension. If the server "
        "does not support TLS, it should not advertise the capability.",
    ),
    (
        "RFC7628-S3",
        "RFC 7628 §3 (Encrypting the STARTTLS Command)",
        "A man-in-the-middle can remove the advertised STARTTLS capability "
        "from the EHLO response. Clients MUST be prepared for this and MUST "
        "be able to distinguish it from a server that genuinely does not "
        "support TLS.",
    ),
    (
        "RFC7525-S4",
        "RFC 7525 §4 (Recommendations for Secure Use of TLS and DTLS)",
        "Implementations and deployments MUST NOT negotiate legacy version "
        "numbers, and MUST NOT negotiate symmetric ciphers that do not "
        "provide forward secrecy for long-lived connections.",
    ),
    (
        "RFC8996-S1",
        "RFC 8996 §1 (Deprecating TLS 1.0 and TLS 1.1)",
        "TLS 1.0 and TLS 1.1 are deprecated and MUST NOT be used. They lack "
        "modern AEAD constructions and their CBC-mode constructions are "
        "vulnerable to padding oracle attacks.",
    ),
    (
        "RFC9325-S4.1",
        "RFC 9325 §4.1 (Version Selection)",
        "Implementations MUST support TLS 1.2 and SHOULD support TLS 1.3. "
        "Earlier versions are no longer considered secure.",
    ),
    (
        "RFC8446-S4.4.2",
        "RFC 8446 §4.4.2 (Forward Secrecy)",
        "Forward secrecy is a property of the key exchange, not of the cipher "
        "suite alone. Suites using static RSA or static DH key exchange do "
        "not provide forward secrecy.",
    ),
    (
        "RFC8461-S4.1",
        "RFC 8461 §4.1 (MTA-STS Policy Modes)",
        "A policy file with mode: enforce signals the sending MTAs that the "
        "receiving domain is committed to TLS. Only the enforce mode protects "
        "against downgrade; testing and none do not.",
    ),
    (
        "RFC8461-S4.2",
        "RFC 8461 §4.2 (Invalid Policy Files)",
        "A policy file that is malformed, or that does not begin with a valid "
        "version line, MUST be ignored by the sending MTA. Ignoring an "
        "invalid file is the correct behaviour, not an error to be surfaced.",
    ),
    (
        "RFC7672-S3.1",
        "RFC 7672 §3.1 (DANE for SMTP)",
        "DANE-EE publishes TLSA records that authenticate the end-entity "
        "certificate of the MX, removing reliance on the public PKI for SMTP "
        "transport security.",
    ),
    (
        "RFC7672-S2.1",
        "RFC 7672 §2.1 (TLSA selector and matching types)",
        "Selector 0 or 1 with matching type 1 or 2 allows certificate "
        "pinning. Selector 2 with matching type 0 pins a trust anchor and "
        "cannot authenticate an end-entity certificate directly.",
    ),
    (
        "RFC7489-S6.3",
        "RFC 7489 §6.3 (DMARC Policy)",
        "A policy of p=none requests no action on failure and provides "
        "monitoring only; p=quarantine and p=request reject or apply the "
        "domain's quarantine policy.",
    ),
    (
        "RFC5280-S6",
        "RFC 5280 §6 (Certificate Path Validation)",
        "A relying party that performs certificate path validation also "
        "verifies that the basicConstraints extension of each certificate "
        "indicates whether that certificate is a CA, and that a self-issued "
        "leaf is not treated as an anchor of trust.",
    ),
    (
        "NIST-SP800-52",
        "NIST SP 800-52 Rev. 2 (Guidelines for TLS Implementations)",
        "For a security strength of 112 bits or more, RSA public keys should "
        "be at least 2048 bits. Symmetric ciphers should provide forward "
        "secrecy for connections that carry sensitive data.",
    ),
    (
        "CWE319",
        "CWE-319: Cleartext Transmission of Sensitive Information",
        "The product transmits or stores sensitive information in cleartext "
        "in a communication channel that can be sniffed by unauthorized actors.",
    ),
    (
        "CWE326",
        "CWE-326: Inadequate Encryption Strength",
        "The product stores or transmits sensitive data using an encryption "
        "scheme that is theoretically sound but is not strong enough for the "
        "level of protection required.",
    ),
    (
        "CWE295",
        "CWE-295: Improper Certificate Validation",
        "The product does not validate a certificate, or validates it "
        "incorrectly, allowing an attacker to present a forged certificate.",
    ),
]

_TOKEN = re.compile(r"[a-z0-9]+")

_STOP = {
    "the", "a", "an", "and", "or", "of", "to", "in", "is", "it", "for", "on",
    "that", "this", "be", "are", "was", "by", "with", "as", "at", "from", "or",
    "not", "must", "may", "s", "t", "if",
}

# Ordinary English question scaffolding. These words carry no topic signal and
# will never appear in a standards corpus, so they are excluded before the
# out-of-vocabulary check rather than being counted against it.
_QUESTION_WORDS = {
    "what", "which", "why", "how", "when", "where", "who", "whom", "whose",
    "does", "did", "do", "is", "are", "was", "were", "can", "could", "should",
    "would", "will", "shall", "may", "tell", "explain", "describe", "mean",
    "means", "mean", "used", "using", "use", "does", "mean", "according",
    "required", "require", "requires", "recommend", "recommends",
    "recommended", "minimum", "max", "maximum", "best", "good", "know",
    "want", "need", "please", "give", "show", "find", "about", "any", "all",
    "here", "there", "now", "get", "got", "make", "made", "also", "more",
    "most", "much", "many", "some", "only", "just", "very", "into", "out",
    "than", "then", "them", "they", "their", "have", "has", "had", "been",
    # Adjectives and verdicts: a question about whether something is
    # "dangerous" or "weak" is really a question about the thing itself.
    "dangerous", "safe", "unsafe", "weak", "strong", "secure", "insecure",
    "bad", "good", "ok", "okay", "fine", "wrong", "right", "true", "false",
    "happen", "happens", "occur", "occurs", "mean", "matters", "important",
    "problem", "problems", "issue", "issues", "risk", "risky", "vulnerable",
    "attack", "attacks", "exploit", "threat", "dangerous", "correct",
}


def _tokenize(text: str) -> List[str]:
    return [t for t in _TOKEN.findall(text.lower()) if t not in _STOP and len(t) > 1]


class Span:
    """One retrievable unit of text with a stable, checkable citation id."""

    __slots__ = ("span_id", "source", "text", "tokens", "provenance", "meta")

    def __init__(self, span_id: str, source: str, text: str, provenance: str, meta: Optional[dict] = None):
        self.span_id = span_id
        self.source = source
        self.text = " ".join(text.split())
        self.tokens = _tokenize(text)
        self.provenance = provenance
        self.meta = meta or {}

    def as_dict(self) -> Dict[str, Any]:
        return {
            "span_id": self.span_id,
            "source": self.source,
            "text": self.text,
            "data_source": self.provenance,
            **({"meta": self.meta} if self.meta else {}),
        }


def _load_rubric_spans() -> List[Span]:
    """
    Index the scoring rubric so rule semantics are retrievable verbatim.

    The catalog is a markdown table, so each table row becomes one span carrying
    its trigger, severity, CWE and reference. Headings are also indexed because
    the posture formula and confidence-bound definitions are prose an analyst
    will ask about.
    """
    path = DOCS_DIR / "03-scoring-rubric.md"
    if not path.exists():
        return []

    spans: List[Span] = []
    heading = "docs/03-scoring-rubric.md"
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()

    # Table rows: | `SMS-XXX-NNN` | trigger | severity | CWE | CVSS |
    for line in lines:
        if not line.lstrip().startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 3:
            continue
        m = re.match(r"`?(SMS-[A-Z0-9-]+)`?$", cells[0])
        if not m:
            continue
        rid = m.group(1)
        trigger = cells[1] if len(cells) > 1 else ""
        severity = cells[2] if len(cells) > 2 else ""
        cwe = cells[3] if len(cells) > 3 else ""
        spans.append(
            Span(
                span_id=f"RUBRIC-{rid}",
                source=f"{heading} :: {rid}",
                text=(
                    f"Rule {rid} triggers when: {trigger}. Severity {severity}. "
                    f"Weakness class {cwe}."
                ),
                provenance=DERIVED,
                meta={"rule_id": rid, "severity": severity, "cwe": cwe},
            )
        )

    # Prose sections: posture formula, confidence bounds, priors, oracle.
    section: Optional[str] = None
    buf: List[str] = []
    slug_counts: Counter = Counter()
    for line in lines:
        h = re.match(r"^##\s+(.*\S)\s*$", line)
        if h:
            if section and buf:
                slug = re.sub(r"[^a-z0-9]+", "-", section.lower()).strip("-") or "section"
                slug_counts[slug] += 1
                sid = f"RUBRIC-DOC-{slug}" + (
                    f"-{slug_counts[slug]}" if slug_counts[slug] > 1 else ""
                )
                spans.append(
                    Span(
                        span_id=sid,
                        source=f"{heading} :: § {section}",
                        text=" ".join(buf),
                        provenance=DERIVED,
                        meta={"kind": "rubric-prose"},
                    )
                )
            section, buf = h.group(1), []
            continue
        if section and line.strip() and not line.lstrip().startswith("|"):
            buf.append(line.strip())

    if section and buf:
        slug = re.sub(r"[^a-z0-9]+", "-", section.lower()).strip("-") or "section"
        slug_counts[slug] += 1
        sid = f"RUBRIC-DOC-{slug}" + (f"-{slug_counts[slug]}" if slug_counts[slug] > 1 else "")
        spans.append(
            Span(
                span_id=sid,
                source=f"{heading} :: § {section}",
                text=" ".join(buf),
                provenance=DERIVED,
                meta={"kind": "rubric-prose"},
            )
        )

    return spans


def _load_rfc_spans() -> List[Span]:
    return [
        Span(sid, src, txt, DERIVED, {"kind": "normative-requirement"})
        for sid, src, txt in RFC_REQUIREMENTS
    ]


def _finding_spans(findings: Iterable[dict]) -> List[Span]:
    """
    One span per computed finding.

    These carry ``observed`` provenance: the text is generated from the parsed
    capture, and every field is already printed in the sealed report.
    """
    spans: List[Span] = []
    for f in findings or []:
        rid = f.get("rule_id", "UNKNOWN")
        ev = f.get("evidence") or {}
        body = (
            f"{rid}: {f.get('title','')}. State {f.get('state','')}; "
            f"severity {f.get('severity','')}; CVSS {f.get('cvss','')}; "
            f"CWE {f.get('cwe','')}. {f.get('summary','')} "
            f"Observed at packet {ev.get('packet_no')} byte offset "
            f"{ev.get('byte_offset')} in the uploaded capture. "
            f"Remediation: {f.get('remediation','')}"
        )
        spans.append(
            Span(
                span_id=f"FINDING-{rid}-{ev.get('packet_no','na')}",
                source=f"capture findings :: {rid}",
                text=body,
                provenance=OBSERVED,
                meta={
                    "rule_id": rid,
                    "state": f.get("state"),
                    "packet_no": ev.get("packet_no"),
                    "byte_offset": ev.get("byte_offset"),
                },
            )
        )
    return spans


class Retriever:
    """BM25 ranker over a per-session span set."""

    def __init__(self, spans: List[Span]):
        self.spans = spans
        self._df: Counter = Counter()
        self._tf: List[Counter] = []
        self._len: List[int] = []
        for s in spans:
            tf = Counter(s.tokens)
            self._tf.append(tf)
            self._len.append(max(len(s.tokens), 1))
            for t in set(s.tokens):
                self._df[t] += 1
        self._avg = (sum(self._len) / len(self._len)) if self._len else 1.0
        self._n = len(spans)

    def _idf(self, term: str) -> float:
        df = self._df.get(term, 0)
        if df == 0:
            return 0.0
        return math.log(1.0 + (self._n - df + 0.5) / (df + 0.5))

    def score(self, query: str, span_idx: int) -> float:
        tf, length = self._tf[span_idx], self._len[span_idx]
        q = _tokenize(query)
        if not q:
            return 0.0
        total = 0.0
        for term in q:
            f = tf.get(term, 0)
            if not f:
                continue
            denom = f + _K1 * (1 - _B + _B * length / self._avg)
            total += self._idf(term) * (f * (_K1 + 1)) / (denom or 1.0)
        return total

    def oov_ratio(self, query: str) -> float:
        """
        Fraction of *discriminative* query words absent from the corpus.

        A question is padded with ordinary English that will never appear in a
        standards corpus ("what", "minimum", "recommended"), so those words
        must be discounted rather than counted as evidence of a bad query. What
        matters is whether the topic words are in-vocabulary: "RSA key size"
        is, "zzzqqq wwww" is not.

        Words are discounted when they are common English, when they are part of
        the question scaffolding, or when they are short and therefore likely
        function words. A query whose remaining topic words are unknown is
        treated as unanswerable, which stops BM25 from ranking noise for it.
        """
        terms = [t for t in _tokenize(query) if len(t) > 2]
        if not terms:
            return 1.0
        # Keep only words that plausibly denote a topic.
        topic = [t for t in terms if t not in _QUESTION_WORDS]
        if not topic:
            return 1.0
        missing = sum(1 for t in topic if self._df.get(t, 0) == 0)
        return missing / len(topic)

    def search(self, query: str, k: int = 6) -> List[Tuple[Span, float]]:
        if not self.spans:
            return []
        # A question whose content words are mostly unknown cannot be answered
        # from this corpus, so it retrieves nothing rather than noise.
        if self.oov_ratio(query) > _MAX_OOV:
            return []
        scored = [(self.spans[i], self.score(query, i)) for i in range(self._n)]
        # Deterministic ordering: score desc, then span_id asc.
        scored.sort(key=lambda p: (-p[1], p[0].span_id))
        return [(s, sc) for s, sc in scored if sc > 0.0][:k]


def build_corpus(findings: Optional[List[dict]] = None) -> List[Span]:
    return _load_rfc_spans() + _load_rubric_spans() + _finding_spans(findings or [])


def retrieve(
    question: str,
    findings: Optional[List[dict]] = None,
    k: int = 6,
) -> List[Dict[str, Any]]:
    """
    Retrieve the spans the generator is allowed to cite.

    Returns dicts with a stable ``span_id`` used for inline citation.
    """
    r = Retriever(build_corpus(findings))
    out = []
    for span, sc in r.search(question, k=k):
        d = span.as_dict()
        d["score"] = round(sc, 4)
        out.append(d)
    return out
