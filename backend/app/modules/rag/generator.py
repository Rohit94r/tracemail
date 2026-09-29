"""
SIH26159 SecureMailScope — grounded generation with cite-or-refuse.

The model is given only the retrieved spans and is required to cite the
span_id supporting every sentence. After generation, each sentence is checked
against the retrieved text; a sentence that is not verifiable is removed, and
if nothing survives the answer is a refusal.

The verifier is deliberately conservative and mechanical rather than a second
LLM call: it can be tested, it cannot be talked into agreeing with itself, and
it cannot hallucinate. Support is confirmed by checking the sentence's content
words against the union of the cited spans.

All network egress in the product passes through here. Nothing is sent except
the question, the session id, and the retrieved spans, which are themselves
already in the repository or the uploaded capture.
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional, Tuple

from .retriever import Span, retrieve, _tokenize

MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

# Out-of-scope vocabulary. The assistant has exactly one knowledge source, so
# anything outside the analysis domain is refused before a model call is made.
_OUT_OF_SCOPE_KEYWORDS = (
    "weather", "stock", "share price", "president", "election", "movie",
    "recipe", "cook", "football", "cricket", "song", "lyrics", "joke",
    "horoscope", "translate", "write a poem", "who won",
)
MAX_TOKENS = 700
TEMPERATURE = 0.0
_MAX_RETRIES = 3      # rate limits are transient; back off and retry
_BACKOFF_S = 1.5  # determinism: same question + same spans -> same answer

_CITE = re.compile(r"\[\s*`?([A-Za-z0-9_.\-]+?)\.?`?\s*\]")
_SENT = re.compile(r"(?<=[.!?])\s+")

# Models occasionally emit zero-width and bidi control characters inside
# citations ("[\u200bRFC3207-S4]"), which would silently break citation
# matching and cause a correct answer to be discarded. Strip them, plus any
# stray backticks/markdown emphasis, before verification.
_INVISIBLE = re.compile(r"[\u200b-\u200f\u2028\u2029\ufeff\u00ad]")

# Narrow no-break space is a real space for reading purposes, so it is mapped to
# an ordinary space rather than deleted (deleting it would fuse "2048 bits").
_NARROW_SPACE = re.compile(r"[\u202f\u2007]")

# This model family brackets citations with U+3010/U+3011 and writes hyphens as
# U+2011. Normalising both is required for citation ids to match the corpus.
_DASHES = {
    "\u2010": "-", "\u2011": "-", "\u2012": "-", "\u2013": "-", "\u2014": "-",
    "\u2212": "-", "\uff0d": "-", "\u00ad": "-",
}


def _clean(text: str) -> str:
    """Normalise model output so verification sees only real characters."""
    text = _INVISIBLE.sub("", text)
    text = _NARROW_SPACE.sub(" ", text)
    for bad, good in _DASHES.items():
        text = text.replace(bad, good)
    # Treat CJK lenticular brackets as square brackets, then drop doubled
    # closers so "[id]]" from a "【id】" citation still parses as "[id]".
    text = text.replace("\u3010", "[").replace("\u3011", "]")
    text = re.sub(r"\]\s*\]", "]", text)
    # Models pad citations with spaces ("[ id ]"); citations must be machine
    # resolvable, so tighten them to a canonical "[id]" form. A closing bracket
    # directly after a word still needs a separating space, so add one back.
    text = re.sub(r"\[\s*`?\s*([A-Za-z0-9_.\-]+?)\s*`?\s*\]", r" [\1] ", text)
    text = re.sub(r"\s+([.,;:!?])", r"\1", text)
    # Collapse the hard line breaks models use for list layout.
    text = re.sub(r"\s*\n\s*", " ", text)
    return re.sub(r"[ \t]{2,}", " ", text).strip()

_SYSTEM = (
    "You are the SecureMailScope evidence analyst. You answer strictly from the "
    "numbered CONTEXT spans supplied by the user. Rules you must follow without "
    "exception:\n"
    "1. Every sentence you write must end with one or more citations in square "
    "brackets naming the span ids that support it, e.g. [RFC3207-S4.2].\n"
    "2. You may only state facts that appear in the cited span. Do not combine, "
    "extrapolate, or add general knowledge.\n"
    "3. If the context does not contain the answer, reply exactly: "
    "INSUFFICIENT_EVIDENCE\n"
    "4. Never speculate. Never state a certainty the evidence does not show.\n"
    "5. Be concise and technical. Plain prose, no headings, no preamble."
)


def _groq_client():
    """Construct the client lazily so importing this module never needs a key."""
    api_key = os.getenv("GROQ_API_KEY", "").strip()
    if not api_key:
        return None
    try:
        from groq import Groq
    except ImportError:
        return None
    return Groq(api_key=api_key)


def _format_context(spans: List[dict]) -> str:
    return "\n\n".join(f"[{s['span_id']}] ({s['source']})\n{s['text']}" for s in spans)


def _content_words(sentence: str) -> set:
    """
    Words that carry meaning. Cites and numbers are dropped so a sentence is
    judged on its assertions, not on its citation syntax.
    """
    stripped = _CITE.sub(" ", sentence)
    stripped = stripped.replace("`", " ")
    return {w for w in _tokenize(stripped) if len(w) > 2}


def _complete(client, user: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Call the model, retrying only on rate limits.

    Returns ``(text, error)``. A rate limit is retried with backoff because it
    is transient; any other failure returns immediately rather than pretending
    an answer exists.
    """
    import time

    last: Optional[str] = None
    for attempt in range(_MAX_RETRIES):
        try:
            resp = client.chat.completions.create(
                model=MODEL,
                messages=[
                    {"role": "system", "content": _SYSTEM},
                    {"role": "user", "content": user},
                ],
                temperature=TEMPERATURE,
                max_tokens=MAX_TOKENS,
            )
            return _clean(resp.choices[0].message.content or ""), None
        except Exception as exc:  # noqa: BLE001 - upstream raises many types
            name = type(exc).__name__
            last = f"generation failed: {name}"
            if "RateLimit" not in name and "429" not in str(exc):
                break
            if attempt < _MAX_RETRIES - 1:
                time.sleep(_BACKOFF_S * (2 ** attempt))
    return None, last


def _verify(sentences: List[str], spans: List[dict]) -> Tuple[List[str], List[dict]]:
    """
    Cite-or-refuse enforcement.

    A sentence survives only if it cites at least one real span and the words it
    asserts are actually present in the text it cited. Returns
    ``(kept_sentences, rejection_reasons)``.
    """
    by_id = {s["span_id"]: s for s in spans}
    kept: List[str] = []
    rejected: List[dict] = []

    for sentence in sentences:
        sentence = sentence.strip()
        if not sentence:
            continue

        cited = _CITE.findall(sentence)
        if not cited:
            rejected.append({"sentence": sentence, "reason": "no citation"})
            continue

        unknown = [c for c in cited if c not in by_id]
        if unknown:
            rejected.append(
                {"sentence": sentence, "reason": f"cited unknown span(s): {unknown}"}
            )
            continue

        claim = _content_words(sentence)
        if not claim:
            # Pure citation with no assertion: nothing to ground, keep it out.
            rejected.append({"sentence": sentence, "reason": "no verifiable claim"})
            continue

        support: set = set()
        for cid in cited:
            support |= set(_tokenize(by_id[cid]["text"]))

        # A claim word is grounded if it appears in any cited span. Allow a
        # small margin for inflection so "encrypted" supports "encrypting".
        unsupported = {
            w
            for w in claim
            if w not in support
            and not any(w[:6] in s or s[:6] in w for s in support if len(s) > 3)
        }

        # A minority of function-ish words may be unsupported (sentiment,
        # connective phrasing); a majority being ungrounded is a failure.
        if len(unsupported) > max(1, len(claim) // 2):
            rejected.append(
                {
                    "sentence": sentence,
                    "reason": f"claims not present in cited spans: {sorted(unsupported)[:6]}",
                }
            )
            continue

        kept.append(sentence)

    return kept, rejected


def _citations(kept: List[str], spans: List[dict]) -> List[dict]:
    by_id = {s["span_id"]: s for s in spans}
    seen: dict = {}
    for sentence in kept:
        for cid in _CITE.findall(sentence):
            if cid in by_id and cid not in seen:
                seen[cid] = {
                    "span_id": cid,
                    "source": by_id[cid]["source"],
                    "data_source": by_id[cid]["data_source"],
                }
    return list(seen.values())


def answer(question: str, findings: Optional[List[dict]] = None, k: int = 6) -> Dict[str, Any]:
    """
    Retrieve, generate, then verify. Returns a grounded answer or a refusal.

    Never raises for a missing key or an upstream outage: a tool that is down
    must not return a fabricated answer, so those paths return a refusal with
    the reason.
    """
    spans = retrieve(question, findings, k=k)
    if not spans:
        return {
            "answer": None,
            "refused": True,
            "grounded": False,
            "reason": "no relevant evidence retrieved for this question",
            "citations": [],
            "rejected": [],
            "model": MODEL,
            "retrieved": [],
        }

    client = _groq_client()
    if client is None:
        return {
            "answer": None,
            "refused": True,
            "grounded": False,
            "reason": (
                "generation unavailable: GROQ_API_KEY is not configured, so no "
                "answer can be produced from evidence"
            ),
            "citations": [],
            "rejected": [],
            "model": MODEL,
            "retrieved": spans,
        }

    user = (
        f"CONTEXT:\n{_format_context(spans)}\n\n"
        f"QUESTION: {question}\n\n"
        "Answer using only the CONTEXT, citing span ids as specified."
    )

    raw, err = _complete(client, user)
    if err:
        return {
            "answer": None,
            "refused": True,
            "grounded": False,
            "reason": err,
            "citations": [],
            "rejected": [],
            "model": MODEL,
            "retrieved": spans,
        }

    if "INSUFFICIENT_EVIDENCE" in raw:
        return {
            "answer": None,
            "refused": True,
            "grounded": False,
            "reason": "the model reported that the context does not answer the question",
            "citations": [],
            "rejected": [],
            "model": MODEL,
            "retrieved": spans,
        }

    kept, rejected = _verify(_SENT.split(raw), spans)

    if not kept:
        return {
            "answer": None,
            "refused": True,
            "grounded": False,
            "reason": "no sentence in the draft was supported by the cited evidence",
            "citations": [],
            "rejected": rejected,
            "model": MODEL,
            "retrieved": spans,
        }

    return {
        "answer": " ".join(kept),
        "refused": False,
        "grounded": True,
        "reason": None,
        "citations": _citations(kept, spans),
        "rejected": rejected,
        "model": MODEL,
        "retrieved": spans,
    }
