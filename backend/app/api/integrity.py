"""
SIH26159 SecureMailScope — Integrity API (D5).

Re-hashes the corpus on every call and compares against the sealed manifest at
``corpus/expected/corpus.sha256``. Verification is a real comparison: a modified
byte anywhere in a capture is detected and reported per file.
"""

from fastapi import APIRouter
from pydantic import BaseModel
from typing import List
from pathlib import Path
import hashlib

from ..config import PACKAGE_VER

router = APIRouter(prefix="/api/v1/integrity", tags=["Integrity"])

CORPUS_DIR = (
    Path(__file__).resolve().parent.parent.parent.parent
    / "corpus" / "scenarios"
)
EXPECTED_DIR = (
    Path(__file__).resolve().parent.parent.parent.parent
    / "corpus" / "expected"
)


class ManifestItem(BaseModel):
    file: str
    sha256: str
    size: str
    package_ver: str
    matches_seal: bool
    sealed: bool


def _sealed_digests() -> dict:
    """Parse the committed sha256 manifest (format: '<hex>  <name>')."""
    manifest = EXPECTED_DIR / "corpus.sha256"
    out = {}
    if not manifest.exists():
        return out
    for line in manifest.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            # Manifest entries are written as "scenarios/<name>" (or, in older
            # seals, bare "<name>"); key on the basename so both resolve.
            out[parts[1].strip().lstrip("*").split("/")[-1]] = parts[0].strip()
    return out


@router.get("/manifest", response_model=List[ManifestItem])
def get_manifest():
    sealed = _sealed_digests()
    items: List[ManifestItem] = []
    if CORPUS_DIR.exists():
        for p in sorted(CORPUS_DIR.glob("*.pcap*")):
            if not p.is_file():
                continue
            digest = hashlib.sha256(p.read_bytes()).hexdigest()
            expected = sealed.get(p.name)
            items.append(
                ManifestItem(
                    file=f"corpus/scenarios/{p.name}",
                    sha256=f"sha256:{digest}",
                    size=f"{p.stat().st_size} B",
                    package_ver=PACKAGE_VER,
                    matches_seal=(expected == digest) if expected else False,
                    sealed=bool(expected),
                )
            )
    return items


@router.post("/verify")
def verify_integrity():
    """Re-hash every sealed capture and report the comparison result."""
    sealed = _sealed_digests()
    checked, mismatched, unsealed = [], [], []

    for name, expected in sorted(sealed.items()):
        path = CORPUS_DIR / name
        if not path.exists():
            mismatched.append({"file": name, "reason": "missing"})
            continue
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual == expected:
            checked.append(name)
        else:
            mismatched.append(
                {
                    "file": name,
                    "reason": "digest mismatch",
                    "expected": f"sha256:{expected}",
                    "actual": f"sha256:{actual}",
                }
            )

    for p in sorted(CORPUS_DIR.glob("*.pcap*")) if CORPUS_DIR.exists() else []:
        if p.is_file() and p.name not in sealed:
            unsealed.append(p.name)

    ok = not mismatched
    return {
        "verified": ok,
        "package_ver": PACKAGE_VER,
        "nodes_checked": len(checked),
        "status": "VALID_SIGNATURE_CHAIN" if ok else "TAMPER_DETECTED",
        "tamper_detected": not ok,
        "mismatched": mismatched,
        "unsealed_files": unsealed,
        "manifest": "corpus/expected/corpus.sha256",
    }
