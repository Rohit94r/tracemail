"""
SIH26159 SecureMailScope — Configuration & Pinned Radar Priors
Priors and rubric constants are pinned per docs/03-scoring-rubric.md §4.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Automatically load .env from project root if present
_env_path = Path(__file__).resolve().parent.parent.parent / ".env"
if _env_path.exists():
    load_dotenv(_env_path)

PACKAGE_VER = "v1.4.0-sih"

MONGO_URI = os.environ.get("MONGO_URI", "").strip()
MONGO_DB_NAME = os.environ.get("MONGO_DB_NAME", "platform").strip() or "platform"

# Credentials must never be hardcoded here. With no MONGO_URI the app starts in
# local-fallback mode and /api/v1/health reports db_ok=false.
if not MONGO_URI:
    import logging

    logging.getLogger("securemailscope.config").warning(
        "MONGO_URI is not set; starting without the remote evidence store. "
        "Copy .env.example to .env and set it to enable persistence."
    )

# Posture sub-score weights (Σ = 1.00)
WEIGHTS = {
    "protocol": 0.20,
    "cipher": 0.25,
    "key": 0.15,
    "x509": 0.15,
    "dns": 0.10,
    "enforce": 0.15,
}

# Downgrade Radar Bayesian Priors (pinned with literature citations)
# Source: IMC'15 "Neither Snow Nor Rain Nor MITM... An Empirical Study of Email Delivery Security"
PRIOR_P_STRIP = 0.20

# Probability of seeing no TLS following STARTTLS if an adversary stripped it
# Source: USENIX'21 EAST / Suricata machine counters
PROB_NO_TLS_GIVEN_STRIP = 0.90

# Probability of advertised-unused under benign/honest conditions (client policy choice)
PROB_UNUSED_GIVEN_HONEST = 0.25

# CT log drift prior for certificate mismatches
# Source: HotNets'25 "Toward Verifiable Mail Infrastructure"
PRIOR_CT_CERT_DRIFT = 0.05

# Confidence Floors
X509_TLS13_CONF_FLOOR = 0.15  # RFC 8446: Certificate message encrypted on wire
CIPHER_PROTO_DEFAULT_CONF = 0.90
ENFORCE_DNS_DEFAULT_CONF = 0.85
