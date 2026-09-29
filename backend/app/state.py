"""
SIH26159 SecureMailScope — Shared In-Memory Session & Findings Cache
Persists uploaded PCAPs and dynamically computed findings across API endpoints.
"""

from typing import Dict, Any, List

# Keyed by session_id
SESSION_CACHE: Dict[str, Dict[str, Any]] = {}
FINDINGS_CACHE: Dict[str, List[Any]] = {}
MX_CACHE: Dict[str, List[Any]] = {}
