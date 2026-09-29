"""
SIH26159 SecureMailScope — MongoDB Database Integration
Connects directly to MongoDB Atlas cluster (vastraq) with resilient fallback and automated indexing.
"""

from __future__ import annotations
import logging
from typing import Any, Dict, List, Optional
from pymongo import MongoClient
from pymongo.database import Database
from .config import MONGO_URI, MONGO_DB_NAME

logger = logging.getLogger("securemailscope.db")

_client: Optional[MongoClient] = None

def get_mongo_client() -> MongoClient:
    global _client
    if not MONGO_URI:
        raise RuntimeError(
            "MONGO_URI is not set. Copy .env.example to .env and fill it in."
        )
    if _client is None:
        _client = MongoClient(
            MONGO_URI,
            serverSelectionTimeoutMS=10000,
            connectTimeoutMS=10000,
            socketTimeoutMS=10000,
        )
    return _client

def get_db() -> Database:
    client = get_mongo_client()
    return client[MONGO_DB_NAME]

def init_db() -> bool:
    try:
        db = get_db()
        # Verify connection with ping
        db.command("ping")
        # Ensure indexes on raven collections
        db.raven_sessions.create_index("id", unique=True)
        db.raven_findings.create_index([("session_id", 1), ("rule_id", 1)])
        db.raven_flows.create_index("session_id")
        db.raven_scores.create_index("session_id")
        logger.info("Successfully connected and indexed MongoDB Atlas database '%s'", MONGO_DB_NAME)
        return True
    except Exception as e:
        logger.warning("MongoDB Atlas initialization warning: %s. Operating with local fallback.", e)
        return False

def ping_db() -> bool:
    try:
        db = get_db()
        db.command("ping")
        return True
    except Exception:
        return False

# Database Persistence Helpers for Sessions, Findings, and Scores
def save_db_session(session_data: Dict[str, Any]) -> None:
    try:
        db = get_db()
        clean = {k: v for k, v in session_data.items() if k != "_id"}
        db.raven_sessions.update_one({"id": clean["id"]}, {"$set": clean}, upsert=True)
    except Exception as e:
        logger.warning("Could not persist session to MongoDB: %s", e)

def get_db_sessions() -> List[Dict[str, Any]]:
    try:
        db = get_db()
        cursor = db.raven_sessions.find({}, {"_id": 0}).sort("started_at", -1)
        return list(cursor)
    except Exception as e:
        logger.warning("Could not list sessions from MongoDB: %s", e)
        return []

def save_db_findings(session_id: str, findings: List[Any]) -> None:
    try:
        db = get_db()
        docs = []
        for f in findings:
            if hasattr(f, "model_dump"):
                item = f.model_dump()
            elif hasattr(f, "dict"):
                item = f.dict()
            else:
                item = dict(f)
            clean = {k: v for k, v in item.items() if k != "_id"}
            clean["session_id"] = session_id
            docs.append(clean)
        if docs:
            db.raven_findings.delete_many({"session_id": session_id})
            db.raven_findings.insert_many(docs)
    except Exception as e:
        logger.warning("Could not persist findings to MongoDB: %s", e)

def get_db_findings(session_id: str) -> List[Dict[str, Any]]:
    try:
        db = get_db()
        cursor = db.raven_findings.find({"session_id": session_id}, {"_id": 0})
        return list(cursor)
    except Exception as e:
        logger.warning("Could not load findings from MongoDB: %s", e)
        return []

def save_db_posture(session_id: str, mx_scores: List[Any]) -> None:
    try:
        db = get_db()
        docs = []
        for m in mx_scores:
            if hasattr(m, "model_dump"):
                item = m.model_dump()
            elif hasattr(m, "dict"):
                item = m.dict()
            else:
                item = dict(m)
            clean = {k: v for k, v in item.items() if k != "_id"}
            clean["session_id"] = session_id
            docs.append(clean)
        if docs:
            db.raven_scores.delete_many({"session_id": session_id})
            db.raven_scores.insert_many(docs)
    except Exception as e:
        logger.warning("Could not persist scores to MongoDB: %s", e)

def get_db_posture(session_id: str) -> List[Dict[str, Any]]:
    try:
        db = get_db()
        cursor = db.raven_scores.find({"session_id": session_id}, {"_id": 0})
        return list(cursor)
    except Exception as e:
        logger.warning("Could not load scores from MongoDB: %s", e)
        return []

if __name__ == "__main__":
    success = init_db()
    print(f"MongoDB Atlas initialization: {'SUCCESS' if success else 'FAILED'}")
