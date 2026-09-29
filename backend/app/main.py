"""
SIH26159 SecureMailScope — Main FastAPI Application
Mounts all /api/v1 routers, CORS middleware, and WebSocket /ws/live feed.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import asyncio
import os

from .db import init_db
from .api import health, captures, mx, graph, findings, reports, ask, lens, integrity, dns

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(
    title="Raven SecureMailScope API",
    description="Passive Cryptographic Security Posture Assessment Platform (SIH26159)",
    version="1.4.0",
    lifespan=lifespan,
)

# CORS middleware for Next.js frontend.
# Origins are allowlisted — never "*" with credentials, which would let any
# website drive the API from a logged-in user's browser.
_ALLOWED_ORIGINS = [
    o.strip()
    for o in os.environ.get(
        "CORS_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000",
    ).split(",")
    if o.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

# Mount all routers
app.include_router(health.router)
app.include_router(captures.router)
app.include_router(mx.router)
app.include_router(graph.router)
app.include_router(findings.router)
app.include_router(reports.router)
app.include_router(ask.router)
app.include_router(lens.router)
app.include_router(integrity.router)
app.include_router(dns.router)

@app.websocket("/ws/live")
async def websocket_live_feed(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            # Push live heartbeat/chunk status
            await websocket.send_json({
                "type": "heartbeat",
                "net": "offline",
                "status": "listening",
                "package_ver": "v1.4.0-sih",
            })
            await asyncio.sleep(5)
    except WebSocketDisconnect:
        pass

if __name__ == "__main__":
    import uvicorn
    import os
    port = int(os.environ.get("PORT", 8001))
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=port, reload=True)
