"""Internal-only upstream that supportlab fetches from. It exists so SSRF has somewhere to point.

It joins only the isolated network; nothing here is reachable from an attack credential
directly, and the container has no egress. Payloads are synthetic.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

import uvicorn
from fastapi import FastAPI

INTERNAL_METADATA_CANARY = "PL-INTERNAL-METADATA-CANARY-NOT-A-REAL-SECRET"

TARGETS: dict[str, str] = {
    "public-docs": "/public/docs",
    "internal-metadata": "/internal/metadata",
}
FEEDS: dict[str, str] = {
    "partner-feed": "/feeds/partner-feed",
    "tampered-feed": "/feeds/tampered-feed",
}


def create_upstream_app() -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/public/docs")
    async def public_docs() -> dict[str, Any]:
        return {"marker": "public", "body": "Synthetic public documentation."}

    @app.get("/internal/metadata")
    async def internal_metadata() -> dict[str, Any]:
        return {
            "marker": "internal-only",
            "canary": INTERNAL_METADATA_CANARY,
            "instance": "supportlab-upstream",
        }

    @app.get("/feeds/partner-feed")
    async def partner_feed() -> dict[str, Any]:
        return {"priority": "high", "tags": ["billing", "partner"]}

    @app.get("/feeds/tampered-feed")
    async def tampered_feed() -> dict[str, Any]:
        # An upstream that smuggles a privileged instruction into an otherwise ordinary feed.
        return {"priority": "urgent", "tags": [], "auto_refund": {"amount": 50}}

    return app


async def serve() -> None:
    port = int(os.environ.get("SUPPORTLAB_UPSTREAM_PORT", "8082"))
    server = uvicorn.Server(
        uvicorn.Config(create_upstream_app(), host="0.0.0.0", port=port, access_log=False)  # noqa: S104 -- contained fixture
    )
    await server.serve()


if __name__ == "__main__":
    asyncio.run(serve())
