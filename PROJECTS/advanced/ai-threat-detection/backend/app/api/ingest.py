"""
©AngelaMos | 2026
ingest.py
"""

import asyncio

from fastapi import APIRouter, Request
from pydantic import BaseModel

router = APIRouter(prefix="/ingest", tags=["ingest"])


class BatchIngestRequest(BaseModel):
    """
    Payload for bulk log line ingestion
    """

    lines: list[str]


@router.post("/batch", status_code=200)
async def ingest_batch(
    body: BatchIngestRequest,
    request: Request,
) -> dict[str, int]:
    """
    Push a batch of raw log lines into the pipeline queue
    """
    pipeline = getattr(request.app.state, "pipeline", None)
    if pipeline is None:
        return {"queued": 0}

    queued = 0
    for line in body.lines:
        try:
            pipeline.raw_queue.put_nowait(line)
            queued += 1
        except asyncio.QueueFull:
            break

    return {"queued": queued}
