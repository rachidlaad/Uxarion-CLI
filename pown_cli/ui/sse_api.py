# SPDX-License-Identifier: Apache-2.0
"""
Server-Sent Events API for real-time agent streaming
Streams events from Redis to web clients
"""
import os
import json
import asyncio
from typing import AsyncGenerator

from fastapi import APIRouter, BackgroundTasks, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

try:
    import aioredis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

try:
    from ..bus.events import EventPublisher
    from ..agents.ai_recon import AIReconAgent
    from ..memory.neo4j_graph import Neo4jGraphMemory
except ImportError:  # pragma: no cover - optional components
    EventPublisher = None
    AIReconAgent = None
    Neo4jGraphMemory = None


router = APIRouter()


class StartReconRequest(BaseModel):
    target: str
    objective: str = "Comprehensive reconnaissance"
    session_id: str = None


@router.get("/events/{session_id}")
async def stream_events(session_id: str):
    """Stream events for a session via Server-Sent Events"""
    if not REDIS_AVAILABLE:
        return StreamingResponse(
            _mock_event_stream(),
            media_type="text/event-stream"
        )

    return StreamingResponse(
        _redis_event_stream(session_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        }
    )


async def _redis_event_stream(session_id: str) -> AsyncGenerator[str, None]:
    """Stream events from Redis pub/sub"""
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")

    try:
        redis = await aioredis.from_url(redis_url, decode_responses=True)
        pubsub = redis.pubsub()
        await pubsub.subscribe(f"events:{session_id}")

        yield "event: connected\ndata: {\"status\": \"connected\"}\n\n"

        async for message in pubsub.listen():
            if message.get("type") == "message":
                data = message.get("data", "{}")
                yield f"event: message\ndata: {data}\n\n"

    except Exception as e:
        yield f"event: error\ndata: {{\"error\": \"{str(e)}\"}}\n\n"
    finally:
        try:
            await pubsub.unsubscribe(f"events:{session_id}")
            await pubsub.close()
            await redis.close()
        except:
            pass


async def _mock_event_stream() -> AsyncGenerator[str, None]:
    """Mock event stream when Redis is unavailable"""
    yield "event: connected\ndata: {\"status\": \"connected\", \"redis\": false}\n\n"

    for i in range(5):
        await asyncio.sleep(1)
        mock_event = {
            "ts": "2025-01-01T00:00:00Z",
            "type": "log.append",
            "session_id": "mock",
            "data": {"stream": "stdout", "text": f"Mock log line {i+1}"}
        }
        yield f"event: message\ndata: {json.dumps(mock_event)}\n\n"

    final_event = {
        "ts": "2025-01-01T00:00:05Z",
        "type": "step.finished",
        "session_id": "mock",
        "data": {"id": "mock-step", "exit_code": 0}
    }
    yield f"event: message\ndata: {json.dumps(final_event)}\n\n"


@router.post("/start")
async def start_recon(request: StartReconRequest, background_tasks: BackgroundTasks):
    """Start a reconnaissance session"""
    if EventPublisher is None or AIReconAgent is None or Neo4jGraphMemory is None:
        raise HTTPException(
            status_code=503,
            detail="Reconnaissance components are not installed.",
        )
    session_id = request.session_id or f"recon_{request.target.replace('/', '_').replace(':', '_')}"

    # Queue the recon task in background
    background_tasks.add_task(_run_recon_session, request, session_id)

    return {
        "status": "started",
        "session_id": session_id,
        "target": request.target,
        "objective": request.objective
    }


async def _run_recon_session(request: StartReconRequest, session_id: str):
    """Run reconnaissance session in background"""
    if EventPublisher is None or AIReconAgent is None or Neo4jGraphMemory is None:
        return
    try:
        # Initialize components
        publisher = EventPublisher()
        graph = Neo4jGraphMemory()
        agent = AIReconAgent(
            event_publisher=publisher,
            graph_memory=graph
        )

        # Override session ID
        agent.session_id = session_id

        # Execute reconnaissance
        result = await agent.recon(request.objective, request.target)

        # Publish completion
        await publisher.publish("session.completed", session_id, {
            "status": "completed",
            "result": result
        })

    except Exception as e:
        # Publish error
        publisher = EventPublisher()
        await publisher.error(session_id, str(e), "recon_session")


@router.get("/sessions/{session_id}/status")
async def get_session_status(session_id: str):
    """Get current session status from graph"""
    if Neo4jGraphMemory is None:
        raise HTTPException(status_code=503, detail="Graph memory backend unavailable.")
    try:
        graph = Neo4jGraphMemory()
        host_id = session_id.split('_')[1] if '_' in session_id else session_id
        context = graph.get_host_context(host_id)

        return {
            "session_id": session_id,
            "status": "active" if context else "not_found",
            "context": context
        }
    except Exception as e:
        return {
            "session_id": session_id,
            "status": "error",
            "error": str(e)
        }


@router.get("/graph/summary")
async def get_graph_summary():
    """Get overall attack surface summary"""
    if Neo4jGraphMemory is None:
        raise HTTPException(status_code=503, detail="Graph memory backend unavailable.")
    try:
        graph = Neo4jGraphMemory()
        summary = graph.get_attack_surface_summary()
        return summary
    except Exception as e:
        return {"error": str(e)}
