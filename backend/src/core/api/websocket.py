from typing import Dict, Optional
from datetime import datetime
from uuid import uuid4

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, Query
from pydantic import BaseModel

from ..auth import get_current_user, User
from ..websocket import ws_manager, Event
from ...utils.logging import LoggerMixin

router = APIRouter()
logger = LoggerMixin()

class EventCreate(BaseModel):
    """Event creation model."""
    type: str
    data: Dict
    source: str

@router.websocket("/ws/{channel}")
async def websocket_endpoint(
    websocket: WebSocket,
    channel: str,
    token: Optional[str] = Query(None),
    user: User = Depends(get_current_user)
) -> None:
    """WebSocket endpoint for real-time updates."""
    try:
        # Validate channel
        if channel not in ["alerts", "metrics", "events"]:
            await websocket.close(code=4000)
            return
        
        # Connect to channel
        await ws_manager.connect(websocket, channel)
        
        try:
            while True:
                # Keep connection alive and handle incoming messages
                data = await websocket.receive_json()
                
                # Handle client messages
                if data.get("type") == "ping":
                    await websocket.send_json({"type": "pong"})
                elif data.get("type") == "event":
                    # Create and publish event
                    try:
                        event = EventCreate(**data.get("data", {}))
                        await ws_manager.publish_event(
                            Event(
                                id=str(uuid4()),
                                type=event.type,
                                timestamp=datetime.utcnow(),
                                data=event.data,
                                source=event.source
                            )
                        )
                    except Exception as e:
                        logger.log_error(
                            "Failed to publish event",
                            error=e,
                            data=data
                        )
                        await websocket.send_json({
                            "type": "error",
                            "message": "Failed to publish event"
                        })
                
        except WebSocketDisconnect:
            await ws_manager.disconnect(websocket, channel)
        except Exception as e:
            logger.log_error(
                "WebSocket error",
                error=e,
                channel=channel,
                user=user.username
            )
            await ws_manager.disconnect(websocket, channel)
            
    except Exception as e:
        logger.log_error(
            "WebSocket connection failed",
            error=e,
            channel=channel,
            user=user.username if user else None
        )
        await websocket.close(code=4000)

@router.post("/events", response_model=Event)
async def create_event(
    event: EventCreate,
    user: User = Depends(get_current_user)
) -> Event:
    """Create and publish a new event."""
    try:
        new_event = Event(
            id=str(uuid4()),
            type=event.type,
            timestamp=datetime.utcnow(),
            data=event.data,
            source=event.source
        )
        
        await ws_manager.publish_event(new_event)
        return new_event
        
    except Exception as e:
        logger.log_error(
            "Failed to create event",
            error=e,
            event=event.dict(),
            user=user.username
        )
        raise WebSocketError("Failed to create event")

@router.on_event("startup")
async def startup_event() -> None:
    """Start the WebSocket broadcast loop on startup."""
    try:
        await ws_manager.start_broadcast_loop()
    except Exception as e:
        logger.log_error("Failed to start broadcast loop", error=e)
        raise

@router.on_event("shutdown")
async def shutdown_event() -> None:
    """Stop the WebSocket broadcast loop on shutdown."""
    try:
        await ws_manager.stop_broadcast_loop()
    except Exception as e:
        logger.log_error("Failed to stop broadcast loop", error=e)
        raise 