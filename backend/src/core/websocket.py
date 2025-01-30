import asyncio
from typing import Dict, Set, List, Optional
from datetime import datetime
from fastapi import WebSocket
from pydantic import BaseModel

from .exceptions import WebSocketError
from ..utils.logging import LoggerMixin
from ..data.connectors.redis import redis_connector

class Event(BaseModel):
    """Real-time event model."""
    id: str
    type: str
    timestamp: datetime
    data: Dict
    source: str

class WebSocketManager(LoggerMixin):
    """Manages WebSocket connections and broadcasts."""
    
    def __init__(self) -> None:
        self.active_connections: Dict[str, Set[WebSocket]] = {
            "alerts": set(),
            "metrics": set(),
            "events": set()
        }
        self.running = False
        self._lock = asyncio.Lock()
        self._event_queue: asyncio.Queue[Event] = asyncio.Queue()
    
    async def connect(
        self,
        websocket: WebSocket,
        channel: str
    ) -> None:
        """Connect a client to a channel."""
        try:
            await websocket.accept()
            
            async with self._lock:
                if channel not in self.active_connections:
                    self.active_connections[channel] = set()
                self.active_connections[channel].add(websocket)
            
            self.log_info(
                "WebSocket client connected",
                channel=channel
            )
        except Exception as e:
            self.log_error(
                "WebSocket connection failed",
                error=e,
                channel=channel
            )
            raise WebSocketError("Connection failed")
    
    async def disconnect(
        self,
        websocket: WebSocket,
        channel: str
    ) -> None:
        """Disconnect a client from a channel."""
        try:
            async with self._lock:
                self.active_connections[channel].remove(websocket)
            
            self.log_info(
                "WebSocket client disconnected",
                channel=channel
            )
        except Exception as e:
            self.log_error(
                "WebSocket disconnection failed",
                error=e,
                channel=channel
            )
    
    async def broadcast(
        self,
        message: Dict,
        channel: str
    ) -> None:
        """Broadcast a message to all clients in a channel."""
        try:
            if channel not in self.active_connections:
                return
            
            dead_connections = set()
            
            async with self._lock:
                for connection in self.active_connections[channel]:
                    try:
                        await connection.send_json(message)
                    except Exception as e:
                        self.log_error(
                            "Failed to send message",
                            error=e,
                            channel=channel
                        )
                        dead_connections.add(connection)
                
                # Clean up dead connections
                for dead in dead_connections:
                    self.active_connections[channel].remove(dead)
            
            self.log_debug(
                "Message broadcast",
                channel=channel,
                recipients=len(self.active_connections[channel])
            )
        except Exception as e:
            self.log_error(
                "Broadcast failed",
                error=e,
                channel=channel
            )
            raise WebSocketError("Broadcast failed")
    
    async def start_broadcast_loop(self) -> None:
        """Start the broadcast loop for real-time updates."""
        try:
            self.running = True
            
            # Start event consumer
            asyncio.create_task(self._consume_events())
            
            while self.running:
                # Broadcast metrics every 5 seconds
                await self.broadcast(
                    {"type": "metrics_update", "data": await self._get_metrics()},
                    "metrics"
                )
                
                # Broadcast events every second
                await self.broadcast(
                    {"type": "events_update", "data": await self._get_events()},
                    "events"
                )
                
                await asyncio.sleep(1)
        except Exception as e:
            self.log_error("Broadcast loop failed", error=e)
            self.running = False
            raise WebSocketError("Broadcast loop failed")
    
    async def stop_broadcast_loop(self) -> None:
        """Stop the broadcast loop."""
        self.running = False
    
    async def _get_metrics(self) -> Dict:
        """Get current system metrics."""
        try:
            # Get metrics from Redis
            metrics = await redis_connector.get_metrics()
            
            if not metrics:
                metrics = {
                    "cpu_usage": 0,
                    "memory_usage": 0,
                    "active_alerts": 0,
                    "active_scans": 0,
                    "events_per_second": 0
                }
            
            return metrics
        except Exception as e:
            self.log_error("Failed to get metrics", error=e)
            return {}
    
    async def _get_events(self) -> List[Dict]:
        """Get recent events."""
        try:
            # Get events from Redis
            events = await redis_connector.get_recent_events(limit=100)
            return events
        except Exception as e:
            self.log_error("Failed to get events", error=e)
            return []
    
    async def _consume_events(self) -> None:
        """Consume events from the event queue and broadcast them."""
        try:
            while self.running:
                event = await self._event_queue.get()
                
                # Determine target channel based on event type
                channel = self._get_channel_for_event(event.type)
                
                if channel:
                    await self.broadcast(
                        {
                            "type": "event",
                            "data": event.dict()
                        },
                        channel
                    )
                
                self._event_queue.task_done()
        except Exception as e:
            self.log_error("Event consumer failed", error=e)
            if self.running:
                # Restart consumer if it fails while manager is running
                asyncio.create_task(self._consume_events())
    
    def _get_channel_for_event(self, event_type: str) -> Optional[str]:
        """Map event type to appropriate channel."""
        if event_type.startswith("alert"):
            return "alerts"
        elif event_type.startswith("metric"):
            return "metrics"
        elif event_type.startswith("event"):
            return "events"
        return None
    
    async def publish_event(self, event: Event) -> None:
        """Publish an event to the event queue."""
        try:
            await self._event_queue.put(event)
        except Exception as e:
            self.log_error("Failed to publish event", error=e)
            raise WebSocketError("Failed to publish event")

# Global WebSocket manager instance
ws_manager = WebSocketManager() 