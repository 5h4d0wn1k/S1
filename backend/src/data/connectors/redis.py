from typing import Dict, List, Optional, Union, Any
from datetime import datetime, timedelta
import json

import aioredis
from aioredis.exceptions import RedisError

from ...core.settings import get_settings
from ...utils.logging import LoggerMixin

settings = get_settings()

class RedisConnector(LoggerMixin):
    """Redis connector for caching and real-time data."""
    
    def __init__(self):
        """Initialize Redis connection."""
        super().__init__()
        self.client = None
        self._initialize_connection()
    
    def _initialize_connection(self):
        """Initialize Redis client."""
        try:
            self.client = aioredis.from_url(
                f"redis://{settings.REDIS_HOST}:{settings.REDIS_PORT}",
                password=settings.REDIS_PASSWORD,
                db=settings.REDIS_DB,
                decode_responses=True,  # Auto-decode to strings
                encoding="utf-8"
            )
            
            self.log_info("Redis client initialized successfully")
            
        except Exception as e:
            self.log_error("Failed to initialize Redis client", error=e)
            raise
    
    async def set(
        self,
        key: str,
        value: Union[str, int, float, dict, list],
        expire: Optional[int] = None
    ) -> bool:
        """Set a key with optional expiration (in seconds)."""
        try:
            # Convert complex types to JSON
            if isinstance(value, (dict, list)):
                value = json.dumps(value)
            
            await self.client.set(key, value, ex=expire)
            return True
            
        except Exception as e:
            self.log_error(
                "Failed to set key",
                error=e,
                key=key,
                expire=expire
            )
            raise
    
    async def get(
        self,
        key: str,
        default: Any = None
    ) -> Any:
        """Get a key's value."""
        try:
            value = await self.client.get(key)
            
            if value is None:
                return default
            
            # Try to parse as JSON
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return value
                
        except Exception as e:
            self.log_error("Failed to get key", error=e, key=key)
            raise
    
    async def delete(self, *keys: str) -> int:
        """Delete one or more keys."""
        try:
            return await self.client.delete(*keys)
            
        except Exception as e:
            self.log_error("Failed to delete keys", error=e, keys=keys)
            raise
    
    async def exists(self, *keys: str) -> int:
        """Check if one or more keys exist."""
        try:
            return await self.client.exists(*keys)
            
        except Exception as e:
            self.log_error("Failed to check keys existence", error=e, keys=keys)
            raise
    
    async def expire(self, key: str, seconds: int) -> bool:
        """Set a key's time to live in seconds."""
        try:
            return await self.client.expire(key, seconds)
            
        except Exception as e:
            self.log_error(
                "Failed to set expiration",
                error=e,
                key=key,
                seconds=seconds
            )
            raise
    
    async def ttl(self, key: str) -> int:
        """Get the remaining time to live of a key in seconds."""
        try:
            return await self.client.ttl(key)
            
        except Exception as e:
            self.log_error("Failed to get TTL", error=e, key=key)
            raise
    
    async def incr(self, key: str) -> int:
        """Increment the integer value of a key by one."""
        try:
            return await self.client.incr(key)
            
        except Exception as e:
            self.log_error("Failed to increment key", error=e, key=key)
            raise
    
    async def decr(self, key: str) -> int:
        """Decrement the integer value of a key by one."""
        try:
            return await self.client.decr(key)
            
        except Exception as e:
            self.log_error("Failed to decrement key", error=e, key=key)
            raise
    
    async def hset(self, key: str, mapping: Dict[str, Any]) -> int:
        """Set multiple hash fields to multiple values."""
        try:
            # Convert complex values to JSON
            serialized = {
                k: json.dumps(v) if isinstance(v, (dict, list)) else v
                for k, v in mapping.items()
            }
            
            return await self.client.hset(key, mapping=serialized)
            
        except Exception as e:
            self.log_error(
                "Failed to set hash fields",
                error=e,
                key=key,
                fields=list(mapping.keys())
            )
            raise
    
    async def hget(
        self,
        key: str,
        field: str,
        default: Any = None
    ) -> Any:
        """Get the value of a hash field."""
        try:
            value = await self.client.hget(key, field)
            
            if value is None:
                return default
            
            # Try to parse as JSON
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return value
                
        except Exception as e:
            self.log_error(
                "Failed to get hash field",
                error=e,
                key=key,
                field=field
            )
            raise
    
    async def hgetall(self, key: str) -> Dict[str, Any]:
        """Get all the fields and values in a hash."""
        try:
            result = await self.client.hgetall(key)
            
            # Try to parse values as JSON
            deserialized = {}
            for k, v in result.items():
                try:
                    deserialized[k] = json.loads(v)
                except json.JSONDecodeError:
                    deserialized[k] = v
            
            return deserialized
            
        except Exception as e:
            self.log_error("Failed to get all hash fields", error=e, key=key)
            raise
    
    async def hdel(self, key: str, *fields: str) -> int:
        """Delete one or more hash fields."""
        try:
            return await self.client.hdel(key, *fields)
            
        except Exception as e:
            self.log_error(
                "Failed to delete hash fields",
                error=e,
                key=key,
                fields=fields
            )
            raise
    
    async def publish(self, channel: str, message: Union[str, dict, list]) -> int:
        """Publish a message to a channel."""
        try:
            # Convert complex types to JSON
            if isinstance(message, (dict, list)):
                message = json.dumps(message)
            
            return await self.client.publish(channel, message)
            
        except Exception as e:
            self.log_error(
                "Failed to publish message",
                error=e,
                channel=channel
            )
            raise
    
    async def close(self):
        """Close Redis connection."""
        try:
            if self.client:
                await self.client.close()
                self.log_info("Redis connection closed")
                
        except Exception as e:
            self.log_error("Failed to close Redis connection", error=e)
            raise
    
    async def get_metrics(self) -> Dict[str, Any]:
        """Get current system metrics from Redis."""
        try:
            metrics = await self.hgetall("metrics")
            
            if not metrics:
                return {
                    "cpu_usage": 0,
                    "memory_usage": 0,
                    "active_alerts": 0,
                    "active_scans": 0,
                    "events_per_second": 0,
                    "total_events_24h": 0,
                    "alerts_by_severity": {
                        "critical": 0,
                        "high": 0,
                        "medium": 0,
                        "low": 0,
                        "info": 0
                    }
                }
            
            return metrics
            
        except Exception as e:
            self.log_error("Failed to get metrics", error=e)
            raise
    
    async def update_metrics(self, metrics: Dict[str, Any]) -> bool:
        """Update system metrics in Redis."""
        try:
            await self.hset("metrics", metrics)
            return True
            
        except Exception as e:
            self.log_error("Failed to update metrics", error=e)
            raise
    
    async def get_recent_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent events from Redis."""
        try:
            # Get events from sorted set, ordered by timestamp
            events = await self.client.zrevrange(
                "recent_events",
                0,
                limit - 1,
                withscores=True
            )
            
            result = []
            for event_data, score in events:
                try:
                    event = json.loads(event_data)
                    event["timestamp"] = datetime.fromtimestamp(score)
                    result.append(event)
                except json.JSONDecodeError:
                    self.log_error(
                        "Failed to decode event",
                        event_data=event_data
                    )
            
            return result
            
        except Exception as e:
            self.log_error("Failed to get recent events", error=e)
            raise
    
    async def add_event(self, event: Dict[str, Any]) -> bool:
        """Add an event to the recent events list."""
        try:
            # Convert event to JSON
            event_data = json.dumps(event)
            
            # Use timestamp as score for ordering
            score = event.get("timestamp", datetime.utcnow().timestamp())
            
            # Add to sorted set
            await self.client.zadd(
                "recent_events",
                {event_data: score}
            )
            
            # Trim to last 1000 events
            await self.client.zremrangebyrank(
                "recent_events",
                0,
                -1001
            )
            
            return True
            
        except Exception as e:
            self.log_error("Failed to add event", error=e)
            raise
    
    async def increment_counter(self, key: str, expire: int = 86400) -> int:
        """Increment a counter with expiration."""
        try:
            # Increment counter
            value = await self.incr(key)
            
            # Set expiration if not already set
            if await self.ttl(key) == -1:
                await self.expire(key, expire)
            
            return value
            
        except Exception as e:
            self.log_error("Failed to increment counter", error=e, key=key)
            raise
    
    async def get_counter(self, key: str) -> int:
        """Get current counter value."""
        try:
            value = await self.get(key, 0)
            return int(value)
            
        except Exception as e:
            self.log_error("Failed to get counter", error=e, key=key)
            raise

# Create singleton instance
redis_connector = RedisConnector() 