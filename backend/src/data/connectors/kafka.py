from typing import Dict, List, Optional, Union, Any, Callable
from datetime import datetime
import json
import asyncio
from functools import partial

from aiokafka import AIOKafkaProducer, AIOKafkaConsumer
from aiokafka.errors import KafkaError
from kafka.admin import KafkaAdminClient, NewTopic

from ...core.settings import get_settings
from ...utils.logging import LoggerMixin

settings = get_settings()

class KafkaConnector(LoggerMixin):
    """Kafka connector for streaming data processing."""
    
    def __init__(self):
        """Initialize Kafka connection."""
        super().__init__()
        self.producer = None
        self.consumers: Dict[str, AIOKafkaConsumer] = {}
        self.admin_client = None
        self._initialize_connection()
    
    def _initialize_connection(self):
        """Initialize Kafka clients."""
        try:
            # Initialize admin client for topic management
            self.admin_client = KafkaAdminClient(
                bootstrap_servers=f"{settings.KAFKA_HOST}:{settings.KAFKA_PORT}",
                client_id=settings.PROJECT_NAME,
                security_protocol="SSL" if settings.KAFKA_USE_SSL else "PLAINTEXT",
                ssl_cafile=settings.KAFKA_SSL_CA_FILE if settings.KAFKA_USE_SSL else None,
                ssl_certfile=settings.KAFKA_SSL_CERT_FILE if settings.KAFKA_USE_SSL else None,
                ssl_keyfile=settings.KAFKA_SSL_KEY_FILE if settings.KAFKA_USE_SSL else None
            )
            
            # Initialize producer
            self.producer = AIOKafkaProducer(
                bootstrap_servers=f"{settings.KAFKA_HOST}:{settings.KAFKA_PORT}",
                security_protocol="SSL" if settings.KAFKA_USE_SSL else "PLAINTEXT",
                ssl_cafile=settings.KAFKA_SSL_CA_FILE if settings.KAFKA_USE_SSL else None,
                ssl_certfile=settings.KAFKA_SSL_CERT_FILE if settings.KAFKA_USE_SSL else None,
                ssl_keyfile=settings.KAFKA_SSL_KEY_FILE if settings.KAFKA_USE_SSL else None,
                value_serializer=lambda v: json.dumps(v).encode('utf-8')
            )
            
            self.log_info("Kafka clients initialized successfully")
            
        except Exception as e:
            self.log_error("Failed to initialize Kafka clients", error=e)
            raise
    
    async def start(self):
        """Start the Kafka producer."""
        try:
            await self.producer.start()
            self.log_info("Kafka producer started")
            
        except Exception as e:
            self.log_error("Failed to start Kafka producer", error=e)
            raise
    
    async def stop(self):
        """Stop all Kafka clients."""
        try:
            # Stop producer
            if self.producer:
                await self.producer.stop()
            
            # Stop all consumers
            for consumer in self.consumers.values():
                await consumer.stop()
            
            # Close admin client
            if self.admin_client:
                self.admin_client.close()
            
            self.log_info("Kafka clients stopped")
            
        except Exception as e:
            self.log_error("Failed to stop Kafka clients", error=e)
            raise
    
    async def create_topic(
        self,
        topic: str,
        num_partitions: int = 1,
        replication_factor: int = 1
    ) -> bool:
        """Create a new Kafka topic."""
        try:
            # Check if topic exists
            topics = self.admin_client.list_topics()
            if topic in topics:
                self.log_warning(f"Topic {topic} already exists")
                return False
            
            # Create topic
            new_topic = NewTopic(
                name=topic,
                num_partitions=num_partitions,
                replication_factor=replication_factor
            )
            
            self.admin_client.create_topics([new_topic])
            self.log_info(f"Topic {topic} created successfully")
            return True
            
        except Exception as e:
            self.log_error(
                "Failed to create topic",
                error=e,
                topic=topic
            )
            raise
    
    async def delete_topic(self, topic: str) -> bool:
        """Delete a Kafka topic."""
        try:
            # Check if topic exists
            topics = self.admin_client.list_topics()
            if topic not in topics:
                self.log_warning(f"Topic {topic} does not exist")
                return False
            
            # Delete topic
            self.admin_client.delete_topics([topic])
            self.log_info(f"Topic {topic} deleted successfully")
            return True
            
        except Exception as e:
            self.log_error(
                "Failed to delete topic",
                error=e,
                topic=topic
            )
            raise
    
    async def send_message(
        self,
        topic: str,
        message: Union[str, dict, list],
        key: Optional[str] = None
    ) -> bool:
        """Send a message to a Kafka topic."""
        try:
            # Ensure producer is running
            if not self.producer._sender.sender.running:
                await self.start()
            
            # Send message
            await self.producer.send_and_wait(
                topic,
                value=message,
                key=key.encode() if key else None
            )
            
            return True
            
        except Exception as e:
            self.log_error(
                "Failed to send message",
                error=e,
                topic=topic
            )
            raise
    
    async def send_batch(
        self,
        topic: str,
        messages: List[Union[str, dict, list]],
        key_func: Optional[Callable[[Any], str]] = None
    ) -> int:
        """Send multiple messages to a Kafka topic."""
        try:
            # Ensure producer is running
            if not self.producer._sender.sender.running:
                await self.start()
            
            # Create batch
            batch = self.producer.create_batch()
            
            sent_count = 0
            for message in messages:
                key = key_func(message).encode() if key_func else None
                
                # Add message to batch
                try:
                    batch.append(
                        key=key,
                        value=json.dumps(message).encode(),
                        timestamp=None
                    )
                    sent_count += 1
                except BufferError:
                    # Batch is full, send it and create a new one
                    await self.producer.send_batch(batch, topic=topic)
                    batch = self.producer.create_batch()
                    
                    # Try to append again
                    batch.append(
                        key=key,
                        value=json.dumps(message).encode(),
                        timestamp=None
                    )
                    sent_count += 1
            
            # Send any remaining messages
            if batch:
                await self.producer.send_batch(batch, topic=topic)
            
            return sent_count
            
        except Exception as e:
            self.log_error(
                "Failed to send batch",
                error=e,
                topic=topic,
                message_count=len(messages)
            )
            raise
    
    async def consume_messages(
        self,
        topic: str,
        callback: Callable[[str, Any], None],
        group_id: Optional[str] = None,
        auto_offset_reset: str = "latest"
    ):
        """Consume messages from a Kafka topic."""
        try:
            # Create consumer if it doesn't exist
            if topic not in self.consumers:
                consumer = AIOKafkaConsumer(
                    topic,
                    bootstrap_servers=f"{settings.KAFKA_HOST}:{settings.KAFKA_PORT}",
                    group_id=group_id or f"{settings.PROJECT_NAME}-{topic}-consumer",
                    auto_offset_reset=auto_offset_reset,
                    security_protocol="SSL" if settings.KAFKA_USE_SSL else "PLAINTEXT",
                    ssl_cafile=settings.KAFKA_SSL_CA_FILE if settings.KAFKA_USE_SSL else None,
                    ssl_certfile=settings.KAFKA_SSL_CERT_FILE if settings.KAFKA_USE_SSL else None,
                    ssl_keyfile=settings.KAFKA_SSL_KEY_FILE if settings.KAFKA_USE_SSL else None,
                    value_deserializer=lambda m: json.loads(m.decode('utf-8'))
                )
                
                await consumer.start()
                self.consumers[topic] = consumer
            
            # Start consuming
            try:
                async for message in self.consumers[topic]:
                    try:
                        # Call callback with message
                        callback(message.key.decode() if message.key else None, message.value)
                    except Exception as e:
                        self.log_error(
                            "Error processing message",
                            error=e,
                            topic=topic,
                            offset=message.offset
                        )
                        
            except Exception as e:
                self.log_error(
                    "Error consuming messages",
                    error=e,
                    topic=topic
                )
                raise
                
        except Exception as e:
            self.log_error(
                "Failed to set up consumer",
                error=e,
                topic=topic
            )
            raise
    
    async def stop_consumer(self, topic: str):
        """Stop consuming from a topic."""
        try:
            if topic in self.consumers:
                await self.consumers[topic].stop()
                del self.consumers[topic]
                self.log_info(f"Consumer for topic {topic} stopped")
                
        except Exception as e:
            self.log_error(
                "Failed to stop consumer",
                error=e,
                topic=topic
            )
            raise

# Create singleton instance
kafka_connector = KafkaConnector() 