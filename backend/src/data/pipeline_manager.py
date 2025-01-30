from typing import Dict, List, Optional, Union, Any
from datetime import datetime
import asyncio
import signal
import sys

from ..core.settings import get_settings
from ..utils.logging import LoggerMixin
from .connectors.elasticsearch import es_connector
from .connectors.kafka import kafka_connector
from .connectors.redis import redis_connector
from .connectors.postgresql import pg_connector
from .processors.log_processor import log_processor
from ..engines.ai.engine import ai_engine
from ..engines.defensive.engine import defensive_engine
from ..engines.offensive.engine import offensive_engine

settings = get_settings()

class PipelineManager(LoggerMixin):
    """Manage and coordinate all data processing components."""
    
    def __init__(self):
        """Initialize pipeline manager."""
        super().__init__()
        self.running = False
        self.components = {
            "elasticsearch": es_connector,
            "kafka": kafka_connector,
            "redis": redis_connector,
            "postgresql": pg_connector,
            "log_processor": log_processor,
            "ai_engine": ai_engine,
            "defensive_engine": defensive_engine,
            "offensive_engine": offensive_engine
        }
        self._setup_signal_handlers()
    
    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown."""
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, self._handle_shutdown)
    
    def _handle_shutdown(self, signum, frame):
        """Handle shutdown signals."""
        self.log_info(f"Received signal {signum}, initiating graceful shutdown...")
        asyncio.create_task(self.stop())
    
    async def initialize_kafka_topics(self):
        """Initialize required Kafka topics."""
        try:
            required_topics = [
                # Log topics
                "logs.syslog",
                "logs.windows",
                "logs.aws_cloudtrail",
                "logs.kubernetes",
                # Alert topics
                "alerts.new",
                "alerts.processed",
                # Scan topics
                "scans.start",
                "scans.complete",
                "scans.failed",
                # Analysis topics
                "analysis.request",
                "analysis.complete"
            ]
            
            for topic in required_topics:
                await kafka_connector.create_topic(
                    topic=topic,
                    num_partitions=settings.KAFKA_PARTITIONS,
                    replication_factor=settings.KAFKA_REPLICATION
                )
            
            self.log_info("Kafka topics initialized successfully")
            
        except Exception as e:
            self.log_error("Failed to initialize Kafka topics", error=e)
            raise
    
    async def initialize_elasticsearch_indices(self):
        """Initialize required Elasticsearch indices."""
        try:
            # Log indices
            log_mapping = {
                "mappings": {
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "@version": {"type": "keyword"},
                        "@id": {"type": "keyword"},
                        "source": {"type": "keyword"},
                        "host": {"type": "keyword"},
                        "message": {"type": "text"},
                        "severity": {"type": "keyword"},
                        "facility": {"type": "keyword"},
                        "program": {"type": "keyword"},
                        "pid": {"type": "long"},
                        "geo": {
                            "properties": {
                                "country": {"type": "keyword"},
                                "city": {"type": "keyword"},
                                "coordinates": {"type": "geo_point"}
                            }
                        },
                        "threat_intel": {
                            "properties": {
                                "malicious": {"type": "boolean"},
                                "confidence": {"type": "float"},
                                "tags": {"type": "keyword"}
                            }
                        },
                        "asset": {
                            "properties": {
                                "type": {"type": "keyword"},
                                "owner": {"type": "keyword"},
                                "criticality": {"type": "keyword"}
                            }
                        },
                        "raw": {"type": "object", "enabled": False}
                    }
                },
                "settings": {
                    "number_of_shards": 3,
                    "number_of_replicas": 1,
                    "index.lifecycle.name": "logs-policy",
                    "index.lifecycle.rollover_alias": "logs"
                }
            }
            
            # Alert indices
            alert_mapping = {
                "mappings": {
                    "properties": {
                        "id": {"type": "keyword"},
                        "timestamp": {"type": "date"},
                        "source": {"type": "keyword"},
                        "severity": {"type": "keyword"},
                        "category": {"type": "keyword"},
                        "description": {"type": "text"},
                        "source_ip": {"type": "ip"},
                        "destination_ip": {"type": "ip"},
                        "network_context": {
                            "properties": {
                                "protocol": {"type": "keyword"},
                                "src_port": {"type": "integer"},
                                "dest_port": {"type": "integer"}
                            }
                        },
                        "additional_context": {"type": "object"}
                    }
                },
                "settings": {
                    "number_of_shards": 3,
                    "number_of_replicas": 1,
                    "index.lifecycle.name": "alerts-policy",
                    "index.lifecycle.rollover_alias": "alerts"
                }
            }
            
            # Create index templates
            await es_connector.client.indices.put_index_template(
                name="logs-template",
                body={
                    "index_patterns": ["logs-*"],
                    **log_mapping
                }
            )
            
            await es_connector.client.indices.put_index_template(
                name="alerts-template",
                body={
                    "index_patterns": ["alerts-*"],
                    **alert_mapping
                }
            )
            
            self.log_info("Elasticsearch indices initialized successfully")
            
        except Exception as e:
            self.log_error("Failed to initialize Elasticsearch indices", error=e)
            raise
    
    async def initialize_postgresql_tables(self):
        """Initialize required PostgreSQL tables."""
        try:
            # Create tables
            queries = [
                # Assets table
                """
                CREATE TABLE IF NOT EXISTS assets (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    hostname VARCHAR(255) NOT NULL,
                    ip_address INET,
                    type VARCHAR(50),
                    owner VARCHAR(100),
                    criticality VARCHAR(20),
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
                """,
                # Scans table
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    target_id UUID REFERENCES assets(id),
                    scan_type VARCHAR(50) NOT NULL,
                    status VARCHAR(20) NOT NULL,
                    start_time TIMESTAMP WITH TIME ZONE,
                    end_time TIMESTAMP WITH TIME ZONE,
                    findings JSONB,
                    error_message TEXT,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
                """,
                # Users table
                """
                CREATE TABLE IF NOT EXISTS users (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    username VARCHAR(100) UNIQUE NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    role VARCHAR(50) NOT NULL,
                    is_active BOOLEAN DEFAULT true,
                    last_login TIMESTAMP WITH TIME ZONE,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
                """
            ]
            
            # Execute queries in transaction
            await pg_connector.execute_transaction([
                {"query": query} for query in queries
            ])
            
            self.log_info("PostgreSQL tables initialized successfully")
            
        except Exception as e:
            self.log_error("Failed to initialize PostgreSQL tables", error=e)
            raise
    
    async def start(self):
        """Start all components."""
        try:
            self.running = True
            
            # Initialize infrastructure
            await self.initialize_kafka_topics()
            await self.initialize_elasticsearch_indices()
            await self.initialize_postgresql_tables()
            
            # Start components
            await kafka_connector.start()
            await log_processor.start()
            await defensive_engine.start()
            await offensive_engine.start()
            
            self.log_info("Pipeline manager started successfully")
            
            # Keep running until stopped
            while self.running:
                await asyncio.sleep(1)
                
        except Exception as e:
            self.log_error("Failed to start pipeline manager", error=e)
            raise
        finally:
            if not self.running:
                await self.stop()
    
    async def stop(self):
        """Stop all components gracefully."""
        try:
            self.running = False
            
            # Stop components in reverse order
            await offensive_engine.stop()
            await defensive_engine.stop()
            await log_processor.stop()
            await kafka_connector.stop()
            
            # Close connections
            await es_connector.close()
            await redis_connector.close()
            await pg_connector.close()
            
            self.log_info("Pipeline manager stopped successfully")
            
        except Exception as e:
            self.log_error("Failed to stop pipeline manager", error=e)
            raise
        finally:
            sys.exit(0)

# Create singleton instance
pipeline_manager = PipelineManager() 