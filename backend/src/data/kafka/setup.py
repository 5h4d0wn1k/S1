from typing import Dict, List, Any
import asyncio
import json

from aiokafka.admin import AIOKafkaAdminClient, NewTopic
from aiokafka.errors import TopicAlreadyExistsError
from confluent_kafka.schema_registry import SchemaRegistryClient
from confluent_kafka.schema_registry.avro import AvroSchema

from ...core.settings import get_settings
from ...utils.logging import LoggerMixin
from .schemas import (
    LOG_SCHEMA,
    ALERT_SCHEMA,
    SCAN_SCHEMA,
    METRIC_SCHEMA
)

settings = get_settings()
logger = LoggerMixin().get_logger()

# Topic configurations
TOPICS = {
    # Log topics
    "logs.raw": {
        "partitions": 6,
        "replication_factor": 3,
        "config": {
            "retention.ms": 604800000,  # 7 days
            "cleanup.policy": "delete",
            "compression.type": "lz4"
        }
    },
    "logs.processed": {
        "partitions": 6,
        "replication_factor": 3,
        "config": {
            "retention.ms": 604800000,  # 7 days
            "cleanup.policy": "delete",
            "compression.type": "lz4"
        }
    },
    
    # Alert topics
    "alerts.new": {
        "partitions": 3,
        "replication_factor": 3,
        "config": {
            "retention.ms": 2592000000,  # 30 days
            "cleanup.policy": "delete",
            "compression.type": "lz4"
        }
    },
    "alerts.updated": {
        "partitions": 3,
        "replication_factor": 3,
        "config": {
            "retention.ms": 2592000000,  # 30 days
            "cleanup.policy": "delete",
            "compression.type": "lz4"
        }
    },
    
    # Scan topics
    "scans.requests": {
        "partitions": 3,
        "replication_factor": 3,
        "config": {
            "retention.ms": 604800000,  # 7 days
            "cleanup.policy": "delete",
            "compression.type": "lz4"
        }
    },
    "scans.results": {
        "partitions": 3,
        "replication_factor": 3,
        "config": {
            "retention.ms": 2592000000,  # 30 days
            "cleanup.policy": "delete",
            "compression.type": "lz4"
        }
    },
    
    # Metric topics
    "metrics.system": {
        "partitions": 3,
        "replication_factor": 3,
        "config": {
            "retention.ms": 86400000,  # 1 day
            "cleanup.policy": "delete",
            "compression.type": "lz4"
        }
    },
    "metrics.application": {
        "partitions": 3,
        "replication_factor": 3,
        "config": {
            "retention.ms": 86400000,  # 1 day
            "cleanup.policy": "delete",
            "compression.type": "lz4"
        }
    }
}

# Schema configurations
SCHEMAS = {
    "logs.raw-value": LOG_SCHEMA,
    "logs.processed-value": LOG_SCHEMA,
    "alerts.new-value": ALERT_SCHEMA,
    "alerts.updated-value": ALERT_SCHEMA,
    "scans.requests-value": SCAN_SCHEMA,
    "scans.results-value": SCAN_SCHEMA,
    "metrics.system-value": METRIC_SCHEMA,
    "metrics.application-value": METRIC_SCHEMA
}

async def setup_kafka():
    """Initialize Kafka topics and schemas."""
    try:
        # Create topics
        await create_topics()
        
        # Register schemas
        await register_schemas()
        
        logger.info("Kafka setup completed successfully")
        
    except Exception as e:
        logger.error(
            "Failed to setup Kafka",
            error=str(e)
        )
        raise

async def create_topics():
    """Create Kafka topics."""
    try:
        # Initialize admin client
        admin_client = AIOKafkaAdminClient(
            bootstrap_servers=settings.kafka_bootstrap_servers,
            client_id="siem-admin"
        )
        
        # Create topic list
        new_topics = []
        for topic_name, config in TOPICS.items():
            new_topics.append(
                NewTopic(
                    name=topic_name,
                    num_partitions=config["partitions"],
                    replication_factor=config["replication_factor"],
                    topic_configs=config["config"]
                )
            )
        
        # Create topics
        try:
            await admin_client.create_topics(new_topics)
            logger.info(
                "Created Kafka topics",
                topics=list(TOPICS.keys())
            )
        except TopicAlreadyExistsError:
            logger.info("Some topics already exist")
        except Exception as e:
            logger.error(
                "Failed to create topics",
                error=str(e)
            )
            raise
        finally:
            await admin_client.close()
        
    except Exception as e:
        logger.error(
            "Failed to create Kafka topics",
            error=str(e)
        )
        raise

async def register_schemas():
    """Register Avro schemas with Schema Registry."""
    try:
        # Initialize Schema Registry client
        schema_registry = SchemaRegistryClient({
            'url': settings.schema_registry_url
        })
        
        # Register schemas
        for subject, schema in SCHEMAS.items():
            try:
                avro_schema = AvroSchema(json.dumps(schema))
                schema_registry.register_schema(
                    subject=subject,
                    schema=avro_schema
                )
                logger.info(
                    "Registered schema",
                    subject=subject
                )
            except Exception as e:
                if "already registered" in str(e):
                    logger.info(
                        "Schema already registered",
                        subject=subject
                    )
                else:
                    raise
        
    except Exception as e:
        logger.error(
            "Failed to register schemas",
            error=str(e)
        )
        raise

async def verify_setup():
    """Verify Kafka setup."""
    try:
        # Initialize admin client
        admin_client = AIOKafkaAdminClient(
            bootstrap_servers=settings.kafka_bootstrap_servers,
            client_id="siem-admin"
        )
        
        # Check topics
        topics = await admin_client.list_topics()
        for topic_name in TOPICS.keys():
            assert topic_name in topics
        
        await admin_client.close()
        
        # Check schemas
        schema_registry = SchemaRegistryClient({
            'url': settings.schema_registry_url
        })
        
        for subject in SCHEMAS.keys():
            schema = schema_registry.get_latest_version(subject)
            assert schema is not None
        
        logger.info("Kafka setup verification successful")
        
    except Exception as e:
        logger.error(
            "Failed to verify Kafka setup",
            error=str(e)
        )
        raise

if __name__ == "__main__":
    # Run setup when script is executed directly
    asyncio.run(setup_kafka()) 