from typing import Dict, Any
import asyncio
import logging

from elasticsearch import AsyncElasticsearch
from elasticsearch.exceptions import RequestError

from ...core.settings import get_settings
from ...utils.logging import LoggerMixin
from .mappings import (
    LOG_TEMPLATE,
    ALERT_TEMPLATE,
    LOG_ILM_POLICY,
    ALERT_ILM_POLICY
)

settings = get_settings()
logger = LoggerMixin().get_logger()

async def setup_elasticsearch():
    """Initialize Elasticsearch with required indices, templates, and policies."""
    try:
        # Initialize Elasticsearch client
        es = AsyncElasticsearch(
            hosts=settings.elasticsearch_hosts,
            basic_auth=(settings.elasticsearch_user, settings.elasticsearch_password),
            verify_certs=settings.elasticsearch_verify_certs
        )
        
        # Create ILM policies
        await create_ilm_policies(es)
        
        # Create index templates
        await create_index_templates(es)
        
        # Create initial indices
        await create_initial_indices(es)
        
        # Close client
        await es.close()
        
        logger.info("Elasticsearch setup completed successfully")
        
    except Exception as e:
        logger.error(
            "Failed to setup Elasticsearch",
            error=str(e)
        )
        raise

async def create_ilm_policies(es: AsyncElasticsearch):
    """Create Index Lifecycle Management policies."""
    try:
        # Create logs policy
        try:
            await es.ilm.put_lifecycle(
                name="logs-policy",
                policy=LOG_ILM_POLICY
            )
            logger.info("Created logs ILM policy")
        except RequestError as e:
            if e.error == "resource_already_exists_exception":
                logger.info("Logs ILM policy already exists")
            else:
                raise
        
        # Create alerts policy
        try:
            await es.ilm.put_lifecycle(
                name="alerts-policy",
                policy=ALERT_ILM_POLICY
            )
            logger.info("Created alerts ILM policy")
        except RequestError as e:
            if e.error == "resource_already_exists_exception":
                logger.info("Alerts ILM policy already exists")
            else:
                raise
        
    except Exception as e:
        logger.error(
            "Failed to create ILM policies",
            error=str(e)
        )
        raise

async def create_index_templates(es: AsyncElasticsearch):
    """Create index templates."""
    try:
        # Create logs template
        try:
            await es.indices.put_index_template(
                name="logs",
                **LOG_TEMPLATE
            )
            logger.info("Created logs index template")
        except RequestError as e:
            if e.error == "resource_already_exists_exception":
                logger.info("Logs index template already exists")
            else:
                raise
        
        # Create alerts template
        try:
            await es.indices.put_index_template(
                name="alerts",
                **ALERT_TEMPLATE
            )
            logger.info("Created alerts index template")
        except RequestError as e:
            if e.error == "resource_already_exists_exception":
                logger.info("Alerts index template already exists")
            else:
                raise
        
    except Exception as e:
        logger.error(
            "Failed to create index templates",
            error=str(e)
        )
        raise

async def create_initial_indices(es: AsyncElasticsearch):
    """Create initial indices with aliases."""
    try:
        # Create initial logs index
        if not await es.indices.exists(index="logs-000001"):
            await es.indices.create(
                index="logs-000001",
                aliases={
                    "logs": {
                        "is_write_index": True
                    },
                    "logs-read": {}
                }
            )
            logger.info("Created initial logs index")
        else:
            logger.info("Initial logs index already exists")
        
        # Create initial alerts index
        if not await es.indices.exists(index="alerts-000001"):
            await es.indices.create(
                index="alerts-000001",
                aliases={
                    "alerts": {
                        "is_write_index": True
                    },
                    "alerts-read": {}
                }
            )
            logger.info("Created initial alerts index")
        else:
            logger.info("Initial alerts index already exists")
        
    except Exception as e:
        logger.error(
            "Failed to create initial indices",
            error=str(e)
        )
        raise

async def verify_setup(es: AsyncElasticsearch):
    """Verify Elasticsearch setup."""
    try:
        # Check ILM policies
        policies = await es.ilm.get_lifecycle()
        assert "logs-policy" in policies
        assert "alerts-policy" in policies
        
        # Check index templates
        templates = await es.indices.get_index_template(name=["logs", "alerts"])
        assert len(templates["index_templates"]) == 2
        
        # Check indices and aliases
        indices = await es.indices.get_alias(index=["logs-*", "alerts-*"])
        assert any(index.startswith("logs-") for index in indices)
        assert any(index.startswith("alerts-") for index in indices)
        
        logger.info("Elasticsearch setup verification successful")
        
    except Exception as e:
        logger.error(
            "Failed to verify Elasticsearch setup",
            error=str(e)
        )
        raise

if __name__ == "__main__":
    # Run setup when script is executed directly
    asyncio.run(setup_elasticsearch()) 