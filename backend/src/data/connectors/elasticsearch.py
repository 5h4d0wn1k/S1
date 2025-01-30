from typing import Dict, List, Optional, Union, Any
from datetime import datetime, timedelta
import json
import asyncio

from elasticsearch import AsyncElasticsearch
from elasticsearch.exceptions import ElasticsearchException, NotFoundError
from elasticsearch.helpers import async_bulk

from ...core.settings import get_settings
from ...utils.logging import LoggerMixin

settings = get_settings()

class ElasticsearchConnector(LoggerMixin):
    """Elasticsearch connector for log storage and search."""
    
    def __init__(self):
        """Initialize Elasticsearch connection."""
        super().__init__()
        self.client = None
        self._initialize_connection()
    
    def _initialize_connection(self):
        """Initialize Elasticsearch client."""
        try:
            # Create client with SSL if enabled
            self.client = AsyncElasticsearch(
                hosts=[{
                    'host': settings.ELASTICSEARCH_HOST,
                    'port': settings.ELASTICSEARCH_PORT,
                    'scheme': 'https' if settings.ELASTICSEARCH_USE_SSL else 'http'
                }],
                basic_auth=(
                    settings.ELASTICSEARCH_USER,
                    settings.ELASTICSEARCH_PASSWORD
                ) if settings.ELASTICSEARCH_USER else None,
                verify_certs=settings.ELASTICSEARCH_VERIFY_CERTS,
                ca_certs=settings.ELASTICSEARCH_CA_CERTS,
                client_cert=settings.ELASTICSEARCH_CLIENT_CERT,
                client_key=settings.ELASTICSEARCH_CLIENT_KEY,
                timeout=30,
                max_retries=5,
                retry_on_timeout=True
            )
            
            self.log_info("Elasticsearch client initialized successfully")
            
        except Exception as e:
            self.log_error("Failed to initialize Elasticsearch client", error=e)
            raise
    
    async def create_index(
        self,
        index: str,
        mappings: Dict[str, Any],
        settings: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Create an Elasticsearch index with mappings and settings."""
        try:
            # Check if index exists
            if await self.client.indices.exists(index=index):
                self.log_warning(f"Index {index} already exists")
                return False
            
            # Create index with mappings and settings
            await self.client.indices.create(
                index=index,
                mappings=mappings,
                settings=settings or {
                    "number_of_shards": 3,
                    "number_of_replicas": 1
                }
            )
            
            self.log_info(f"Index {index} created successfully")
            return True
            
        except Exception as e:
            self.log_error(
                "Failed to create index",
                error=e,
                index=index
            )
            raise
    
    async def delete_index(self, index: str) -> bool:
        """Delete an Elasticsearch index."""
        try:
            # Check if index exists
            if not await self.client.indices.exists(index=index):
                self.log_warning(f"Index {index} does not exist")
                return False
            
            # Delete index
            await self.client.indices.delete(index=index)
            
            self.log_info(f"Index {index} deleted successfully")
            return True
            
        except Exception as e:
            self.log_error(
                "Failed to delete index",
                error=e,
                index=index
            )
            raise
    
    async def index_document(
        self,
        index: str,
        document: Dict[str, Any],
        doc_id: Optional[str] = None,
        refresh: bool = False
    ) -> str:
        """Index a single document."""
        try:
            result = await self.client.index(
                index=index,
                document=document,
                id=doc_id,
                refresh=refresh
            )
            
            return result["_id"]
            
        except Exception as e:
            self.log_error(
                "Failed to index document",
                error=e,
                index=index,
                doc_id=doc_id
            )
            raise
    
    async def bulk_index(
        self,
        index: str,
        documents: List[Dict[str, Any]],
        chunk_size: int = 500
    ) -> Dict[str, int]:
        """Bulk index multiple documents."""
        try:
            # Prepare actions
            actions = [
                {
                    "_index": index,
                    "_source": doc,
                    "_id": doc.get("id")
                }
                for doc in documents
            ]
            
            # Perform bulk indexing
            success, failed = 0, 0
            async for ok, result in async_bulk(
                self.client,
                actions,
                chunk_size=chunk_size,
                raise_on_error=False
            ):
                if ok:
                    success += 1
                else:
                    failed += 1
                    self.log_error(
                        "Failed to index document in bulk",
                        error=result
                    )
            
            return {
                "indexed": success,
                "failed": failed
            }
            
        except Exception as e:
            self.log_error(
                "Failed to perform bulk indexing",
                error=e,
                index=index,
                doc_count=len(documents)
            )
            raise
    
    async def search(
        self,
        index: str,
        query: Dict[str, Any],
        size: int = 10,
        from_: int = 0,
        sort: Optional[List[Dict[str, Any]]] = None,
        source: Optional[Union[List[str], bool]] = None,
        aggs: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Perform a search query."""
        try:
            result = await self.client.search(
                index=index,
                query=query,
                size=size,
                from_=from_,
                sort=sort,
                _source=source,
                aggs=aggs
            )
            
            return {
                "total": result["hits"]["total"]["value"],
                "hits": result["hits"]["hits"],
                "aggregations": result.get("aggregations")
            }
            
        except Exception as e:
            self.log_error(
                "Failed to perform search",
                error=e,
                index=index,
                query=query
            )
            raise
    
    async def get_document(
        self,
        index: str,
        doc_id: str,
        source: Optional[Union[List[str], bool]] = None
    ) -> Optional[Dict[str, Any]]:
        """Get a document by ID."""
        try:
            result = await self.client.get(
                index=index,
                id=doc_id,
                _source=source
            )
            return result["_source"]
            
        except NotFoundError:
            return None
        except Exception as e:
            self.log_error(
                "Failed to get document",
                error=e,
                index=index,
                doc_id=doc_id
            )
            raise
    
    async def update_document(
        self,
        index: str,
        doc_id: str,
        update: Dict[str, Any],
        upsert: bool = False
    ) -> bool:
        """Update a document by ID."""
        try:
            await self.client.update(
                index=index,
                id=doc_id,
                body={"doc": update},
                doc_as_upsert=upsert
            )
            return True
            
        except NotFoundError:
            return False
        except Exception as e:
            self.log_error(
                "Failed to update document",
                error=e,
                index=index,
                doc_id=doc_id
            )
            raise
    
    async def delete_document(
        self,
        index: str,
        doc_id: str
    ) -> bool:
        """Delete a document by ID."""
        try:
            await self.client.delete(
                index=index,
                id=doc_id
            )
            return True
            
        except NotFoundError:
            return False
        except Exception as e:
            self.log_error(
                "Failed to delete document",
                error=e,
                index=index,
                doc_id=doc_id
            )
            raise
    
    async def scroll(
        self,
        index: str,
        query: Dict[str, Any],
        size: int = 1000,
        scroll: str = "5m"
    ) -> AsyncGenerator[List[Dict[str, Any]], None]:
        """Scroll through large result sets."""
        try:
            # Initial search
            result = await self.client.search(
                index=index,
                query=query,
                size=size,
                scroll=scroll
            )
            
            scroll_id = result["_scroll_id"]
            hits = result["hits"]["hits"]
            
            while hits:
                yield hits
                
                # Get next batch
                result = await self.client.scroll(
                    scroll_id=scroll_id,
                    scroll=scroll
                )
                scroll_id = result["_scroll_id"]
                hits = result["hits"]["hits"]
                
        except Exception as e:
            self.log_error(
                "Failed to scroll results",
                error=e,
                index=index,
                query=query
            )
            raise
        finally:
            # Clear scroll
            if scroll_id:
                try:
                    await self.client.clear_scroll(
                        scroll_id=scroll_id
                    )
                except Exception as e:
                    self.log_error(
                        "Failed to clear scroll",
                        error=e,
                        scroll_id=scroll_id
                    )
    
    async def close(self):
        """Close Elasticsearch connection."""
        try:
            if self.client:
                await self.client.close()
                self.log_info("Elasticsearch connection closed")
                
        except Exception as e:
            self.log_error("Failed to close Elasticsearch connection", error=e)
            raise

# Create singleton instance
es_connector = ElasticsearchConnector() 