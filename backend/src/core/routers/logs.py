from typing import Dict, List, Optional, Union, Any
from datetime import datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ...data.connectors.elasticsearch import es_connector
from ...data.connectors.kafka import kafka_connector
from ...utils.logging import LoggerMixin
from ...utils.auth import get_current_user
from ...data.models.user import User

router = APIRouter(prefix="/logs", tags=["logs"])
logger = LoggerMixin().get_logger()

class LogSearchParams(BaseModel):
    """Parameters for log search."""
    query: str = Field(..., description="Search query string")
    source: Optional[List[str]] = Field(None, description="Log sources to search")
    severity: Optional[List[str]] = Field(None, description="Severity levels to include")
    start_time: datetime = Field(..., description="Start time for search")
    end_time: datetime = Field(..., description="End time for search")
    size: int = Field(10, ge=1, le=10000, description="Number of results to return")
    from_: int = Field(0, ge=0, description="Starting offset for pagination")
    sort: Optional[List[Dict[str, str]]] = Field(None, description="Sort criteria")

class LogIngestParams(BaseModel):
    """Parameters for log ingestion."""
    source: str = Field(..., description="Log source identifier")
    logs: List[Dict[str, Any]] = Field(..., description="List of logs to ingest")

@router.post("/search", response_model=Dict[str, Any])
async def search_logs(
    params: LogSearchParams,
    current_user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    """Search logs with advanced filtering."""
    try:
        # Build Elasticsearch query
        query = {
            "bool": {
                "must": [
                    {"query_string": {"query": params.query}},
                    {
                        "range": {
                            "@timestamp": {
                                "gte": params.start_time.isoformat(),
                                "lte": params.end_time.isoformat()
                            }
                        }
                    }
                ]
            }
        }
        
        # Add source filter
        if params.source:
            query["bool"]["must"].append({
                "terms": {"source": params.source}
            })
        
        # Add severity filter
        if params.severity:
            query["bool"]["must"].append({
                "terms": {"severity": params.severity}
            })
        
        # Add aggregations for analytics
        aggs = {
            "sources": {
                "terms": {"field": "source"}
            },
            "severity_levels": {
                "terms": {"field": "severity"}
            },
            "timeline": {
                "date_histogram": {
                    "field": "@timestamp",
                    "calendar_interval": "hour"
                }
            }
        }
        
        # Execute search
        result = await es_connector.search(
            index="logs-*",
            query=query,
            size=params.size,
            from_=params.from_,
            sort=params.sort or [{"@timestamp": "desc"}],
            aggs=aggs
        )
        
        logger.info(
            "Log search executed successfully",
            user_id=str(current_user.id),
            params=params.model_dump()
        )
        
        return result
        
    except Exception as e:
        logger.error(
            "Failed to search logs",
            error=str(e),
            user_id=str(current_user.id),
            params=params.model_dump()
        )
        raise HTTPException(
            status_code=500,
            detail="Failed to search logs"
        )

@router.post("/ingest")
async def ingest_logs(
    params: LogIngestParams,
    current_user: User = Depends(get_current_user)
) -> JSONResponse:
    """Ingest logs into the system."""
    try:
        # Validate source
        if params.source not in ["syslog", "windows", "aws_cloudtrail", "kubernetes"]:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid log source: {params.source}"
            )
        
        # Send logs to Kafka for processing
        for log in params.logs:
            await kafka_connector.send_message(
                topic=f"logs.{params.source}",
                message=log
            )
        
        logger.info(
            "Logs ingested successfully",
            user_id=str(current_user.id),
            source=params.source,
            count=len(params.logs)
        )
        
        return JSONResponse(
            content={
                "message": "Logs ingested successfully",
                "count": len(params.logs)
            },
            status_code=202
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Failed to ingest logs",
            error=str(e),
            user_id=str(current_user.id),
            source=params.source
        )
        raise HTTPException(
            status_code=500,
            detail="Failed to ingest logs"
        )

@router.get("/sources")
async def get_log_sources(
    current_user: User = Depends(get_current_user)
) -> List[str]:
    """Get available log sources."""
    try:
        # Query unique sources from Elasticsearch
        result = await es_connector.search(
            index="logs-*",
            aggs={
                "sources": {
                    "terms": {"field": "source"}
                }
            },
            size=0
        )
        
        sources = [
            bucket["key"]
            for bucket in result.get("aggregations", {}).get("sources", {}).get("buckets", [])
        ]
        
        logger.info(
            "Retrieved log sources successfully",
            user_id=str(current_user.id)
        )
        
        return sources
        
    except Exception as e:
        logger.error(
            "Failed to get log sources",
            error=str(e),
            user_id=str(current_user.id)
        )
        raise HTTPException(
            status_code=500,
            detail="Failed to get log sources"
        )

@router.get("/stats")
async def get_log_stats(
    start_time: datetime = Query(...),
    end_time: datetime = Query(...),
    current_user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    """Get log statistics for the specified time range."""
    try:
        # Query Elasticsearch for stats
        result = await es_connector.search(
            index="logs-*",
            query={
                "range": {
                    "@timestamp": {
                        "gte": start_time.isoformat(),
                        "lte": end_time.isoformat()
                    }
                }
            },
            aggs={
                "total_logs": {"value_count": {"field": "@id"}},
                "sources": {
                    "terms": {"field": "source"}
                },
                "severity_levels": {
                    "terms": {"field": "severity"}
                },
                "timeline": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "calendar_interval": "hour"
                    }
                }
            },
            size=0
        )
        
        logger.info(
            "Retrieved log stats successfully",
            user_id=str(current_user.id),
            start_time=start_time.isoformat(),
            end_time=end_time.isoformat()
        )
        
        return {
            "total_logs": result["aggregations"]["total_logs"]["value"],
            "sources": {
                bucket["key"]: bucket["doc_count"]
                for bucket in result["aggregations"]["sources"]["buckets"]
            },
            "severity_levels": {
                bucket["key"]: bucket["doc_count"]
                for bucket in result["aggregations"]["severity_levels"]["buckets"]
            },
            "timeline": [
                {
                    "timestamp": bucket["key_as_string"],
                    "count": bucket["doc_count"]
                }
                for bucket in result["aggregations"]["timeline"]["buckets"]
            ]
        }
        
    except Exception as e:
        logger.error(
            "Failed to get log stats",
            error=str(e),
            user_id=str(current_user.id),
            start_time=start_time.isoformat(),
            end_time=end_time.isoformat()
        )
        raise HTTPException(
            status_code=500,
            detail="Failed to get log stats"
        )

@router.delete("/{log_id}")
async def delete_log(
    log_id: UUID,
    current_user: User = Depends(get_current_user)
) -> JSONResponse:
    """Delete a specific log entry."""
    try:
        # Check user permissions
        if not current_user.role in ["admin", "security_analyst"]:
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions to delete logs"
            )
        
        # Delete from Elasticsearch
        success = await es_connector.delete_document(
            index="logs-*",
            doc_id=str(log_id)
        )
        
        if not success:
            raise HTTPException(
                status_code=404,
                detail=f"Log {log_id} not found"
            )
        
        logger.info(
            "Log deleted successfully",
            user_id=str(current_user.id),
            log_id=str(log_id)
        )
        
        return JSONResponse(
            content={"message": "Log deleted successfully"},
            status_code=200
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Failed to delete log",
            error=str(e),
            user_id=str(current_user.id),
            log_id=str(log_id)
        )
        raise HTTPException(
            status_code=500,
            detail="Failed to delete log"
        ) 