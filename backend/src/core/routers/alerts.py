from typing import Dict, List, Optional, Union, Any
from datetime import datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ...data.connectors.elasticsearch import es_connector
from ...data.connectors.kafka import kafka_connector
from ...data.connectors.redis import redis_connector
from ...utils.logging import LoggerMixin
from ...utils.auth import get_current_user
from ...data.models.user import User
from ...data.models.alert import Alert, AlertSeverity, AlertCategory

router = APIRouter(prefix="/alerts", tags=["alerts"])
logger = LoggerMixin().get_logger()

class AlertSearchParams(BaseModel):
    """Parameters for alert search."""
    query: Optional[str] = Field(None, description="Search query string")
    severity: Optional[List[AlertSeverity]] = Field(None, description="Alert severities to include")
    category: Optional[List[AlertCategory]] = Field(None, description="Alert categories to include")
    start_time: datetime = Field(..., description="Start time for search")
    end_time: datetime = Field(..., description="End time for search")
    size: int = Field(10, ge=1, le=10000, description="Number of results to return")
    from_: int = Field(0, ge=0, description="Starting offset for pagination")
    sort: Optional[List[Dict[str, str]]] = Field(None, description="Sort criteria")

class AlertUpdateParams(BaseModel):
    """Parameters for alert update."""
    status: Optional[str] = Field(None, description="Alert status")
    assignee: Optional[UUID] = Field(None, description="Assigned user ID")
    notes: Optional[str] = Field(None, description="Alert notes")
    tags: Optional[List[str]] = Field(None, description="Alert tags")

@router.post("/search", response_model=Dict[str, Any])
async def search_alerts(
    params: AlertSearchParams,
    current_user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    """Search alerts with advanced filtering."""
    try:
        # Build Elasticsearch query
        query = {
            "bool": {
                "must": [
                    {
                        "range": {
                            "timestamp": {
                                "gte": params.start_time.isoformat(),
                                "lte": params.end_time.isoformat()
                            }
                        }
                    }
                ]
            }
        }
        
        # Add query string if provided
        if params.query:
            query["bool"]["must"].append({
                "query_string": {"query": params.query}
            })
        
        # Add severity filter
        if params.severity:
            query["bool"]["must"].append({
                "terms": {"severity": [s.value for s in params.severity]}
            })
        
        # Add category filter
        if params.category:
            query["bool"]["must"].append({
                "terms": {"category": [c.value for c in params.category]}
            })
        
        # Add aggregations for analytics
        aggs = {
            "severity_breakdown": {
                "terms": {"field": "severity"}
            },
            "category_breakdown": {
                "terms": {"field": "category"}
            },
            "timeline": {
                "date_histogram": {
                    "field": "timestamp",
                    "calendar_interval": "hour"
                }
            }
        }
        
        # Execute search
        result = await es_connector.search(
            index="alerts-*",
            query=query,
            size=params.size,
            from_=params.from_,
            sort=params.sort or [{"timestamp": "desc"}],
            aggs=aggs
        )
        
        logger.info(
            "Alert search executed successfully",
            user_id=str(current_user.id),
            params=params.model_dump()
        )
        
        return result
        
    except Exception as e:
        logger.error(
            "Failed to search alerts",
            error=str(e),
            user_id=str(current_user.id),
            params=params.model_dump()
        )
        raise HTTPException(
            status_code=500,
            detail="Failed to search alerts"
        )

@router.get("/{alert_id}", response_model=Alert)
async def get_alert(
    alert_id: UUID,
    current_user: User = Depends(get_current_user)
) -> Alert:
    """Get a specific alert by ID."""
    try:
        # Get from Elasticsearch
        doc = await es_connector.get_document(
            index="alerts-*",
            doc_id=str(alert_id)
        )
        
        if not doc:
            raise HTTPException(
                status_code=404,
                detail=f"Alert {alert_id} not found"
            )
        
        logger.info(
            "Alert retrieved successfully",
            user_id=str(current_user.id),
            alert_id=str(alert_id)
        )
        
        return Alert(**doc)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Failed to get alert",
            error=str(e),
            user_id=str(current_user.id),
            alert_id=str(alert_id)
        )
        raise HTTPException(
            status_code=500,
            detail="Failed to get alert"
        )

@router.patch("/{alert_id}")
async def update_alert(
    alert_id: UUID,
    params: AlertUpdateParams,
    current_user: User = Depends(get_current_user)
) -> JSONResponse:
    """Update alert details."""
    try:
        # Get current alert
        doc = await es_connector.get_document(
            index="alerts-*",
            doc_id=str(alert_id)
        )
        
        if not doc:
            raise HTTPException(
                status_code=404,
                detail=f"Alert {alert_id} not found"
            )
        
        # Update fields
        update = {}
        if params.status:
            update["status"] = params.status
        if params.assignee:
            update["assignee"] = str(params.assignee)
        if params.notes:
            update["notes"] = params.notes
        if params.tags:
            update["tags"] = params.tags
        
        # Add audit trail
        update["updated_at"] = datetime.utcnow().isoformat()
        update["updated_by"] = str(current_user.id)
        
        # Update in Elasticsearch
        success = await es_connector.update_document(
            index="alerts-*",
            doc_id=str(alert_id),
            update=update
        )
        
        if not success:
            raise HTTPException(
                status_code=500,
                detail="Failed to update alert"
            )
        
        # Send update notification to Kafka
        await kafka_connector.send_message(
            topic="alerts.updated",
            message={
                "alert_id": str(alert_id),
                "updates": update,
                "user_id": str(current_user.id)
            }
        )
        
        logger.info(
            "Alert updated successfully",
            user_id=str(current_user.id),
            alert_id=str(alert_id),
            updates=update
        )
        
        return JSONResponse(
            content={"message": "Alert updated successfully"},
            status_code=200
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Failed to update alert",
            error=str(e),
            user_id=str(current_user.id),
            alert_id=str(alert_id)
        )
        raise HTTPException(
            status_code=500,
            detail="Failed to update alert"
        )

@router.get("/stats")
async def get_alert_stats(
    start_time: datetime = Query(...),
    end_time: datetime = Query(...),
    current_user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    """Get alert statistics for the specified time range."""
    try:
        # Query Elasticsearch for stats
        result = await es_connector.search(
            index="alerts-*",
            query={
                "range": {
                    "timestamp": {
                        "gte": start_time.isoformat(),
                        "lte": end_time.isoformat()
                    }
                }
            },
            aggs={
                "total_alerts": {"value_count": {"field": "id"}},
                "severity_breakdown": {
                    "terms": {"field": "severity"}
                },
                "category_breakdown": {
                    "terms": {"field": "category"}
                },
                "status_breakdown": {
                    "terms": {"field": "status"}
                },
                "timeline": {
                    "date_histogram": {
                        "field": "timestamp",
                        "calendar_interval": "hour"
                    }
                }
            },
            size=0
        )
        
        # Get real-time stats from Redis
        active_alerts = await redis_connector.get("active_alerts_count", 0)
        
        logger.info(
            "Retrieved alert stats successfully",
            user_id=str(current_user.id),
            start_time=start_time.isoformat(),
            end_time=end_time.isoformat()
        )
        
        return {
            "total_alerts": result["aggregations"]["total_alerts"]["value"],
            "active_alerts": active_alerts,
            "severity_breakdown": {
                bucket["key"]: bucket["doc_count"]
                for bucket in result["aggregations"]["severity_breakdown"]["buckets"]
            },
            "category_breakdown": {
                bucket["key"]: bucket["doc_count"]
                for bucket in result["aggregations"]["category_breakdown"]["buckets"]
            },
            "status_breakdown": {
                bucket["key"]: bucket["doc_count"]
                for bucket in result["aggregations"]["status_breakdown"]["buckets"]
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
            "Failed to get alert stats",
            error=str(e),
            user_id=str(current_user.id),
            start_time=start_time.isoformat(),
            end_time=end_time.isoformat()
        )
        raise HTTPException(
            status_code=500,
            detail="Failed to get alert stats"
        )

@router.post("/bulk_update")
async def bulk_update_alerts(
    alert_ids: List[UUID],
    params: AlertUpdateParams,
    current_user: User = Depends(get_current_user)
) -> JSONResponse:
    """Update multiple alerts in bulk."""
    try:
        # Check user permissions
        if not current_user.role in ["admin", "security_analyst"]:
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions for bulk update"
            )
        
        # Prepare update
        update = {}
        if params.status:
            update["status"] = params.status
        if params.assignee:
            update["assignee"] = str(params.assignee)
        if params.notes:
            update["notes"] = params.notes
        if params.tags:
            update["tags"] = params.tags
        
        # Add audit trail
        update["updated_at"] = datetime.utcnow().isoformat()
        update["updated_by"] = str(current_user.id)
        
        # Update each alert
        success_count = 0
        for alert_id in alert_ids:
            try:
                success = await es_connector.update_document(
                    index="alerts-*",
                    doc_id=str(alert_id),
                    update=update
                )
                if success:
                    success_count += 1
                    
                    # Send update notification to Kafka
                    await kafka_connector.send_message(
                        topic="alerts.updated",
                        message={
                            "alert_id": str(alert_id),
                            "updates": update,
                            "user_id": str(current_user.id)
                        }
                    )
            except Exception as e:
                logger.error(
                    "Failed to update alert in bulk operation",
                    error=str(e),
                    alert_id=str(alert_id)
                )
        
        logger.info(
            "Bulk alert update completed",
            user_id=str(current_user.id),
            total=len(alert_ids),
            success=success_count,
            failed=len(alert_ids) - success_count
        )
        
        return JSONResponse(
            content={
                "message": "Bulk update completed",
                "total": len(alert_ids),
                "success": success_count,
                "failed": len(alert_ids) - success_count
            },
            status_code=200
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Failed to perform bulk alert update",
            error=str(e),
            user_id=str(current_user.id),
            alert_count=len(alert_ids)
        )
        raise HTTPException(
            status_code=500,
            detail="Failed to perform bulk alert update"
        ) 