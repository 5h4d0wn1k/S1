from typing import Dict, List
from fastapi import APIRouter, Depends, HTTPException, status

from ..auth import User, requires_permissions
from ...data.pipeline.processor import LogEvent, data_processor
from ...utils.logging import LoggerMixin

router = APIRouter()
logger = LoggerMixin()

@router.post("/ingest", response_model=Dict[str, str])
async def ingest_log(
    log_event: LogEvent,
    current_user: User = Depends(requires_permissions("data:ingest"))
) -> Dict[str, str]:
    """Ingest a log event into the pipeline."""
    try:
        logger.log_info(
            "Ingesting log event",
            source=log_event.source,
            event_type=log_event.event_type,
            user=current_user.username
        )
        
        await data_processor.ingest_log(log_event)
        return {"message": "Log event ingested successfully"}
    except Exception as e:
        logger.log_error(
            "Failed to ingest log event",
            error=e,
            source=log_event.source,
            user=current_user.username
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to ingest log event"
        )

@router.post("/batch/ingest", response_model=Dict[str, str])
async def batch_ingest_logs(
    log_events: List[LogEvent],
    current_user: User = Depends(requires_permissions("data:ingest"))
) -> Dict[str, str]:
    """Batch ingest multiple log events."""
    try:
        logger.log_info(
            "Batch ingesting log events",
            count=len(log_events),
            user=current_user.username
        )
        
        for event in log_events:
            await data_processor.ingest_log(event)
        
        return {
            "message": f"Successfully ingested {len(log_events)} log events"
        }
    except Exception as e:
        logger.log_error(
            "Failed to batch ingest log events",
            error=e,
            count=len(log_events),
            user=current_user.username
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to batch ingest log events"
        )

@router.get("/pipeline/status", response_model=Dict[str, Any])
async def get_pipeline_status(
    current_user: User = Depends(requires_permissions("data:status:read"))
) -> Dict[str, Any]:
    """Get the current status of the data pipeline."""
    try:
        logger.log_info(
            "Retrieving pipeline status",
            user=current_user.username
        )
        
        return {
            "running": data_processor.running,
            "enrichment_queue_size": data_processor.enrichment_queue.qsize(),
            "alert_queue_size": data_processor.alert_queue.qsize(),
            "kafka_topics": ["logs", "events", "alerts"]
        }
    except Exception as e:
        logger.log_error(
            "Failed to get pipeline status",
            error=e,
            user=current_user.username
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get pipeline status"
        )

@router.post("/pipeline/start", response_model=Dict[str, str])
async def start_pipeline(
    current_user: User = Depends(requires_permissions("data:pipeline:manage"))
) -> Dict[str, str]:
    """Start the data processing pipeline."""
    try:
        logger.log_info(
            "Starting pipeline",
            user=current_user.username
        )
        
        await data_processor.start()
        return {"message": "Pipeline started successfully"}
    except Exception as e:
        logger.log_error(
            "Failed to start pipeline",
            error=e,
            user=current_user.username
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to start pipeline"
        )

@router.post("/pipeline/stop", response_model=Dict[str, str])
async def stop_pipeline(
    current_user: User = Depends(requires_permissions("data:pipeline:manage"))
) -> Dict[str, str]:
    """Stop the data processing pipeline."""
    try:
        logger.log_info(
            "Stopping pipeline",
            user=current_user.username
        )
        
        await data_processor.stop()
        return {"message": "Pipeline stopped successfully"}
    except Exception as e:
        logger.log_error(
            "Failed to stop pipeline",
            error=e,
            user=current_user.username
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to stop pipeline"
        ) 