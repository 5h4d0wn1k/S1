from typing import Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from ..auth import User, requires_permissions
from ...engines.ai.pipeline import (
    PredictionResult,
    ModelMetrics,
    ml_pipeline
)
from ...utils.logging import LoggerMixin

router = APIRouter()
logger = LoggerMixin()

# Request Models
class ThreatAnalysisRequest(BaseModel):
    text: str
    context: Optional[Dict[str, str]] = None

class AnomalyDetectionRequest(BaseModel):
    features: List[float]
    context: Optional[Dict[str, str]] = None

class QueryAnalysisRequest(BaseModel):
    query: str
    context: Optional[Dict[str, str]] = None

@router.post("/threats/analyze", response_model=PredictionResult)
async def analyze_threat(
    request: ThreatAnalysisRequest,
    current_user: User = Depends(requires_permissions("ai:predict"))
) -> PredictionResult:
    """Analyze text for security threats."""
    try:
        logger.log_info(
            "Analyzing threat",
            text_length=len(request.text),
            user=current_user.username
        )
        
        result = await ml_pipeline.predict_threat(
            request.text,
            request.context
        )
        
        return result
    except Exception as e:
        logger.log_error(
            "Threat analysis failed",
            error=e,
            text_length=len(request.text),
            user=current_user.username
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to analyze threat"
        )

@router.post("/anomalies/detect", response_model=PredictionResult)
async def detect_anomaly(
    request: AnomalyDetectionRequest,
    current_user: User = Depends(requires_permissions("ai:predict"))
) -> PredictionResult:
    """Detect anomalies in feature vectors."""
    try:
        logger.log_info(
            "Detecting anomalies",
            features_count=len(request.features),
            user=current_user.username
        )
        
        result = await ml_pipeline.detect_anomaly(
            request.features,
            request.context
        )
        
        return result
    except Exception as e:
        logger.log_error(
            "Anomaly detection failed",
            error=e,
            features_count=len(request.features),
            user=current_user.username
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to detect anomalies"
        )

@router.post("/queries/analyze", response_model=PredictionResult)
async def analyze_query(
    request: QueryAnalysisRequest,
    current_user: User = Depends(requires_permissions("ai:predict"))
) -> PredictionResult:
    """Analyze natural language security queries."""
    try:
        logger.log_info(
            "Analyzing query",
            query=request.query,
            user=current_user.username
        )
        
        result = await ml_pipeline.analyze_query(
            request.query,
            request.context
        )
        
        return result
    except Exception as e:
        logger.log_error(
            "Query analysis failed",
            error=e,
            query=request.query,
            user=current_user.username
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to analyze query"
        )

@router.get("/models/metrics", response_model=Dict[str, ModelMetrics])
async def get_model_metrics(
    current_user: User = Depends(requires_permissions("ai:metrics:read"))
) -> Dict[str, ModelMetrics]:
    """Get performance metrics for all models."""
    try:
        logger.log_info(
            "Retrieving model metrics",
            user=current_user.username
        )
        
        return ml_pipeline.metrics
    except Exception as e:
        logger.log_error(
            "Failed to get model metrics",
            error=e,
            user=current_user.username
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get model metrics"
        )

@router.post("/models/{model_type}/train")
async def train_model(
    model_type: str,
    training_data: Dict[str, Any],
    current_user: User = Depends(requires_permissions("ai:models:train"))
) -> Dict[str, str]:
    """Train or fine-tune a specific model."""
    try:
        logger.log_info(
            "Training model",
            model_type=model_type,
            data_size=len(training_data),
            user=current_user.username
        )
        
        # Queue training job
        await ml_pipeline.training_queue.put({
            "model_type": model_type,
            **training_data
        })
        
        return {"message": "Training job queued successfully"}
    except Exception as e:
        logger.log_error(
            "Failed to queue training job",
            error=e,
            model_type=model_type,
            user=current_user.username
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to queue training job"
        ) 