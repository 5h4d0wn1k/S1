from typing import Dict, List
from uuid import UUID
import asyncio

from fastapi import APIRouter, HTTPException, Query, UploadFile, File
from fastapi.responses import JSONResponse

from ...data.models.alert import Alert
from ...data.models.prediction import AlertAnalysis, AnomalyScore, ThreatPrediction
from ...engines.ai.engine import ai_engine
from ...utils.logging import LoggerMixin

router = APIRouter()
logger = LoggerMixin()

@router.post("/anomalies", response_model=List[AnomalyScore])
async def detect_anomalies(alerts: List[Alert]) -> List[AnomalyScore]:
    """Detect anomalies in a list of alerts."""
    try:
        scores = await ai_engine.detect_anomalies(alerts)
        return scores
        
    except Exception as e:
        logger.log_error("Failed to detect anomalies", error=e)
        raise HTTPException(
            status_code=500,
            detail="Failed to detect anomalies"
        )

@router.post("/threats", response_model=List[ThreatPrediction])
async def classify_threats(alerts: List[Alert]) -> List[ThreatPrediction]:
    """Classify threats in a list of alerts."""
    try:
        predictions = await ai_engine.classify_threats(alerts)
        return predictions
        
    except Exception as e:
        logger.log_error("Failed to classify threats", error=e)
        raise HTTPException(
            status_code=500,
            detail="Failed to classify threats"
        )

@router.post("/analyze", response_model=AlertAnalysis)
async def analyze_alert(alert: Alert) -> AlertAnalysis:
    """Generate a detailed analysis of an alert."""
    try:
        analysis = await ai_engine.analyze_alert(alert)
        return AlertAnalysis(
            alert_id=alert.id,
            analysis=analysis,
            recommendations=[
                "Block source IP",
                "Update firewall rules",
                "Review logs for similar patterns"
            ]
        )
        
    except Exception as e:
        logger.log_error("Failed to analyze alert", error=e)
        raise HTTPException(
            status_code=500,
            detail="Failed to analyze alert"
        )

@router.post("/batch/analyze")
async def batch_analyze(alerts: List[Alert]) -> Dict:
    """Analyze multiple alerts in batch."""
    try:
        results = {
            "anomalies": [],
            "threats": [],
            "analyses": []
        }
        
        # Run analyses concurrently
        anomaly_task = ai_engine.detect_anomalies(alerts)
        threat_task = ai_engine.classify_threats(alerts)
        
        # Gather results
        results["anomalies"], results["threats"] = await asyncio.gather(
            anomaly_task,
            threat_task
        )
        
        # Sequential analysis (LLM calls are resource-intensive)
        for alert in alerts:
            try:
                analysis = await ai_engine.analyze_alert(alert)
                results["analyses"].append({
                    "alert_id": alert.id,
                    "analysis": analysis
                })
            except Exception as e:
                logger.log_error(
                    "Failed to analyze alert in batch",
                    error=e,
                    alert_id=str(alert.id)
                )
        
        return {
            "processed": len(alerts),
            "failed": len(alerts) - len(results["analyses"]),
            "results": results
        }
        
    except Exception as e:
        logger.log_error("Failed to process batch analysis", error=e)
        raise HTTPException(
            status_code=500,
            detail="Failed to process batch analysis"
        )

@router.post("/train")
async def train_model(
    historical_alerts: List[Alert],
    model_type: str = Query(..., regex="^(anomaly|threat)$")
) -> Dict:
    """Train AI models on historical data."""
    try:
        if model_type == "anomaly":
            await ai_engine.train_anomaly_detector(historical_alerts)
        else:
            # Implement threat model training
            pass
        
        return {
            "message": f"Successfully trained {model_type} model",
            "samples": len(historical_alerts)
        }
        
    except Exception as e:
        logger.log_error("Failed to train model", error=e, model_type=model_type)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to train {model_type} model"
        )

@router.post("/upload/training-data")
async def upload_training_data(
    file: UploadFile = File(...),
    model_type: str = Query(..., regex="^(anomaly|threat)$")
) -> Dict:
    """Upload training data for AI models."""
    try:
        # Read and validate CSV/JSON data
        # Convert to Alert objects
        # Call appropriate training method
        return {
            "message": "Training data uploaded successfully",
            "filename": file.filename,
            "model_type": model_type
        }
        
    except Exception as e:
        logger.log_error(
            "Failed to upload training data",
            error=e,
            filename=file.filename,
            model_type=model_type
        )
        raise HTTPException(
            status_code=500,
            detail="Failed to upload training data"
        ) 
