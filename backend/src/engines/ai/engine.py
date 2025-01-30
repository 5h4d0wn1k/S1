from typing import Dict, List, Optional, Union, Any
from datetime import datetime, timedelta
import asyncio
import json
import logging
from pathlib import Path

from fastapi import HTTPException
import numpy as np
import torch
from torch import nn
from transformers import AutoTokenizer, AutoModelForSequenceClassification, pipeline
from sklearn.preprocessing import StandardScaler
import pandas as pd
from sklearn.ensemble import IsolationForest

from ...core.settings import get_settings
from ...utils.logging import LoggerMixin
from ...data.models.alert import Alert
from ...data.models.prediction import ThreatPrediction, AnomalyScore, AlertAnalysis
from ...data.connectors.elasticsearch import es_connector
from ...data.connectors.kafka import kafka_connector

settings = get_settings()

logger = LoggerMixin().get_logger()

class AnomalyDetector:
    """Anomaly detection using Isolation Forest."""
    
    def __init__(self):
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42
        )
        self.feature_columns = [
            "request_count",
            "error_rate",
            "avg_response_time",
            "unique_ips",
            "unique_users",
            "data_transfer"
        ]
    
    async def train(self, start_time: datetime, end_time: datetime):
        """Train the anomaly detection model on historical data."""
        try:
            # Get training data from Elasticsearch
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
                    "metrics": {
                        "date_histogram": {
                            "field": "@timestamp",
                            "calendar_interval": "hour",
                            "extended_bounds": {
                                "min": start_time.isoformat(),
                                "max": end_time.isoformat()
                            }
                        },
                        "aggs": {
                            "request_count": {"value_count": {"field": "request_id"}},
                            "error_rate": {
                                "filters": {
                                    "filters": {
                                        "errors": {"match": {"level": "error"}}
                                    }
                                }
                            },
                            "avg_response_time": {"avg": {"field": "response_time"}},
                            "unique_ips": {"cardinality": {"field": "source_ip"}},
                            "unique_users": {"cardinality": {"field": "user_id"}},
                            "data_transfer": {"sum": {"field": "bytes"}}
                        }
                    }
                },
                size=0
            )
            
            # Transform data into features
            features = []
            for bucket in result["aggregations"]["metrics"]["buckets"]:
                features.append([
                    bucket["request_count"]["value"],
                    bucket["error_rate"]["buckets"]["errors"]["doc_count"] / bucket["request_count"]["value"],
                    bucket["avg_response_time"]["value"],
                    bucket["unique_ips"]["value"],
                    bucket["unique_users"]["value"],
                    bucket["data_transfer"]["value"]
                ])
            
            # Train model
            if features:
                self.model.fit(features)
                logger.info("Anomaly detection model trained successfully")
            else:
                logger.warning("No data available for training")
            
        except Exception as e:
            logger.error(
                "Failed to train anomaly detection model",
                error=str(e)
            )
            raise
    
    async def detect(self, features: Dict[str, float]) -> bool:
        """Detect if the given features represent an anomaly."""
        try:
            # Transform features into array
            feature_array = np.array([[
                features.get(col, 0) for col in self.feature_columns
            ]])
            
            # Predict (-1 for anomalies, 1 for normal)
            prediction = self.model.predict(feature_array)
            
            return prediction[0] == -1
            
        except Exception as e:
            logger.error(
                "Failed to detect anomaly",
                error=str(e),
                features=features
            )
            raise

class ThreatAnalyzer:
    """Threat analysis using transformer models."""
    
    def __init__(self):
        # Load pre-trained models
        self.classifier = pipeline(
            "text-classification",
            model="microsoft/mdeberta-v3-base",
            device=0 if torch.cuda.is_available() else -1
        )
        
        self.summarizer = pipeline(
            "summarization",
            model="facebook/bart-large-cnn",
            device=0 if torch.cuda.is_available() else -1
        )
    
    async def analyze_threat(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze threat details and provide insights."""
        try:
            # Prepare text for analysis
            text = f"""
            Alert Type: {alert_data.get('type')}
            Source: {alert_data.get('source')}
            Description: {alert_data.get('description')}
            Additional Context: {json.dumps(alert_data.get('context', {}))}
            """
            
            # Classify threat
            classification = await asyncio.to_thread(
                self.classifier,
                text,
                max_length=512
            )
            
            # Generate summary
            summary = await asyncio.to_thread(
                self.summarizer,
                text,
                max_length=130,
                min_length=30,
                do_sample=False
            )
            
            return {
                "classification": classification[0],
                "summary": summary[0]["summary_text"],
                "confidence": float(classification[0]["score"])
            }
            
        except Exception as e:
            logger.error(
                "Failed to analyze threat",
                error=str(e),
                alert_data=alert_data
            )
            raise

class AIEngine:
    """Main AI engine for security analytics."""
    
    def __init__(self):
        self.anomaly_detector = AnomalyDetector()
        self.threat_analyzer = ThreatAnalyzer()
        self.is_running = False
    
    async def start(self):
        """Start the AI engine."""
        try:
            self.is_running = True
            
            # Train initial anomaly detection model
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=7)
            await self.anomaly_detector.train(start_time, end_time)
            
            # Start processing loop
            while self.is_running:
                try:
                    # Process metrics for anomaly detection
                    await self._process_metrics()
                    
                    # Process alerts for threat analysis
                    await self._process_alerts()
                    
                    # Wait before next iteration
                    await asyncio.sleep(60)
                    
                except Exception as e:
                    logger.error(
                        "Error in AI engine processing loop",
                        error=str(e)
                    )
                    await asyncio.sleep(5)
            
        except Exception as e:
            logger.error(
                "Failed to start AI engine",
                error=str(e)
            )
            raise
    
    async def stop(self):
        """Stop the AI engine."""
        self.is_running = False
    
    async def _process_metrics(self):
        """Process system metrics for anomaly detection."""
        try:
            # Get latest metrics
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(minutes=5)
            
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
                    "request_count": {"value_count": {"field": "request_id"}},
                    "error_rate": {
                        "filters": {
                            "filters": {
                                "errors": {"match": {"level": "error"}}
                            }
                        }
                    },
                    "avg_response_time": {"avg": {"field": "response_time"}},
                    "unique_ips": {"cardinality": {"field": "source_ip"}},
                    "unique_users": {"cardinality": {"field": "user_id"}},
                    "data_transfer": {"sum": {"field": "bytes"}}
                },
                size=0
            )
            
            # Extract features
            features = {
                "request_count": result["aggregations"]["request_count"]["value"],
                "error_rate": result["aggregations"]["error_rate"]["buckets"]["errors"]["doc_count"] / result["aggregations"]["request_count"]["value"],
                "avg_response_time": result["aggregations"]["avg_response_time"]["value"],
                "unique_ips": result["aggregations"]["unique_ips"]["value"],
                "unique_users": result["aggregations"]["unique_users"]["value"],
                "data_transfer": result["aggregations"]["data_transfer"]["value"]
            }
            
            # Detect anomalies
            is_anomaly = await self.anomaly_detector.detect(features)
            
            if is_anomaly:
                # Create alert
                alert = {
                    "type": "anomaly",
                    "severity": "high",
                    "description": "Anomalous system behavior detected",
                    "features": features,
                    "timestamp": datetime.utcnow().isoformat()
                }
                
                # Send alert to Kafka
                await kafka_connector.send_message(
                    topic="alerts.anomaly",
                    message=alert
                )
                
                logger.warning(
                    "Anomaly detected",
                    features=features
                )
            
        except Exception as e:
            logger.error(
                "Failed to process metrics",
                error=str(e)
            )
            raise
    
    async def _process_alerts(self):
        """Process security alerts for threat analysis."""
        try:
            # Get unprocessed alerts
            result = await es_connector.search(
                index="alerts-*",
                query={
                    "bool": {
                        "must_not": {
                            "exists": {
                                "field": "ai_analysis"
                            }
                        }
                    }
                },
                sort=[{"timestamp": "desc"}],
                size=10
            )
            
            for alert in result["hits"]["hits"]:
                try:
                    # Analyze threat
                    analysis = await self.threat_analyzer.analyze_threat(
                        alert["_source"]
                    )
                    
                    # Update alert with analysis
                    await es_connector.update_document(
                        index=alert["_index"],
                        doc_id=alert["_id"],
                        update={
                            "ai_analysis": analysis,
                            "analyzed_at": datetime.utcnow().isoformat()
                        }
                    )
                    
                    logger.info(
                        "Alert analyzed successfully",
                        alert_id=alert["_id"],
                        analysis=analysis
                    )
                    
                except Exception as e:
                    logger.error(
                        "Failed to analyze alert",
                        error=str(e),
                        alert_id=alert["_id"]
                    )
            
        except Exception as e:
            logger.error(
                "Failed to process alerts",
                error=str(e)
            )
            raise

# Create singleton instance
ai_engine = AIEngine() 