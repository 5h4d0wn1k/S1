from datetime import datetime, timedelta
from typing import Dict, List, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from ..data.models.alert import Alert
from ..data.models.prediction import AnomalyScore, ThreatPrediction, AlertAnalysis
from ..engines.ai.engine import ai_engine
from ..utils.logging import LoggerMixin

class AIService(LoggerMixin):
    """Service for handling AI-related operations."""
    
    async def detect_anomalies(
        self,
        alerts: List[Alert]
    ) -> List[AnomalyScore]:
        """Detect anomalies in alerts."""
        try:
            anomaly_scores = []
            
            for alert in alerts:
                try:
                    # Extract features from alert
                    features = self._extract_features(alert)
                    
                    # Detect anomaly
                    is_anomaly = await ai_engine.anomaly_detector.detect(features)
                    
                    # Create anomaly score
                    score = AnomalyScore(
                        alert_id=alert.id,
                        score=features.get("anomaly_score", 0.0),
                        features=features,
                        threshold=0.75,  # TODO: Make configurable
                        is_anomaly=is_anomaly
                    )
                    
                    anomaly_scores.append(score)
                    
                except Exception as e:
                    self.log_error(
                        "Failed to detect anomaly for alert",
                        error=e,
                        alert_id=alert.id
                    )
            
            return anomaly_scores
            
        except Exception as e:
            self.log_error("Failed to detect anomalies", error=e)
            raise
    
    async def analyze_alert(self, alert: Alert) -> AlertAnalysis:
        """Analyze alert using AI."""
        try:
            # Get threat analysis
            threat_data = await ai_engine.threat_analyzer.analyze_threat(
                alert.model_dump()
            )
            
            # Create alert analysis
            analysis = AlertAnalysis(
                alert_id=alert.id,
                analysis=threat_data.get("analysis", ""),
                recommendations=threat_data.get("recommendations", []),
                risk_score=threat_data.get("risk_score"),
                context=threat_data.get("context", {})
            )
            
            # Find related alerts
            if "related_alerts" in threat_data:
                analysis.related_alerts = threat_data["related_alerts"]
            
            return analysis
            
        except Exception as e:
            self.log_error(
                "Failed to analyze alert",
                error=e,
                alert_id=alert.id
            )
            raise
    
    async def classify_threats(
        self,
        alerts: List[Alert]
    ) -> List[ThreatPrediction]:
        """Classify threats in alerts."""
        try:
            predictions = []
            
            for alert in alerts:
                try:
                    # Analyze threat
                    threat_data = await ai_engine.threat_analyzer.analyze_threat(
                        alert.model_dump()
                    )
                    
                    # Create prediction
                    prediction = ThreatPrediction(
                        alert_id=alert.id,
                        threat_type=threat_data.get("threat_type", "unknown"),
                        confidence=threat_data.get("confidence", 0.0),
                        evidence=threat_data.get("evidence", []),
                        severity=threat_data.get("severity", "unknown"),
                        tactics=threat_data.get("tactics", []),
                        techniques=threat_data.get("techniques", [])
                    )
                    
                    predictions.append(prediction)
                    
                except Exception as e:
                    self.log_error(
                        "Failed to classify threat for alert",
                        error=e,
                        alert_id=alert.id
                    )
            
            return predictions
            
        except Exception as e:
            self.log_error("Failed to classify threats", error=e)
            raise
    
    async def train_models(
        self,
        alerts: List[Alert],
        model_type: str
    ) -> Dict:
        """Train AI models."""
        try:
            if model_type == "anomaly":
                # Train anomaly detection model
                start_time = datetime.utcnow() - timedelta(days=30)
                await ai_engine.anomaly_detector.train(start_time, datetime.utcnow())
                return {"message": "Anomaly detection model trained successfully"}
                
            elif model_type == "threat":
                # Train threat analysis model
                # TODO: Implement threat model training
                return {"message": "Threat analysis model training not implemented"}
                
            else:
                raise ValueError(f"Invalid model type: {model_type}")
                
        except Exception as e:
            self.log_error("Failed to train models", error=e)
            raise
    
    async def process_metrics(self) -> None:
        """Process metrics for AI models."""
        try:
            await ai_engine._process_metrics()
        except Exception as e:
            self.log_error("Failed to process metrics", error=e)
            raise
    
    async def process_alerts(self) -> None:
        """Process alerts with AI models."""
        try:
            await ai_engine._process_alerts()
        except Exception as e:
            self.log_error("Failed to process alerts", error=e)
            raise
    
    def _extract_features(self, alert: Alert) -> Dict:
        """Extract features from alert for anomaly detection."""
        features = {
            "severity_score": self._get_severity_score(alert.severity),
            "source_type_score": self._get_source_type_score(alert.source),
            "time_of_day_score": self._get_time_of_day_score(alert.timestamp),
            "indicator_count": len(alert.indicators),
            "mitre_tactic_count": len(alert.mitre_tactics),
            "mitre_technique_count": len(alert.mitre_techniques)
        }
        
        # Calculate anomaly score
        features["anomaly_score"] = sum(features.values()) / len(features)
        
        return features
    
    def _get_severity_score(self, severity: str) -> float:
        """Get numerical score for severity level."""
        severity_scores = {
            "critical": 1.0,
            "high": 0.8,
            "medium": 0.6,
            "low": 0.4,
            "info": 0.2
        }
        return severity_scores.get(severity.lower(), 0.0)
    
    def _get_source_type_score(self, source: str) -> float:
        """Get numerical score for alert source."""
        source_scores = {
            "suricata": 0.8,
            "wazuh": 0.7,
            "elasticsearch": 0.6,
            "custom": 0.5
        }
        return source_scores.get(source.lower(), 0.3)
    
    def _get_time_of_day_score(self, timestamp: datetime) -> float:
        """Get numerical score for time of day."""
        hour = timestamp.hour
        
        # Higher score for suspicious hours (night time)
        if 0 <= hour < 6:
            return 0.9
        elif 6 <= hour < 8:
            return 0.7
        elif 8 <= hour < 18:
            return 0.3
        elif 18 <= hour < 22:
            return 0.5
        else:
            return 0.8

# Create service instance
ai_service = AIService() 