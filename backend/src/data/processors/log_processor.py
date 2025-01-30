from typing import Dict, List, Optional, Union, Any, Callable
from datetime import datetime
import json
import asyncio
from uuid import uuid4

from ...core.settings import get_settings
from ...utils.logging import LoggerMixin
from ...data.connectors.elasticsearch import es_connector
from ...data.connectors.kafka import kafka_connector
from ...data.models.alert import Alert, AlertSeverity, AlertCategory

settings = get_settings()

class LogNormalizer:
    """Normalize logs from different sources into a common format."""
    
    @staticmethod
    def normalize_syslog(log: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize syslog format."""
        return {
            "timestamp": datetime.fromisoformat(log.get("timestamp", datetime.utcnow().isoformat())),
            "source": "syslog",
            "host": log.get("host"),
            "facility": log.get("facility"),
            "severity": log.get("severity"),
            "program": log.get("program"),
            "message": log.get("message"),
            "pid": log.get("pid"),
            "raw": log
        }
    
    @staticmethod
    def normalize_windows_event(log: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize Windows Event Log format."""
        return {
            "timestamp": datetime.fromisoformat(log.get("TimeCreated", {}).get("SystemTime", datetime.utcnow().isoformat())),
            "source": "windows",
            "host": log.get("Computer"),
            "event_id": log.get("EventID"),
            "channel": log.get("Channel"),
            "level": log.get("Level"),
            "message": log.get("Message"),
            "provider": log.get("Provider", {}).get("Name"),
            "raw": log
        }
    
    @staticmethod
    def normalize_aws_cloudtrail(log: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize AWS CloudTrail format."""
        return {
            "timestamp": datetime.fromisoformat(log.get("eventTime", datetime.utcnow().isoformat())),
            "source": "aws_cloudtrail",
            "region": log.get("awsRegion"),
            "event_name": log.get("eventName"),
            "event_type": log.get("eventType"),
            "user_identity": log.get("userIdentity", {}).get("userName"),
            "source_ip": log.get("sourceIPAddress"),
            "user_agent": log.get("userAgent"),
            "error_code": log.get("errorCode"),
            "error_message": log.get("errorMessage"),
            "raw": log
        }
    
    @staticmethod
    def normalize_kubernetes(log: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize Kubernetes logs."""
        return {
            "timestamp": datetime.fromisoformat(log.get("timestamp", datetime.utcnow().isoformat())),
            "source": "kubernetes",
            "namespace": log.get("kubernetes", {}).get("namespace_name"),
            "pod": log.get("kubernetes", {}).get("pod_name"),
            "container": log.get("kubernetes", {}).get("container_name"),
            "host": log.get("kubernetes", {}).get("host"),
            "message": log.get("log"),
            "stream": log.get("stream"),
            "raw": log
        }

class LogEnricher:
    """Enrich logs with additional context and threat intelligence."""
    
    @staticmethod
    def enrich_with_geo_ip(log: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich log with GeoIP information."""
        ip = log.get("source_ip")
        if ip:
            # TODO: Implement GeoIP lookup
            log["geo"] = {
                "country": "Unknown",
                "city": "Unknown",
                "coordinates": [0, 0]
            }
        return log
    
    @staticmethod
    def enrich_with_threat_intel(log: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich log with threat intelligence."""
        # TODO: Implement threat intel lookup
        log["threat_intel"] = {
            "malicious": False,
            "confidence": 0,
            "tags": []
        }
        return log
    
    @staticmethod
    def enrich_with_asset_info(log: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich log with asset information."""
        host = log.get("host")
        if host:
            # TODO: Implement asset lookup
            log["asset"] = {
                "type": "unknown",
                "owner": "unknown",
                "criticality": "low"
            }
        return log

class LogProcessor(LoggerMixin):
    """Process logs from various sources."""
    
    def __init__(self):
        """Initialize log processor."""
        super().__init__()
        self.normalizer = LogNormalizer()
        self.enricher = LogEnricher()
        self.processors: Dict[str, Callable] = {
            "syslog": self.normalizer.normalize_syslog,
            "windows": self.normalizer.normalize_windows_event,
            "aws_cloudtrail": self.normalizer.normalize_aws_cloudtrail,
            "kubernetes": self.normalizer.normalize_kubernetes
        }
        self.running = False
    
    async def start(self):
        """Start the log processor."""
        try:
            self.running = True
            
            # Start Kafka consumer for each log type
            for log_type in self.processors.keys():
                asyncio.create_task(
                    self._consume_logs(
                        topic=f"logs.{log_type}",
                        processor=self.processors[log_type]
                    )
                )
            
            self.log_info("Log processor started")
            
        except Exception as e:
            self.log_error("Failed to start log processor", error=e)
            raise
    
    async def stop(self):
        """Stop the log processor."""
        try:
            self.running = False
            
            # Stop Kafka consumers
            for log_type in self.processors.keys():
                await kafka_connector.stop_consumer(f"logs.{log_type}")
            
            self.log_info("Log processor stopped")
            
        except Exception as e:
            self.log_error("Failed to stop log processor", error=e)
            raise
    
    async def _consume_logs(
        self,
        topic: str,
        processor: Callable[[Dict[str, Any]], Dict[str, Any]]
    ):
        """Consume logs from Kafka topic."""
        try:
            async def process_message(key: Optional[str], value: Dict[str, Any]):
                try:
                    # Normalize log
                    normalized = processor(value)
                    
                    # Enrich log
                    enriched = self._enrich_log(normalized)
                    
                    # Store in Elasticsearch
                    await self._store_log(enriched)
                    
                    # Process for alerts
                    await self._process_for_alerts(enriched)
                    
                except Exception as e:
                    self.log_error(
                        "Failed to process log message",
                        error=e,
                        topic=topic,
                        value=value
                    )
            
            # Start consuming
            await kafka_connector.consume_messages(
                topic=topic,
                callback=process_message
            )
            
        except Exception as e:
            self.log_error(
                "Failed to consume logs",
                error=e,
                topic=topic
            )
            raise
    
    def _enrich_log(self, log: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich log with additional context."""
        try:
            enriched = log.copy()
            
            # Apply enrichments
            enriched = self.enricher.enrich_with_geo_ip(enriched)
            enriched = self.enricher.enrich_with_threat_intel(enriched)
            enriched = self.enricher.enrich_with_asset_info(enriched)
            
            return enriched
            
        except Exception as e:
            self.log_error(
                "Failed to enrich log",
                error=e,
                log=log
            )
            raise
    
    async def _store_log(self, log: Dict[str, Any]):
        """Store log in Elasticsearch."""
        try:
            # Add metadata
            log["@timestamp"] = log.get("timestamp", datetime.utcnow().isoformat())
            log["@version"] = "1"
            log["@id"] = str(uuid4())
            
            # Store in appropriate index
            index = f"logs-{log['source']}-{datetime.utcnow().strftime('%Y.%m.%d')}"
            await es_connector.index_document(
                index=index,
                document=log,
                doc_id=log["@id"]
            )
            
        except Exception as e:
            self.log_error(
                "Failed to store log",
                error=e,
                log=log
            )
            raise
    
    async def _process_for_alerts(self, log: Dict[str, Any]):
        """Process log for potential alerts."""
        try:
            # Check for threat intel hits
            if log.get("threat_intel", {}).get("malicious"):
                await self._create_alert(
                    log,
                    AlertSeverity.HIGH,
                    AlertCategory.MALWARE,
                    "Malicious activity detected from threat intelligence"
                )
            
            # Check for authentication failures
            if "authentication failure" in log.get("message", "").lower():
                await self._create_alert(
                    log,
                    AlertSeverity.MEDIUM,
                    AlertCategory.IDENTITY,
                    "Multiple authentication failures detected"
                )
            
            # Check for critical errors
            if log.get("severity") in ["CRITICAL", "ERROR"]:
                await self._create_alert(
                    log,
                    AlertSeverity.HIGH,
                    AlertCategory.APPLICATION,
                    "Critical system error detected"
                )
            
        except Exception as e:
            self.log_error(
                "Failed to process log for alerts",
                error=e,
                log=log
            )
            raise
    
    async def _create_alert(
        self,
        log: Dict[str, Any],
        severity: AlertSeverity,
        category: AlertCategory,
        description: str
    ):
        """Create and store an alert."""
        try:
            alert = Alert(
                source=log["source"],
                severity=severity,
                category=category,
                description=description,
                timestamp=datetime.fromisoformat(log["@timestamp"]),
                source_ip=log.get("source_ip"),
                destination_ip=log.get("destination_ip"),
                additional_context={
                    "log_id": log["@id"],
                    "raw_log": log["raw"]
                }
            )
            
            # Store alert in Elasticsearch
            index = f"alerts-{datetime.utcnow().strftime('%Y.%m.%d')}"
            await es_connector.index_document(
                index=index,
                document=alert.model_dump(),
                doc_id=str(alert.id)
            )
            
            # Send alert to Kafka for real-time processing
            await kafka_connector.send_message(
                topic="alerts.new",
                message=alert.model_dump()
            )
            
        except Exception as e:
            self.log_error(
                "Failed to create alert",
                error=e,
                log=log,
                severity=severity,
                category=category
            )
            raise

# Create singleton instance
log_processor = LogProcessor() 