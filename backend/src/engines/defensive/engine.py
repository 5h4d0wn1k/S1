import asyncio
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Union
from uuid import UUID, uuid4
import json
import logging
from pathlib import Path
import aiohttp
import socket
import time
import yaml

from pydantic import BaseModel, Field
from fastapi import HTTPException
from wazuhi import Wazuh
from suricatasc import SuricataSC

from ...core.exceptions import DefensiveEngineError
from ...utils.logging import LoggerMixin
from ...core.settings import get_settings
from ...data.models.alert import Alert, AlertSeverity, AlertCategory

settings = get_settings()

class ThreatLevel(str):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ThreatIndicator(BaseModel):
    """Indicator of compromise or threat."""
    type: str  # e.g., "ip", "domain", "hash", "pattern"
    value: str
    confidence: float = 0.0
    source: str
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

class ThreatRule(BaseModel):
    """Detection rule for threats."""
    id: UUID = Field(default_factory=uuid4)
    name: str
    description: str
    level: ThreatLevel
    rule_type: str  # e.g., "suricata", "wazuh", "yara"
    rule_content: str
    enabled: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)

class ResponseAction(BaseModel):
    """Automated response action."""
    id: UUID = Field(default_factory=uuid4)
    name: str
    description: str
    action_type: str  # e.g., "block_ip", "quarantine_host", "disable_user"
    parameters: Dict[str, Any] = Field(default_factory=dict)
    requires_approval: bool = False
    created_at: datetime = Field(default_factory=datetime.utcnow)

class DefensiveEngine(LoggerMixin):
    """Core defensive engine integrating Suricata IDS and Wazuh HIDS."""
    
    def __init__(self):
        """Initialize defensive engine components."""
        super().__init__()
        self.active_rules: Dict[UUID, ThreatRule] = {}
        self.active_indicators: Dict[str, ThreatIndicator] = {}
        self.blocked_ips: Set[str] = set()
        self.running = False
        
        # Queues for processing
        self.event_queue: asyncio.Queue = asyncio.Queue()
        self.response_queue: asyncio.Queue = asyncio.Queue()
        
        self.suricata_client = None
        self.wazuh_client = None
        self._initialize_components()
    
    def _initialize_components(self):
        """Initialize connections to Suricata and Wazuh."""
        try:
            # Initialize Suricata client
            self.suricata_client = SuricataSC(
                settings.SURICATA_SOCKET_PATH
            )
            
            # Initialize Wazuh client
            self.wazuh_client = Wazuh(
                host=settings.WAZUH_HOST,
                port=settings.WAZUH_PORT,
                user=settings.WAZUH_USER,
                password=settings.WAZUH_PASSWORD,
                protocol="https",
                verify=settings.WAZUH_VERIFY_SSL
            )
            
            self.log_info("Defensive engine components initialized successfully")
            
        except Exception as e:
            self.log_error("Failed to initialize defensive components", error=e)
            raise
    
    async def start(self) -> None:
        """Start the defensive engine."""
        try:
            self.running = True
            self.log_info("Defensive engine started")
            
            # Start background tasks
            asyncio.create_task(self._process_events())
            asyncio.create_task(self._process_responses())
            asyncio.create_task(self._update_threat_intel())
        except Exception as e:
            self.log_error("Failed to start defensive engine", e)
            raise DefensiveEngineError("Engine startup failed")
    
    async def stop(self) -> None:
        """Stop the defensive engine."""
        try:
            self.running = False
            self.log_info("Defensive engine stopped")
        except Exception as e:
            self.log_error("Failed to stop defensive engine", e)
            raise DefensiveEngineError("Engine shutdown failed")
    
    async def add_rule(self, rule: ThreatRule) -> ThreatRule:
        """Add a new detection rule."""
        try:
            # Validate rule content based on type
            await self._validate_rule(rule)
            
            # Store rule
            self.active_rules[rule.id] = rule
            
            self.log_info(
                "Rule added",
                rule_id=str(rule.id),
                rule_name=rule.name,
                rule_type=rule.rule_type
            )
            
            # Deploy rule to appropriate system
            await self._deploy_rule(rule)
            
            return rule
        except Exception as e:
            self.log_error(
                "Failed to add rule",
                error=e,
                rule_name=rule.name
            )
            raise DefensiveEngineError("Failed to add rule")
    
    async def add_indicator(self, indicator: ThreatIndicator) -> ThreatIndicator:
        """Add a new threat indicator."""
        try:
            key = f"{indicator.type}:{indicator.value}"
            
            # Update if exists
            if key in self.active_indicators:
                existing = self.active_indicators[key]
                existing.last_seen = datetime.utcnow()
                existing.confidence = max(existing.confidence, indicator.confidence)
                existing.tags.extend(indicator.tags)
                indicator = existing
            
            self.active_indicators[key] = indicator
            
            self.log_info(
                "Indicator added",
                indicator_type=indicator.type,
                indicator_value=indicator.value,
                confidence=indicator.confidence
            )
            
            # Auto-block if high confidence malicious IP
            if (
                indicator.type == "ip" and
                indicator.confidence >= 0.9 and
                "malicious" in indicator.tags
            ):
                await self.block_ip(indicator.value)
            
            return indicator
        except Exception as e:
            self.log_error(
                "Failed to add indicator",
                error=e,
                indicator_type=indicator.type,
                indicator_value=indicator.value
            )
            raise DefensiveEngineError("Failed to add indicator")
    
    async def block_ip(self, ip: str) -> None:
        """Block an IP address."""
        try:
            if ip in self.blocked_ips:
                return
            
            self.blocked_ips.add(ip)
            
            # Create response action
            action = ResponseAction(
                name=f"Block IP {ip}",
                description=f"Automatically block malicious IP {ip}",
                action_type="block_ip",
                parameters={"ip": ip}
            )
            
            await self.response_queue.put(action)
            
            self.log_info(
                "IP blocked",
                ip=ip
            )
        except Exception as e:
            self.log_error(
                "Failed to block IP",
                error=e,
                ip=ip
            )
            raise DefensiveEngineError(f"Failed to block IP {ip}")
    
    async def _process_events(self) -> None:
        """Process security events."""
        while self.running:
            try:
                event = await self.event_queue.get()
                
                # Match event against rules
                matched_rules = []
                for rule in self.active_rules.values():
                    if not rule.enabled:
                        continue
                    
                    if await self._match_rule(rule, event):
                        matched_rules.append(rule)
                
                if matched_rules:
                    await self._handle_matches(event, matched_rules)
                
                self.event_queue.task_done()
            except Exception as e:
                self.log_error("Event processing failed", e)
                await asyncio.sleep(1)  # Prevent tight loop on error
    
    async def _process_responses(self) -> None:
        """Process automated responses."""
        while self.running:
            try:
                action = await self.response_queue.get()
                
                if action.requires_approval:
                    # Here you would implement approval workflow
                    continue
                
                await self._execute_response(action)
                
                self.response_queue.task_done()
            except Exception as e:
                self.log_error("Response processing failed", e)
                await asyncio.sleep(1)
    
    async def _update_threat_intel(self) -> None:
        """Update threat intelligence periodically."""
        while self.running:
            try:
                # Here you would fetch updates from threat feeds
                await asyncio.sleep(3600)  # Update every hour
            except Exception as e:
                self.log_error("Threat intel update failed", e)
                await asyncio.sleep(60)
    
    async def _validate_rule(self, rule: ThreatRule) -> None:
        """Validate a detection rule."""
        if rule.rule_type == "suricata":
            # Validate Suricata rule syntax
            if not rule.rule_content.startswith("alert"):
                raise DefensiveEngineError("Invalid Suricata rule format")
        elif rule.rule_type == "wazuh":
            # Validate Wazuh rule XML
            if not rule.rule_content.startswith("<rule"):
                raise DefensiveEngineError("Invalid Wazuh rule format")
        elif rule.rule_type == "yara":
            # Validate YARA rule syntax
            if not rule.rule_content.startswith("rule"):
                raise DefensiveEngineError("Invalid YARA rule format")
    
    async def _deploy_rule(self, rule: ThreatRule) -> None:
        """Deploy a rule to the appropriate security system."""
        try:
            if rule.rule_type == "suricata":
                # Here you would use Suricata's API or reload rules
                pass
            elif rule.rule_type == "wazuh":
                # Here you would use Wazuh's API
                pass
            elif rule.rule_type == "yara":
                # Here you would compile and load YARA rule
                pass
        except Exception as e:
            self.log_error(
                "Rule deployment failed",
                error=e,
                rule_id=str(rule.id),
                rule_type=rule.rule_type
            )
            raise DefensiveEngineError("Rule deployment failed")
    
    async def _match_rule(self, rule: ThreatRule, event: Dict[str, Any]) -> bool:
        """Match an event against a rule."""
        try:
            # Here you would implement rule matching logic
            # This is a placeholder implementation
            return any(
                tag in event.get("tags", [])
                for tag in rule.metadata.get("tags", [])
            )
        except Exception as e:
            self.log_error(
                "Rule matching failed",
                error=e,
                rule_id=str(rule.id),
                event=event
            )
            return False
    
    async def _handle_matches(
        self,
        event: Dict[str, Any],
        matched_rules: List[ThreatRule]
    ) -> None:
        """Handle events that matched rules."""
        try:
            # Create alert for highest severity match
            highest_severity = max(rule.level for rule in matched_rules)
            
            # Here you would create an alert in your alert system
            
            # Determine and queue response actions
            for rule in matched_rules:
                if response_action := rule.metadata.get("response_action"):
                    await self.response_queue.put(
                        ResponseAction(**response_action)
                    )
        except Exception as e:
            self.log_error(
                "Match handling failed",
                error=e,
                event=event,
                matched_rules=[str(r.id) for r in matched_rules]
            )
    
    async def _execute_response(self, action: ResponseAction) -> None:
        """Execute an automated response action."""
        try:
            if action.action_type == "block_ip":
                # Here you would integrate with firewalls/WAFs
                ip = action.parameters.get("ip")
                if ip:
                    self.blocked_ips.add(ip)
            elif action.action_type == "quarantine_host":
                # Here you would integrate with EDR/network controls
                pass
            elif action.action_type == "disable_user":
                # Here you would integrate with IAM systems
                pass
            
            self.log_info(
                "Response action executed",
                action_id=str(action.id),
                action_type=action.action_type,
                parameters=action.parameters
            )
        except Exception as e:
            self.log_error(
                "Response execution failed",
                error=e,
                action_id=str(action.id),
                action_type=action.action_type
            )
            raise DefensiveEngineError("Response execution failed")

    async def get_all_alerts(
        self,
        timeframe_minutes: int = 5,
        severity: Optional[AlertSeverity] = None,
        category: Optional[AlertCategory] = None
    ) -> Dict[str, List[Alert]]:
        """Get alerts from all defensive components."""
        try:
            # Calculate time range
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(minutes=timeframe_minutes)
            
            # Get alerts concurrently
            suricata_task = self._get_suricata_alerts(start_time, end_time)
            wazuh_task = self._get_wazuh_alerts(start_time, end_time)
            
            # Gather results
            suricata_alerts, wazuh_alerts = await asyncio.gather(
                suricata_task,
                wazuh_task
            )
            
            # Apply filters if specified
            if severity:
                suricata_alerts = [a for a in suricata_alerts if a.severity == severity]
                wazuh_alerts = [a for a in wazuh_alerts if a.severity == severity]
            
            if category:
                suricata_alerts = [a for a in suricata_alerts if a.category == category]
                wazuh_alerts = [a for a in wazuh_alerts if a.category == category]
            
            return {
                "suricata": suricata_alerts,
                "wazuh": wazuh_alerts
            }
            
        except Exception as e:
            self.log_error("Failed to get alerts", error=e)
            raise HTTPException(
                status_code=500,
                detail="Failed to retrieve alerts from defensive components"
            )
    
    async def _get_suricata_alerts(
        self,
        start_time: datetime,
        end_time: datetime
    ) -> List[Alert]:
        """Get alerts from Suricata."""
        try:
            alerts = []
            
            # Query Suricata's EVE JSON log file
            eve_log_path = Path(settings.SURICATA_EVE_LOG)
            if not eve_log_path.exists():
                self.log_warning("Suricata EVE log file not found", path=str(eve_log_path))
                return []
            
            with eve_log_path.open() as f:
                for line in f:
                    try:
                        event = json.loads(line)
                        
                        # Skip non-alert events
                        if event.get("event_type") != "alert":
                            continue
                        
                        # Parse timestamp
                        timestamp = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
                        
                        # Check time range
                        if not (start_time <= timestamp <= end_time):
                            continue
                        
                        # Convert to our Alert model
                        alert = Alert(
                            source="suricata",
                            severity=self._map_suricata_severity(event.get("alert", {}).get("severity", 1)),
                            category=AlertCategory.NETWORK,
                            description=event.get("alert", {}).get("signature", "Unknown alert"),
                            timestamp=timestamp,
                            source_ip=event.get("src_ip"),
                            destination_ip=event.get("dest_ip"),
                            network_context={
                                "protocol": event.get("proto"),
                                "src_port": event.get("src_port"),
                                "dest_port": event.get("dest_port"),
                                "app_proto": event.get("app_proto")
                            },
                            additional_context={
                                "signature_id": event.get("alert", {}).get("signature_id"),
                                "category": event.get("alert", {}).get("category"),
                                "rev": event.get("alert", {}).get("rev")
                            }
                        )
                        alerts.append(alert)
                        
                    except json.JSONDecodeError:
                        continue
                    except Exception as e:
                        self.log_error("Failed to parse Suricata alert", error=e, line=line)
                        continue
            
            return alerts
            
        except Exception as e:
            self.log_error("Failed to get Suricata alerts", error=e)
            raise
    
    async def _get_wazuh_alerts(
        self,
        start_time: datetime,
        end_time: datetime
    ) -> List[Alert]:
        """Get alerts from Wazuh."""
        try:
            alerts = []
            
            # Convert timestamps to Wazuh format
            start_str = start_time.strftime("%Y-%m-%d %H:%M:%S")
            end_str = end_time.strftime("%Y-%m-%d %H:%M:%S")
            
            # Query Wazuh API
            response = await self.wazuh_client.get_alerts(
                select=["rule.id", "rule.description", "rule.level", "timestamp", "agent.id", "agent.name"],
                search={"from": start_str, "to": end_str}
            )
            
            for event in response["data"]["items"]:
                try:
                    # Convert to our Alert model
                    alert = Alert(
                        source="wazuh",
                        severity=self._map_wazuh_severity(event.get("rule", {}).get("level", 3)),
                        category=AlertCategory.ENDPOINT,
                        description=event.get("rule", {}).get("description", "Unknown alert"),
                        timestamp=datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00")),
                        additional_context={
                            "rule_id": event.get("rule", {}).get("id"),
                            "agent_id": event.get("agent", {}).get("id"),
                            "agent_name": event.get("agent", {}).get("name")
                        }
                    )
                    alerts.append(alert)
                    
                except Exception as e:
                    self.log_error("Failed to parse Wazuh alert", error=e, event=event)
                    continue
            
            return alerts
            
        except Exception as e:
            self.log_error("Failed to get Wazuh alerts", error=e)
            raise
    
    def _map_suricata_severity(self, severity: int) -> AlertSeverity:
        """Map Suricata severity levels to our AlertSeverity enum."""
        mapping = {
            1: AlertSeverity.LOW,      # Low
            2: AlertSeverity.MEDIUM,   # Medium
            3: AlertSeverity.HIGH,     # High
            4: AlertSeverity.CRITICAL  # Critical
        }
        return mapping.get(severity, AlertSeverity.MEDIUM)
    
    def _map_wazuh_severity(self, level: int) -> AlertSeverity:
        """Map Wazuh rule levels to our AlertSeverity enum."""
        if level <= 4:
            return AlertSeverity.LOW
        elif level <= 7:
            return AlertSeverity.MEDIUM
        elif level <= 10:
            return AlertSeverity.HIGH
        else:
            return AlertSeverity.CRITICAL
    
    async def update_suricata_rules(self, rules: List[Dict]) -> Dict:
        """Update Suricata rules dynamically."""
        try:
            # Write rules to file
            rules_file = Path(settings.SURICATA_RULES_PATH) / "dynamic-rules.rules"
            with rules_file.open("w") as f:
                for rule in rules:
                    f.write(f"{rule['content']}\n")
            
            # Reload Suricata rules
            self.suricata_client.send_command("reload-rules")
            
            self.log_info("Suricata rules updated successfully", rules_count=len(rules))
            
            return {
                "message": "Rules updated successfully",
                "updated": len(rules)
            }
            
        except Exception as e:
            self.log_error("Failed to update Suricata rules", error=e)
            raise HTTPException(
                status_code=500,
                detail="Failed to update Suricata rules"
            )
    
    async def update_wazuh_rules(self, rules: List[Dict]) -> Dict:
        """Update Wazuh rules dynamically."""
        try:
            # Convert rules to Wazuh XML format
            xml_content = self._convert_to_wazuh_xml(rules)
            
            # Write rules to file
            rules_file = Path(settings.WAZUH_RULES_PATH) / "dynamic-rules.xml"
            with rules_file.open("w") as f:
                f.write(xml_content)
            
            # Restart Wazuh manager to apply rules
            await self.wazuh_client.restart_manager()
            
            self.log_info("Wazuh rules updated successfully", rules_count=len(rules))
            
            return {
                "message": "Rules updated successfully",
                "updated": len(rules)
            }
            
        except Exception as e:
            self.log_error("Failed to update Wazuh rules", error=e)
            raise HTTPException(
                status_code=500,
                detail="Failed to update Wazuh rules"
            )
    
    def _convert_to_wazuh_xml(self, rules: List[Dict]) -> str:
        """Convert rules to Wazuh XML format."""
        # This is a simplified version - in production, use proper XML templating
        xml_rules = ['<?xml version="1.0" encoding="UTF-8"?>', '<group name="dynamic">']
        
        for rule in rules:
            xml_rules.append(f'  <rule id="{rule["id"]}" level="{rule["level"]}">')
            xml_rules.append(f'    <description>{rule["description"]}</description>')
            
            if "pattern" in rule:
                xml_rules.append(f'    <pattern>{rule["pattern"]}</pattern>')
                
            xml_rules.append('  </rule>')
            
        xml_rules.append('</group>')
        return "\n".join(xml_rules)

# Create singleton instance
defensive_engine = DefensiveEngine() 