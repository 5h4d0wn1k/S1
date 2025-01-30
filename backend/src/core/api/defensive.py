from typing import Dict, List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status

from ..auth import User, requires_permissions
from ...engines.defensive.engine import (
    ThreatRule,
    ThreatIndicator,
    ResponseAction,
    defensive_engine
)
from ...utils.logging import LoggerMixin

router = APIRouter()
logger = LoggerMixin()

@router.post("/rules", response_model=ThreatRule)
async def create_rule(
    rule: ThreatRule,
    current_user: User = Depends(requires_permissions("defensive:rules:create"))
) -> ThreatRule:
    """Create a new detection rule."""
    try:
        logger.log_info(
            "Creating new rule",
            rule_name=rule.name,
            rule_type=rule.rule_type,
            user=current_user.username
        )
        
        return await defensive_engine.add_rule(rule)
    except Exception as e:
        logger.log_error(
            "Failed to create rule",
            error=e,
            rule_name=rule.name,
            user=current_user.username
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create detection rule"
        )

@router.get("/rules", response_model=List[ThreatRule])
async def list_rules(
    current_user: User = Depends(requires_permissions("defensive:rules:read"))
) -> List[ThreatRule]:
    """List all detection rules."""
    try:
        logger.log_info(
            "Listing rules",
            user=current_user.username
        )
        
        return list(defensive_engine.active_rules.values())
    except Exception as e:
        logger.log_error(
            "Failed to list rules",
            error=e,
            user=current_user.username
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list detection rules"
        )

@router.get("/rules/{rule_id}", response_model=ThreatRule)
async def get_rule(
    rule_id: UUID,
    current_user: User = Depends(requires_permissions("defensive:rules:read"))
) -> ThreatRule:
    """Get a specific detection rule."""
    try:
        logger.log_info(
            "Retrieving rule",
            rule_id=str(rule_id),
            user=current_user.username
        )
        
        if rule_id not in defensive_engine.active_rules:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Rule {rule_id} not found"
            )
        
        return defensive_engine.active_rules[rule_id]
    except HTTPException:
        raise
    except Exception as e:
        logger.log_error(
            "Failed to retrieve rule",
            error=e,
            rule_id=str(rule_id),
            user=current_user.username
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve rule"
        )

@router.post("/indicators", response_model=ThreatIndicator)
async def add_indicator(
    indicator: ThreatIndicator,
    current_user: User = Depends(requires_permissions("defensive:indicators:create"))
) -> ThreatIndicator:
    """Add a new threat indicator."""
    try:
        logger.log_info(
            "Adding new indicator",
            indicator_type=indicator.type,
            indicator_value=indicator.value,
            user=current_user.username
        )
        
        return await defensive_engine.add_indicator(indicator)
    except Exception as e:
        logger.log_error(
            "Failed to add indicator",
            error=e,
            indicator_type=indicator.type,
            indicator_value=indicator.value,
            user=current_user.username
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to add threat indicator"
        )

@router.get("/indicators", response_model=List[ThreatIndicator])
async def list_indicators(
    current_user: User = Depends(requires_permissions("defensive:indicators:read"))
) -> List[ThreatIndicator]:
    """List all threat indicators."""
    try:
        logger.log_info(
            "Listing indicators",
            user=current_user.username
        )
        
        return list(defensive_engine.active_indicators.values())
    except Exception as e:
        logger.log_error(
            "Failed to list indicators",
            error=e,
            user=current_user.username
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list threat indicators"
        )

@router.post("/actions/block_ip")
async def block_ip(
    ip: str,
    current_user: User = Depends(requires_permissions("defensive:actions:execute"))
) -> Dict[str, str]:
    """Block an IP address."""
    try:
        logger.log_info(
            "Blocking IP",
            ip=ip,
            user=current_user.username
        )
        
        await defensive_engine.block_ip(ip)
        return {"message": f"IP {ip} blocked successfully"}
    except Exception as e:
        logger.log_error(
            "Failed to block IP",
            error=e,
            ip=ip,
            user=current_user.username
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to block IP {ip}"
        )

@router.get("/actions/blocked_ips", response_model=List[str])
async def list_blocked_ips(
    current_user: User = Depends(requires_permissions("defensive:actions:read"))
) -> List[str]:
    """List all blocked IP addresses."""
    try:
        logger.log_info(
            "Listing blocked IPs",
            user=current_user.username
        )
        
        return list(defensive_engine.blocked_ips)
    except Exception as e:
        logger.log_error(
            "Failed to list blocked IPs",
            error=e,
            user=current_user.username
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list blocked IPs"
        )

@router.post("/actions/execute", response_model=Dict[str, str])
async def execute_response_action(
    action: ResponseAction,
    current_user: User = Depends(requires_permissions("defensive:actions:execute"))
) -> Dict[str, str]:
    """Execute a response action."""
    try:
        logger.log_info(
            "Executing response action",
            action_type=action.action_type,
            parameters=action.parameters,
            user=current_user.username
        )
        
        await defensive_engine.response_queue.put(action)
        return {"message": "Response action queued successfully"}
    except Exception as e:
        logger.log_error(
            "Failed to execute response action",
            error=e,
            action_type=action.action_type,
            parameters=action.parameters,
            user=current_user.username
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to execute response action"
        ) 