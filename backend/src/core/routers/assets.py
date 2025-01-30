from typing import Dict, List, Optional, Union, Any
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, IPvAnyAddress

from ...data.connectors.postgresql import pg_connector
from ...data.connectors.elasticsearch import es_connector
from ...utils.logging import LoggerMixin
from ...utils.auth import get_current_user
from ...data.models.user import User

router = APIRouter(prefix="/assets", tags=["assets"])
logger = LoggerMixin().get_logger()

class AssetBase(BaseModel):
    """Base asset model."""
    hostname: str = Field(..., description="Asset hostname")
    ip_address: Optional[IPvAnyAddress] = Field(None, description="Asset IP address")
    type: str = Field(..., description="Asset type (e.g., server, workstation, network device)")
    owner: str = Field(..., description="Asset owner or responsible team")
    criticality: str = Field(..., description="Asset criticality level")

class AssetCreate(AssetBase):
    """Asset creation model."""
    pass

class AssetUpdate(BaseModel):
    """Asset update model."""
    hostname: Optional[str] = None
    ip_address: Optional[IPvAnyAddress] = None
    type: Optional[str] = None
    owner: Optional[str] = None
    criticality: Optional[str] = None

class AssetResponse(AssetBase):
    """Asset response model."""
    id: UUID
    created_at: datetime
    updated_at: datetime
    security_score: Optional[float] = None
    vulnerabilities_count: Optional[int] = None
    last_scan_date: Optional[datetime] = None

@router.post("", response_model=AssetResponse)
async def create_asset(
    asset: AssetCreate,
    current_user: User = Depends(get_current_user)
) -> AssetResponse:
    """Create a new asset."""
    try:
        # Check user permissions
        if not current_user.role in ["admin", "asset_manager"]:
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions to create assets"
            )
        
        # Insert into PostgreSQL
        asset_id = await pg_connector.insert(
            table="assets",
            data={
                **asset.model_dump(),
                "ip_address": str(asset.ip_address) if asset.ip_address else None
            }
        )
        
        # Get created asset
        result = await pg_connector.get_by_id(
            table="assets",
            id_=asset_id
        )
        
        if not result:
            raise HTTPException(
                status_code=500,
                detail="Failed to retrieve created asset"
            )
        
        logger.info(
            "Asset created successfully",
            user_id=str(current_user.id),
            asset_id=str(asset_id)
        )
        
        # Add security metrics
        result["security_score"] = None
        result["vulnerabilities_count"] = 0
        result["last_scan_date"] = None
        
        return AssetResponse(**result)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Failed to create asset",
            error=str(e),
            user_id=str(current_user.id),
            asset=asset.model_dump()
        )
        raise HTTPException(
            status_code=500,
            detail="Failed to create asset"
        )

@router.get("/{asset_id}", response_model=AssetResponse)
async def get_asset(
    asset_id: UUID,
    current_user: User = Depends(get_current_user)
) -> AssetResponse:
    """Get asset details by ID."""
    try:
        # Get from PostgreSQL
        result = await pg_connector.get_by_id(
            table="assets",
            id_=str(asset_id)
        )
        
        if not result:
            raise HTTPException(
                status_code=404,
                detail=f"Asset {asset_id} not found"
            )
        
        # Get security metrics from Elasticsearch
        security_metrics = await get_asset_security_metrics(asset_id)
        result.update(security_metrics)
        
        logger.info(
            "Asset retrieved successfully",
            user_id=str(current_user.id),
            asset_id=str(asset_id)
        )
        
        return AssetResponse(**result)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Failed to get asset",
            error=str(e),
            user_id=str(current_user.id),
            asset_id=str(asset_id)
        )
        raise HTTPException(
            status_code=500,
            detail="Failed to get asset"
        )

@router.patch("/{asset_id}", response_model=AssetResponse)
async def update_asset(
    asset_id: UUID,
    asset: AssetUpdate,
    current_user: User = Depends(get_current_user)
) -> AssetResponse:
    """Update asset details."""
    try:
        # Check user permissions
        if not current_user.role in ["admin", "asset_manager"]:
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions to update assets"
            )
        
        # Check if asset exists
        existing = await pg_connector.get_by_id(
            table="assets",
            id_=str(asset_id)
        )
        
        if not existing:
            raise HTTPException(
                status_code=404,
                detail=f"Asset {asset_id} not found"
            )
        
        # Prepare update data
        update_data = {
            k: v for k, v in asset.model_dump().items()
            if v is not None
        }
        
        if "ip_address" in update_data and update_data["ip_address"]:
            update_data["ip_address"] = str(update_data["ip_address"])
        
        update_data["updated_at"] = datetime.utcnow()
        
        # Update in PostgreSQL
        rows_updated = await pg_connector.update(
            table="assets",
            data=update_data,
            where={"id": str(asset_id)}
        )
        
        if not rows_updated:
            raise HTTPException(
                status_code=500,
                detail="Failed to update asset"
            )
        
        # Get updated asset
        result = await pg_connector.get_by_id(
            table="assets",
            id_=str(asset_id)
        )
        
        # Get security metrics
        security_metrics = await get_asset_security_metrics(asset_id)
        result.update(security_metrics)
        
        logger.info(
            "Asset updated successfully",
            user_id=str(current_user.id),
            asset_id=str(asset_id),
            updates=update_data
        )
        
        return AssetResponse(**result)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Failed to update asset",
            error=str(e),
            user_id=str(current_user.id),
            asset_id=str(asset_id)
        )
        raise HTTPException(
            status_code=500,
            detail="Failed to update asset"
        )

@router.delete("/{asset_id}")
async def delete_asset(
    asset_id: UUID,
    current_user: User = Depends(get_current_user)
) -> JSONResponse:
    """Delete an asset."""
    try:
        # Check user permissions
        if not current_user.role == "admin":
            raise HTTPException(
                status_code=403,
                detail="Only administrators can delete assets"
            )
        
        # Delete from PostgreSQL
        rows_deleted = await pg_connector.delete(
            table="assets",
            where={"id": str(asset_id)}
        )
        
        if not rows_deleted:
            raise HTTPException(
                status_code=404,
                detail=f"Asset {asset_id} not found"
            )
        
        logger.info(
            "Asset deleted successfully",
            user_id=str(current_user.id),
            asset_id=str(asset_id)
        )
        
        return JSONResponse(
            content={"message": "Asset deleted successfully"},
            status_code=200
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Failed to delete asset",
            error=str(e),
            user_id=str(current_user.id),
            asset_id=str(asset_id)
        )
        raise HTTPException(
            status_code=500,
            detail="Failed to delete asset"
        )

@router.get("", response_model=List[AssetResponse])
async def list_assets(
    type: Optional[str] = None,
    owner: Optional[str] = None,
    criticality: Optional[str] = None,
    current_user: User = Depends(get_current_user)
) -> List[AssetResponse]:
    """List assets with optional filtering."""
    try:
        # Build where clause
        where = {}
        if type:
            where["type"] = type
        if owner:
            where["owner"] = owner
        if criticality:
            where["criticality"] = criticality
        
        # Query PostgreSQL
        query = "SELECT * FROM assets"
        if where:
            conditions = " AND ".join(f"{k} = :{k}" for k in where.keys())
            query += f" WHERE {conditions}"
        
        results = await pg_connector.execute_query(query, where)
        
        # Get security metrics for each asset
        assets = []
        for result in results:
            security_metrics = await get_asset_security_metrics(
                UUID(result["id"])
            )
            result.update(security_metrics)
            assets.append(AssetResponse(**result))
        
        logger.info(
            "Assets listed successfully",
            user_id=str(current_user.id),
            filters=where,
            count=len(assets)
        )
        
        return assets
        
    except Exception as e:
        logger.error(
            "Failed to list assets",
            error=str(e),
            user_id=str(current_user.id),
            filters=locals()
        )
        raise HTTPException(
            status_code=500,
            detail="Failed to list assets"
        )

async def get_asset_security_metrics(asset_id: UUID) -> Dict[str, Any]:
    """Get security metrics for an asset."""
    try:
        # Get latest scan results
        scan_result = await pg_connector.execute_query(
            """
            SELECT findings, start_time
            FROM scans
            WHERE target_id = :asset_id
            ORDER BY start_time DESC
            LIMIT 1
            """,
            {"asset_id": str(asset_id)}
        )
        
        if not scan_result:
            return {
                "security_score": None,
                "vulnerabilities_count": 0,
                "last_scan_date": None
            }
        
        findings = scan_result[0]["findings"]
        
        # Calculate security score (example algorithm)
        if findings:
            critical = findings.get("critical", 0)
            high = findings.get("high", 0)
            medium = findings.get("medium", 0)
            low = findings.get("low", 0)
            
            # Score = 100 - (critical * 20 + high * 10 + medium * 5 + low * 2)
            score = 100 - (critical * 20 + high * 10 + medium * 5 + low * 2)
            score = max(0, min(100, score))  # Clamp between 0 and 100
            
            total_vulns = critical + high + medium + low
        else:
            score = None
            total_vulns = 0
        
        return {
            "security_score": score,
            "vulnerabilities_count": total_vulns,
            "last_scan_date": scan_result[0]["start_time"]
        }
        
    except Exception as e:
        logger.error(
            "Failed to get asset security metrics",
            error=str(e),
            asset_id=str(asset_id)
        )
        return {
            "security_score": None,
            "vulnerabilities_count": 0,
            "last_scan_date": None
        } 