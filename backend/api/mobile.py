"""
Mobile-optimized endpoints for PHANTØM Mobile app.
Add this file to backend/api/mobile.py
Then add: from api.mobile import mobile_router
         app.include_router(mobile_router)
to main.py
"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func
from db.database import get_db
from db.models import ThreatRecord
from db.cache import cache
from utils.mobile_auth import verify_mobile_key

mobile_router = APIRouter(prefix="/api/mobile", tags=["mobile"])


@mobile_router.get("/summary", dependencies=[Depends(verify_mobile_key)])
async def mobile_summary(db: Session = Depends(get_db)):
    """
    Single endpoint that returns everything the mobile dashboard needs.
    Reduces mobile API calls from 3 → 1.
    """
    # Stats
    total    = db.query(func.count(ThreatRecord.id)).scalar()
    critical = db.query(func.count(ThreatRecord.id)).filter(ThreatRecord.severity == "CRITICAL").scalar()
    high     = db.query(func.count(ThreatRecord.id)).filter(ThreatRecord.severity == "HIGH").scalar()
    medium   = db.query(func.count(ThreatRecord.id)).filter(ThreatRecord.severity == "MEDIUM").scalar()
    avg      = db.query(func.avg(ThreatRecord.threat_score)).scalar()

    # Recent threats (last 10)
    recent = (
        db.query(ThreatRecord)
        .order_by(ThreatRecord.created_at.desc())
        .limit(10)
        .all()
    )

    # Top threat
    top = (
        db.query(ThreatRecord)
        .order_by(ThreatRecord.threat_score.desc())
        .first()
    )

    return {
        "stats": {
            "total_analyzed": total,
            "critical_count": critical,
            "high_count":     high,
            "medium_count":   medium,
            "avg_score":      round(float(avg or 0), 2),
            "redis_status":   "online" if cache.health_check() else "offline",
        },
        "recent_threats": [
            {
                "id":           r.id,
                "ioc":          r.ioc,
                "ioc_type":     r.ioc_type,
                "threat_score": r.threat_score,
                "severity":     r.severity,
                "country":      r.country,
                "ai_summary":   r.ai_summary,
                "created_at":   str(r.created_at),
            }
            for r in recent
        ],
        "top_threat": {
            "ioc":          top.ioc,
            "threat_score": top.threat_score,
            "severity":     top.severity,
            "country":      top.country,
        } if top else None,
    }


@mobile_router.get("/threats", dependencies=[Depends(verify_mobile_key)])
async def mobile_threats(
    severity: str     = Query(default=None),
    limit:    int     = Query(default=20, le=50),
    db:       Session = Depends(get_db),
):
    """Paginated threat history for mobile."""
    q = db.query(ThreatRecord).order_by(ThreatRecord.created_at.desc())
    if severity:
        q = q.filter(ThreatRecord.severity == severity)
    records = q.limit(limit).all()

    return {
        "count": len(records),
        "threats": [
            {
                "id":           r.id,
                "ioc":          r.ioc,
                "ioc_type":     r.ioc_type,
                "threat_score": r.threat_score,
                "severity":     r.severity,
                "country":      r.country,
                "ai_summary":   r.ai_summary,
                "created_at":   str(r.created_at),
            }
            for r in records
        ],
    }


@mobile_router.get("/ioc/{ioc}", dependencies=[Depends(verify_mobile_key)])
async def mobile_ioc_lookup(
    ioc:      str,
    ioc_type: str     = Query(default="ip", enum=["ip", "domain", "hash"]),
    db:       Session = Depends(get_db),
):
    """
    Check if IOC already exists in DB before doing a full analysis.
    Returns cached result if found, None if new.
    """
    record = (
        db.query(ThreatRecord)
        .filter(ThreatRecord.ioc == ioc)
        .order_by(ThreatRecord.created_at.desc())
        .first()
    )
    if record:
        return {
            "cached":       True,
            "id":           record.id,
            "ioc":          record.ioc,
            "ioc_type":     record.ioc_type,
            "threat_score": record.threat_score,
            "severity":     record.severity,
            "country":      record.country,
            "ai_summary":   record.ai_summary,
            "created_at":   str(record.created_at),
        }
    return {"cached": False, "ioc": ioc}


@mobile_router.post("/push-token", dependencies=[Depends(verify_mobile_key)])
async def register_push_token(token: str):
    """
    Register Expo push token for critical threat notifications.
    Store in .env or a simple file for now.
    Later: save to DB for multi-device support.
    """
    import os
    # For single-device use: just save to env or a local file
    # For multi-device: save to DB
    with open("push_tokens.txt", "a") as f:
        f.write(token + "\n")
    return {"status": "registered", "token": token}
