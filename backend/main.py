from db.models import APICallLog, ThreatRecord, FileAnalysis
from nlp.ner_engine import ner
from utils.file_analyzer import analyze_file_static, analyze_file_ai, get_verdict_severity
from fastapi.responses import StreamingResponse
from utils.pdf_report import generate_pdf_report
from io import BytesIO
from fastapi import FastAPI, Depends, Query, WebSocket, WebSocketDisconnect, UploadFile, File, HTTPException
import asyncio
from utils.alerts import send_alert
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from dotenv import load_dotenv
import os
import json
from db.database import init_db, get_db
from db.models import ThreatRecord
from db.cache import cache
from utils.aggregator import aggregate_threat_intel
from nlp.scorer import calculate_threat_score, build_summary_context
from nlp.summarizer import generate_threat_briefing
from api.otx import get_latest_pulses
from api.mobile import mobile_router

load_dotenv()


# ── Lifespan ──────
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    from nlp.ner_engine import ner
    ner.try_load_model()
    yield



# ── App Init ──────────────────────────────────────────────────────────────────
app = FastAPI(
    title="PHANTØM API",
    version="2.0.0",
    lifespan=lifespan
)
      #For the Mobile App
app.include_router(mobile_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── WebSocket Manager ─────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, data: dict):
        dead = []
        for ws in self.active:
            try:
                await ws.send_text(json.dumps(data))
            except Exception:
                dead.append(ws)
        for ws in dead:
            if ws in self.active:
                self.active.remove(ws)

manager = ConnectionManager()


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# ── Broadcast to WebSocket ────────────────────────────
    await manager.broadcast({
        "type":         "new_threat",
        "ioc":          ioc,
        "threat_score": scored["threat_score"],
        "severity":     scored["severity"],
        "country":      scored.get("country"),
        "ai_summary":   ai_summary,
    })

# ── Fire Alert if above threshold ─────────────────────
    await send_alert({
        "ioc":          ioc,
        "threat_score": scored["threat_score"],
        "severity":     scored["severity"],
        "country":      scored.get("country"),
        "ai_summary":   ai_summary,
    })

# ── Health ────────────────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {
        "status":   "online",
        "platform": "PHANTØM",
        "version":  "2.0.0",
        "redis":    cache.health_check(),
    }


# ── Core Analysis ─────────────────────────────────────────────────────────────
@app.get("/api/analyze/{ioc}")
async def analyze_ioc(
    ioc:      str,
    ioc_type: str     = Query(default="ip", enum=["ip", "domain", "hash"]),
    ai:       bool    = Query(default=True),
    db:       Session = Depends(get_db),
):
    aggregated = await aggregate_threat_intel(ioc, ioc_type)

# ── Phase 3: NLP Entity Extraction ───────────────────────────────────────
    nlp_text = " ".join([
        str(aggregated.get("virustotal", {}).get("categories", [])),
        str(aggregated.get("virustotal", {}).get("tags", [])),
        str(aggregated.get("otx",        {}).get("tags", [])),
        str(aggregated.get("otx",        {}).get("malware_families", [])),
        str(aggregated.get("abuseipdb",  {}).get("categories", [])),
        str(aggregated.get("shodan",     {}).get("tags", [])),
        str(aggregated.get("shodan",     {}).get("cves", [])),
    ])
    nlp_entities = ner.extract_entities(nlp_text)
    scored = calculate_threat_score(aggregated, nlp_entities)

    ai_summary = None
    if ai:
        context    = build_summary_context(aggregated, scored)
        ai_summary = await generate_threat_briefing(context)

   # Get geo — try scored first, then fetch fresh
    latitude  = scored.get("latitude")
    longitude = scored.get("longitude")
    country   = scored.get("country", "Unknown")

    # If still no geo, fetch directly
    if not latitude or not longitude:
        from utils.helpers import get_ip_geo
        if ioc_type == "ip":
            geo       = await get_ip_geo(ioc)
            latitude  = geo.get("latitude")
            longitude = geo.get("longitude")
            if country == "Unknown":
                country = geo.get("country", "Unknown")

    record = ThreatRecord(
        ioc          = ioc,
        ioc_type     = ioc_type,
        threat_score = scored["threat_score"],
        severity     = scored["severity"],
        country      = country,
        latitude     = latitude,
        longitude    = longitude,
        vt_data      = aggregated.get("virustotal"),
        shodan_data  = aggregated.get("shodan"),
        abuse_data   = aggregated.get("abuseipdb"),
        otx_data     = aggregated.get("otx"),
        vt_score     = aggregated.get("virustotal", {}).get("vt_score",     0.0),
        abuse_score  = aggregated.get("abuseipdb",  {}).get("abuse_score",  0.0),
        shodan_score = aggregated.get("shodan",     {}).get("shodan_score", 0.0),
        otx_score    = aggregated.get("otx",        {}).get("otx_score",    0.0),
        ai_summary   = ai_summary,
    ) 

    db.add(record)
    db.commit()
    db.refresh(record)
    db.refresh(record)

    # ── Broadcast to all connected dashboards ─────────────────
    await manager.broadcast({
        "type":         "new_threat",
        "ioc":          ioc,
        "threat_score": scored["threat_score"],
        "severity":     scored["severity"],
        "country":      scored.get("country"),
        "ai_summary":   ai_summary,
    })

     
    await send_alert({
        "ioc":          ioc,
        "threat_score": scored["threat_score"],
        "severity":     scored["severity"],
        "country":      scored.get("country"),
        "ai_summary":   ai_summary or "",
    }) 

    return {
        **scored,
        "ai_summary": ai_summary,
        "record_id":  record.id,
    }

# ── Bulk IOC Analysis ─────────────────────────────────────────────────────────
@app.post("/api/bulk-analyze")
async def bulk_analyze(
    file:     UploadFile = File(...),
    ioc_type: str        = Query(default="ip"),
    ai:       bool       = Query(default=False),  # AI off by default for bulk
    db:       Session    = Depends(get_db),
):
    """
    Bulk analyze up to 50 IOCs from a .txt file.
    One IOC per line. Fires all concurrently.
    """
    content = await file.read()
    lines   = content.decode("utf-8").strip().splitlines()

    # Clean and deduplicate
    iocs = list({line.strip() for line in lines if line.strip()})[:50]

    if not iocs:
        raise HTTPException(status_code=400, detail="No valid IOCs found in file.")

    # Analyze all concurrently
    tasks   = [aggregate_threat_intel(ioc, ioc_type) for ioc in iocs]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    bulk_results = []
    for ioc, result in zip(iocs, results):
        if isinstance(result, Exception):
            bulk_results.append({
                "ioc":          ioc,
                "error":        str(result),
                "threat_score": 0,
                "severity":     "ERROR",
            })
            continue

        scored     = calculate_threat_score(result)
        ai_summary = None

        if ai:
            context    = build_summary_context(result, scored)
            ai_summary = await generate_threat_briefing(context)

        # Save to DB
        record = ThreatRecord(
            ioc          = ioc,
            ioc_type     = ioc_type,
            threat_score = scored["threat_score"],
            severity     = scored["severity"],
            country      = scored.get("country"),
            latitude     = scored.get("latitude"),
            longitude    = scored.get("longitude"),
            vt_data      = result.get("virustotal"),
            shodan_data  = result.get("shodan"),
            abuse_data   = result.get("abuseipdb"),
            otx_data     = result.get("otx"),
            vt_score     = result.get("virustotal", {}).get("vt_score",     0.0),
            abuse_score  = result.get("abuseipdb",  {}).get("abuse_score",  0.0),
            shodan_score = result.get("shodan",     {}).get("shodan_score", 0.0),
            otx_score    = result.get("otx",        {}).get("otx_score",    0.0),
            ai_summary   = ai_summary,
        )
        db.add(record)

        # Alert if critical
        await send_alert({
            "ioc":          ioc,
            "threat_score": scored["threat_score"],
            "severity":     scored["severity"],
            "country":      scored.get("country"),
            "ai_summary":   ai_summary or "",
        })

        bulk_results.append({
            **scored,
            "ai_summary": ai_summary,
        })

    db.commit()

    # Broadcast bulk complete
    await manager.broadcast({
        "type":  "bulk_complete",
        "count": len(bulk_results),
        "critical": sum(1 for r in bulk_results if r.get("severity") == "CRITICAL"),
        "high":     sum(1 for r in bulk_results if r.get("severity") == "HIGH"),
    })

    return {
        "total":    len(iocs),
        "results":  sorted(bulk_results, key=lambda x: x.get("threat_score", 0), reverse=True),
        "summary": {
            "critical": sum(1 for r in bulk_results if r.get("severity") == "CRITICAL"),
            "high":     sum(1 for r in bulk_results if r.get("severity") == "HIGH"),
            "medium":   sum(1 for r in bulk_results if r.get("severity") == "MEDIUM"),
            "low":      sum(1 for r in bulk_results if r.get("severity") == "LOW"),
        }
    }

# ── File Malware Analyzer ─────────────────────────────────────────────────────
@app.post("/api/analyze-file")
async def analyze_file_endpoint(
    file: UploadFile = File(...),
    ai:   bool       = Query(default=True),
):
    """
    Analyze any uploaded file for malicious code patterns.
    Combines static pattern detection + Groq AI deep analysis.
    """
    content_bytes = await file.read()

    # Try decode as text
    try:
        content = content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        try:
            content = content_bytes.decode("latin-1")
        except Exception:
            content = content_bytes.hex()

    # Static analysis
    static = analyze_file_static(file.filename, content)

    # AI analysis
    ai_analysis = None
    if ai:
        ai_analysis = await analyze_file_ai(file.filename, content, static)

    verdict, severity, color = get_verdict_severity(static["risk_score"])

    return {
        "filename":    file.filename,
        "verdict":     verdict,
        "severity":    severity,
        "color":       color,
        "risk_score":  static["risk_score"],
        "sha256":      static["sha256"],
        "findings":    static["findings"],
        "extension":   static["extension"],
        "file_size":   static["file_size"],
        "line_count":  static["line_count"],
        "ai_analysis": ai_analysis,
    }
    
# ── File Analysis History ──────────────────────────────────────────────────────
@app.get("/api/file-history")
async def file_history(
    limit: int     = Query(default=30),
    db:    Session = Depends(get_db),
):
    records = (
        db.query(FileAnalysis)
        .order_by(FileAnalysis.created_at.desc())
        .limit(limit)
        .all()
    )
    return {
        "count": len(records),
        "files": [
            {
                "id":          r.id,
                "filename":    r.filename,
                "verdict":     r.verdict,
                "risk_score":  r.risk_score,
                "sha256":      r.sha256,
                "file_size":   r.file_size,
                "findings":    r.findings,
                "ai_analysis": r.ai_analysis,
                "extension":   r.extension,
                "created_at":  str(r.created_at),
            }
            for r in records
        ]
    }
# ── Live Feed ─────────────────────────────────────────────────────────────────
@app.get("/api/feed")
async def get_feed(limit: int = Query(default=20, le=50)):
    pulses = await get_latest_pulses(limit=limit)
    return {"count": len(pulses), "pulses": pulses}


# ── Historical Threats ────────────────────────────────────────────────────────
@app.get("/api/threats")
async def get_threats(
    severity: str     = Query(default=None),
    limit:    int     = Query(default=50, le=200),
    db:       Session = Depends(get_db),
):
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
                "latitude":     r.latitude,
                "longitude":    r.longitude,
                "country":      r.country,
                "ai_summary":   r.ai_summary,
                "created_at":   str(r.created_at),
            }
            for r in records
        ],
    }


# ── Leaderboard ───────────────────────────────────────────────────────────────
@app.get("/api/leaderboard")
async def leaderboard(
    limit: int     = Query(default=10),
    db:    Session = Depends(get_db),
):
    records = (
        db.query(ThreatRecord)
        .order_by(ThreatRecord.threat_score.desc())
        .limit(limit)
        .all()
    )
    return {
    "leaderboard": [
        {
            "rank":         i + 1,
            "ioc":          r.ioc,
            "ioc_type":     r.ioc_type,
            "threat_score": r.threat_score,
            "severity":     r.severity,
            "country":      r.country,
            "ai_summary":   r.ai_summary,
            "boosts":       r.vt_data.get("boosts", []) if r.vt_data else [],
        }
        for i, r in enumerate(records)
    ]
}

# ── PDF Report ────────────────────────────────────────────────────────────────
@app.get("/api/report/{record_id}")
async def download_report(
    record_id: int,
    db: Session = Depends(get_db),
):
    """Generate and download a PDF threat report for a specific IOC record."""
    record = db.query(ThreatRecord).filter(ThreatRecord.id == record_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")

    report_data = {
        "ioc":          record.ioc,
        "ioc_type":     record.ioc_type,
        "threat_score": record.threat_score,
        "severity":     record.severity,
        "country":      record.country,
        "ai_summary":   record.ai_summary,
        "created_at":   str(record.created_at),
        "tags":         record.vt_data.get("tags", []) if record.vt_data else [],
        "raw_scores": {
            "vt":     record.vt_score,
            "abuse":  record.abuse_score,
            "shodan": record.shodan_score,
            "otx":    record.otx_score,
            "base":   round(
                record.vt_score * 0.35 +
                record.abuse_score * 0.30 +
                record.shodan_score * 0.20 +
                record.otx_score * 0.15, 2
            ),
            "final":  record.threat_score,
        },
    }

    pdf_bytes = generate_pdf_report(report_data)

    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="phantom_report_{record.ioc}.pdf"'
        }
    )

# ── Stats ─────────────────────────────────────────────────────────────────────
@app.get("/api/stats")
async def stats(db: Session = Depends(get_db)):
    from sqlalchemy import func

    total    = db.query(func.count(ThreatRecord.id)).scalar()
    critical = db.query(func.count(ThreatRecord.id)).filter(ThreatRecord.severity == "CRITICAL").scalar()
    high     = db.query(func.count(ThreatRecord.id)).filter(ThreatRecord.severity == "HIGH").scalar()
    avg      = db.query(func.avg(ThreatRecord.threat_score)).scalar()

    return {
        "total_analyzed": total,
        "critical_count": critical,
        "high_count":     high,
        "avg_score":      round(float(avg or 0), 2),
        "redis_status":   "online" if cache.health_check() else "offline",
    }


# ── Entry Point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.getenv("APP_PORT", 8000)),
        reload=True
    )
