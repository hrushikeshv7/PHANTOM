from sqlalchemy import Column, String, Float, Integer, Boolean, DateTime, Text, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func

Base = declarative_base()

class ThreatRecord(Base):
    __tablename__ = "threat_records"

    id           = Column(Integer, primary_key=True, index=True)
    ioc          = Column(String(255), index=True, nullable=False)
    ioc_type     = Column(String(20), nullable=False)
    threat_score = Column(Float, default=0.0)
    severity     = Column(String(10), default="LOW")
    country      = Column(String(100), nullable=True)
    latitude     = Column(Float, nullable=True)
    longitude    = Column(Float, nullable=True)
    is_blocked   = Column(Boolean, default=False)
    created_at   = Column(DateTime(timezone=True), server_default=func.now())
    updated_at   = Column(DateTime(timezone=True), onupdate=func.now())
    vt_data      = Column(JSON, nullable=True)
    shodan_data  = Column(JSON, nullable=True)
    abuse_data   = Column(JSON, nullable=True)
    otx_data     = Column(JSON, nullable=True)
    vt_score     = Column(Float, default=0.0)
    abuse_score  = Column(Float, default=0.0)
    shodan_score = Column(Float, default=0.0)
    otx_score    = Column(Float, default=0.0)
    ai_summary   = Column(Text, nullable=True)
    ner_entities = Column(JSON, nullable=True)

class FileAnalysis(Base):
    __tablename__ = "file_analyses"

    id           = Column(Integer, primary_key=True, index=True)
    filename     = Column(String(255), nullable=False)
    verdict      = Column(String(30), nullable=False)
    risk_score   = Column(Float, default=0.0)
    sha256       = Column(String(64), nullable=True)
    file_size    = Column(Integer, default=0)
    findings     = Column(JSON, nullable=True)
    ai_analysis  = Column(Text, nullable=True)
    extension    = Column(String(20), nullable=True)
    created_at   = Column(DateTime(timezone=True), server_default=func.now())

class APICallLog(Base):
    __tablename__ = "api_call_logs"

    id          = Column(Integer, primary_key=True, index=True)
    source      = Column(String(50), nullable=False)
    ioc         = Column(String(255), nullable=False)
    status_code = Column(Integer, nullable=True)
    success     = Column(Boolean, default=True)
    error_msg   = Column(Text, nullable=True)
    called_at   = Column(DateTime(timezone=True), server_default=func.now())
