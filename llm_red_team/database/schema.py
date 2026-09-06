"""Database schema definitions."""

from sqlalchemy import (
    Column, DateTime, Float, ForeignKey, Integer, JSON, String, Text, Boolean,
    create_engine, Index
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from datetime import datetime

Base = declarative_base()


class Model(Base):
    __tablename__ = "models"
    id = Column(String(36), primary_key=True)
    name = Column(String(100), nullable=False)
    provider = Column(String(50), nullable=False)
    model_id = Column(String(100), nullable=False)
    type = Column(String(20), nullable=False)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)


class Prompt(Base):
    __tablename__ = "prompts"
    id = Column(String(36), primary_key=True)
    tier = Column(Integer, nullable=False)
    category = Column(String(50), nullable=False)
    prompt_text = Column(Text, nullable=False)
    attack_type = Column(String(50))
    created_at = Column(DateTime, default=datetime.utcnow)


class TestResult(Base):
    __tablename__ = "test_results"
    id = Column(String(36), primary_key=True)
    model_id = Column(String(36), ForeignKey("models.id"))
    prompt_id = Column(String(36), ForeignKey("prompts.id"))
    attack_category = Column(String(50))
    tier = Column(Integer)
    prompt_text = Column(Text)
    response = Column(Text)
    tokens_used = Column(Integer)
    latency_ms = Column(Integer)
    success = Column(Boolean)
    severity_score = Column(Float)
    vulnerability_type = Column(String(50))
    root_cause = Column(String(100))
    metadata = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)

    model = relationship("Model", backref="test_results")
    prompt = relationship("Prompt", backref="test_results")


class DefenseResult(Base):
    __tablename__ = "defense_results"
    id = Column(String(36), primary_key=True)
    defense_strategy = Column(String(100), nullable=False)
    model_id = Column(String(36), ForeignKey("models.id"))
    prompt_id = Column(String(36), ForeignKey("prompts.id"))
    blocked = Column(Boolean)
    false_positive = Column(Boolean)
    latency_impact_ms = Column(Integer)
    effectiveness_score = Column(Float)
    created_at = Column(DateTime, default=datetime.utcnow)


# Indexes
Index("idx_results_model", TestResult.model_id)
Index("idx_results_prompt", TestResult.prompt_id)
Index("idx_results_vuln_type", TestResult.vulnerability_type)
Index("idx_results_created", TestResult.created_at)


def get_session(db_url: str = "sqlite:///llm_red_team.db"):
    """Create a database session."""
    engine = create_engine(db_url)
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    return SessionLocal()
