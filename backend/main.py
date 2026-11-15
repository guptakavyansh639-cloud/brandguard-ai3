from pydantic import BaseModel, Field, AliasChoices
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import (JSON, Boolean, DateTime, Float, ForeignKey, Integer,
                        String, Text, create_engine, func, select)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker
from starlette.concurrency import run_in_threadpool

try:
    from google import genai
    from google.genai import types as genai_types
    GEMINI_AVAILABLE = True
except ImportError:
    genai = None
    genai_types = None
    GEMINI_AVAILABLE = False

# ----------------------------- Configuration -----------------------------
APP_VERSION = "4.1.0"
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./brandguard_local.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif DATABASE_URL.startswith("postgresql://") and "+psycopg" not in DATABASE_URL:
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
GEMINI_PRO_MODEL = os.getenv("GEMINI_PRO_MODEL", "gemini-2.5-pro")
JWT_SECRET = os.getenv("JWT_SECRET", "brandguard-enterprise-default-secret-key-2026")
JWT_ALGORITHM = "HS256"
JWT_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "480"))

CORS_ORIGINS = [
    "https://brandguard-frontend-coral.vercel.app",
    "https://brandguard-frontend-g3eno85fy-acers24.vercel.app",
    "https://brandguard-frontend.vercel.app",
    "http://localhost:5173",
    "http://localhost:3000",
]

MAX_TEXT_CHARS = int(os.getenv("MAX_TEXT_CHARS", "12000"))
MAX_IMAGE_BYTES = int(os.getenv("MAX_IMAGE_BYTES", str(5 * 1024 * 1024)))
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))
AUTH_REQUIRED_FOR_READS = os.getenv("AUTH_REQUIRED_FOR_READS", "false").lower() == "true"
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "brandguardadmin").replace("ADMIN_USERNAME=", "")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "bpit123").replace("ADMIN_PASSWORD=", "")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("brandguard")

# ----------------------------- Database Models -----------------------------
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, pool_pre_ping=True, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


class BrandRuleORM(Base):
    __tablename__ = "brand_rules"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    category: Mapped[str] = mapped_column(String(100), default="General")
    severity: Mapped[str] = mapped_column(String(50), default="HIGH")
    pattern: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class SubmissionORM(Base):
    __tablename__ = "submissions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    submission_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    content_type: Mapped[str] = mapped_column(String(50), default="text")
    status: Mapped[str] = mapped_column(String(50), default="FLAGGED")
    risk_level: Mapped[str] = mapped_column(String(50), default="LOW")
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    confidence_score: Mapped[float] = mapped_column(Float, default=0.95)
    brand_alignment_score: Mapped[int] = mapped_column(Integer, default=100)
    violations: Mapped[Any] = mapped_column(JSON, default=list)
    sanitized_rewrite: Mapped[str] = mapped_column(Text, default="")
    explanation: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[Any] = mapped_column(JSON, default=list)
    version_id: Mapped[str] = mapped_column(String(64), default="v1.0")
    version_hash: Mapped[str] = mapped_column(String(128), default="")
    sign_off_status: Mapped[str] = mapped_column(String(64), default="PENDING_REVIEW")
    escalation: Mapped[Any] = mapped_column(JSON, default=dict)
    injection_result: Mapped[Any] = mapped_column(JSON, default=dict)
    stage1_ms: Mapped[float] = mapped_column(Float, default=1.0)
    stage2_ms: Mapped[float] = mapped_column(Float, default=0.0)
    total_ms: Mapped[float] = mapped_column(Float, default=1.0)
    gemini_status: Mapped[str] = mapped_column(String(100), default="deterministic")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def seed_default_rules():
    with SessionLocal() as db:
        if db.scalar(select(func.count(BrandRuleORM.id))) == 0:
            defaults = [
                BrandRuleORM(
                    title="No Unverified Financial Guarantees",
                    category="Financial Compliance",
                    severity="CRITICAL",
                    pattern=r"\b(guaranteed returns|risk-free profit|100% safe investment|instant wealth)\b",
                    description="Prohibits misleading investment or financial return guarantees.",
                ),
                BrandRuleORM(
                    title="Superlative & Unsubstantiated Claims",
                    category="Brand Integrity",
                    severity="HIGH",
                    pattern=r"\b(no\.?\s*1 in the world|best on earth|100% cure|zero defects guaranteed)\b",
                    description="Blocks unsubstantiated absolute superlatives violating advertising codes.",
                ),
                BrandRuleORM(
                    title="Competitor Disparagement Guardrail",
                    category="Legal & Defamation",
                    severity="MEDIUM",
                    pattern=r"\b(competitor is a scam|fraudulent rival|destroy the competition)\b",
                    description="Prevents direct defamation of competing enterprises.",
                ),
                BrandRuleORM(
                    title="PII & Sensitive Credential Leak",
                    category="Data Privacy",
                    severity="CRITICAL",
                    pattern=r"\b(\d{3}-\d{2}-\d{4}|password\s*[:=]\s*\S+|api[_-]?key\s*[:=]\s*\S+)\b",
                    description="Detects accidental leakage of SSNs, passwords, or API credentials.",
                ),
            ]
            db.add_all(defaults)
            db.commit()


seed_default_rules()

# ----------------------------- Security & Sandbox -----------------------------
PROMPT_INJECTION_PATTERNS = [
    r"ignore (all )?(previous|prior) instructions",
    r"system override",
    r"you are now (dan|unrestricted|jailbroken)",
    r"bypass compliance",
    r"reveal system prompt",
]


def detect_prompt_injection(text: str) -> dict[str, Any]:
    matched = []
    for pat in PROMPT_INJECTION_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            matched.append(pat)
    return {
        "sandbox_triggered": len(matched) > 0,
        "threat_vectors_detected": len(matched),
        "matched_signatures": matched,
        "action": "QUARANTINED" if matched else "PASSED",
    }


def serialize_submission(s: SubmissionORM) -> dict[str, Any]:
    return {
        "submission_id": s.submission_id,
        "content": s.content,
        "content_type": s.content_type,
        "status": s.status,
        "risk_level": s.risk_level,
        "risk_score": s.risk_score,
        "confidence_score": s.confidence_score,
        "brand_alignment_score": s.brand_alignment_score,
        "violations": s.violations,
        "detected_violations": s.violations,
        "sanitized_rewrite": s.sanitized_rewrite,
        "explanation": s.explanation,
        "evidence": s.evidence,
        "version_lock_audit": {
            "version_id": s.version_id,
            "sha256_immutable_hash": s.version_hash,
            "sign_off_status": s.sign_off_status,
            "required_role": "Legal & Brand Compliance Lead" if s.status == "REJECTED" else "Content Reviewer",
        },
        "escalation_matrix": s.escalation,
        "prompt_injection_sandbox": s.injection_result,
        "telemetry": {
            "stage1_regex_ms": s.stage1_ms,
            "stage2_gemini_ms": s.stage2_ms,
            "total_ms": s.total_ms,
            "gemini_status": s.gemini_status,
        },
        "latency_ms": s.total_ms,
        "created_at": s.created_at.isoformat() if s.created_at else datetime.now(timezone.utc).isoformat(),
    }


# ----------------------------- App and Middleware -----------------------------
app = FastAPI(title="BrandGuard AI Enterprise Gateway", version=APP_VERSION)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://brandguard-frontend-coral.vercel.app",
        "http://localhost:3000",
        "http://localhost:5173",
        "*"
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

_rate_buckets: dict[str, deque[float]] = defaultdict(deque)


def rate_limit(request: Request):
    ip = request.client.host if request.client else "unknown"
    now = time.monotonic()
    bucket = _rate_buckets[ip]
    while bucket and now - bucket[0] > 60:
        bucket.popleft()
    if len(bucket) >= RATE_LIMIT_PER_MINUTE:
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Try again in a minute.")
    bucket.append(now)


# ----------------------------- Schemas -----------------------------
class LoginRequest(BaseModel):
    username: str
    password: str


class EvaluateRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=12000, validation_alias=AliasChoices("content", "text"))
    content_type: str = Field(default="text")
    image_base64: Optional[str] = None
    model_preference: str = Field(default="auto", description="auto, gemini-2.5-flash, or gemini-2.5-pro")
    regulatory_preset: Optional[str] = None


class RuleCreateRequest(BaseModel):
    title: str
    category: str = "General"
    severity: str = "HIGH"
    pattern: str
    description: str = ""


class SignOffRequest(BaseModel):
    submission_id: str
    version_hash: str
    decision: str = "APPROVED"
    reviewer: str = "Enterprise Compliance Lead"


# ----------------------------- Core Endpoints -----------------------------
@app.get("/")
def root():
    return {
        "service": "BrandGuard AI Enterprise Gateway",
        "version": APP_VERSION,
        "status": "online",
        "models": {"fast": GEMINI_MODEL, "deep": GEMINI_PRO_MODEL},
    }


@app.get("/health")
def health_check(db: Session = Depends(get_db)):
    total_eval = db.scalar(select(func.count(SubmissionORM.id))) or 0
    active_rules = db.scalar(select(func.count(BrandRuleORM.id)).where(BrandRuleORM.active == True)) or 0
    return {
        "status": "healthy",
        "healthy": True,
        "version": APP_VERSION,
        "gemini_active": GEMINI_AVAILABLE,
        "active_models": [GEMINI_MODEL, GEMINI_PRO_MODEL],
        "total_evaluated": total_eval,
        "active_rules": active_rules,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/ready")
def readiness_check(db: Session = Depends(get_db)):
    try:
        db.execute(select(1))
        return {"status": "ready", "database": "connected", "gemini_active": GEMINI_AVAILABLE}
    except Exception:
        logger.exception("Readiness check failed")
        raise HTTPException(status_code=503, detail="Database unavailable")


@app.post("/auth/token")
def login_for_token(payload: LoginRequest):
    if payload.username != ADMIN_USERNAME or payload.password != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid enterprise credentials")
    exp = datetime.now(timezone.utc) + timedelta(minutes=JWT_MINUTES)
    token = jwt.encode({"sub": payload.username, "exp": exp, "role": "admin"}, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {"access_token": token, "token_type": "bearer", "expires_in_minutes": JWT_MINUTES}


@app.get("/rules")
def list_rules(db: Session = Depends(get_db)):
    rules = db.scalars(select(BrandRuleORM).order_by(BrandRuleORM.id.desc())).all()
    return [
        {
            "id": r.id,
            "title": r.title,
            "category": r.category,
            "severity": r.severity,
            "pattern": r.pattern,
            "description": r.description,
            "active": r.active,
        }
        for r in rules
    ]


@app.post("/rules")
def create_rule(payload: RuleCreateRequest, db: Session = Depends(get_db)):
    rule = BrandRuleORM(
        title=payload.title,
        category=payload.category,
        severity=payload.severity.upper(),
        pattern=payload.pattern,
        description=payload.description,
        active=True,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return {"id": rule.id, "title": rule.title, "status": "created"}


@app.post("/evaluate")
async def evaluate_content(payload: EvaluateRequest, request: Request, db: Session = Depends(get_db)):
    rate_limit(request)
    t_start = time.perf_counter()
    clean_text = payload.content.strip()[:MAX_TEXT_CHARS]

    # Stage 1: Deterministic Regex + Prompt Injection Sandbox
    t_s1 = time.perf_counter()
    injection = detect_prompt_injection(clean_text)
    rules = db.scalars(select(BrandRuleORM).where(BrandRuleORM.active == True)).all()
    violations: list[dict[str, Any]] = []
    evidence: list[str] = []

    if injection["sandbox_triggered"]:
        violations.append({
            "rule": "Prompt Injection Sandbox",
            "severity": "CRITICAL",
            "category": "AI Security",
            "matched_text": ", ".join(injection["matched_signatures"]),
        })
        evidence.append("Blocked attempt to override system governance instructions.")

    for r in rules:
        try:
            match = re.search(r.pattern, clean_text, re.IGNORECASE)
            if match:
                violations.append({
                    "rule": r.title,
                    "severity": r.severity,
                    "category": r.category,
                    "matched_text": match.group(0),
                })
                evidence.append(f"Matched rule '{r.title}': '{match.group(0)}'")
        except re.error:
            continue

    stage1_ms = round((time.perf_counter() - t_s1) * 1000, 2)

    base_risk = min(100, len(violations) * 35 + (50 if injection["sandbox_triggered"] else 0))
    sanitized_rewrite = clean_text
    for v in violations:
        if v.get("matched_text"):
            sanitized_rewrite = re.sub(re.escape(v["matched_text"]), "[REDACTED BY BRANDGUARD]", sanitized_rewrite, flags=re.IGNORECASE)

    explanation = (
        f"Detected {len(violations)} policy violation(s) in deterministic scan."
        if violations else "Content passed deterministic policy checks."
    )

    # Stage 2: Intelligent Dual-Model Gemini 2.5 Routing
    t_s2 = time.perf_counter()
    chosen_model = (
        GEMINI_PRO_MODEL
        if (payload.model_preference == "gemini-2.5-pro" or (payload.model_preference == "auto" and base_risk >= 35))
        else GEMINI_MODEL
    )
    gemini_status = f"deterministic-only ({chosen_model} standby)"

    if genai and GEMINI_API_KEY and not injection["sandbox_triggered"]:
        try:
            client = genai.Client(api_key=GEMINI_API_KEY)
            prompt = (
                f"You are BrandGuard AI Enterprise Auditor powered by {chosen_model}.\n"
                f"Evaluate the following content for brand safety, regulatory compliance, and tone.\n"
                f"Existing deterministic violations found: {json.dumps(violations)}\n"
                f"Return strict JSON with keys: risk_score (int 0-100), explanation (str), sanitized_rewrite (str).\n"
                f"Content: {clean_text}"
            )
            resp = await run_in_threadpool(
                client.models.generate_content,
                model=chosen_model,
                contents=prompt,
                config=genai_types.GenerateContentConfig(
                    temperature=0.1,
                    response_mime_type="application/json",
                ) if genai_types else None,
            )
            parsed = json.loads(resp.text or "{}")
            base_risk = max(base_risk, int(parsed.get("risk_score", base_risk)))
            explanation = parsed.get("explanation", explanation)
            sanitized_rewrite = parsed.get("sanitized_rewrite", sanitized_rewrite)
            gemini_status = f"verified-by-{chosen_model}"
        except Exception as exc:
            logger.warning("Primary model %s fallback triggered: %s", chosen_model, exc)
            gemini_status = f"fallback-deterministic ({chosen_model})"

    stage2_ms = round((time.perf_counter() - t_s2) * 1000, 2)
    total_ms = round((time.perf_counter() - t_start) * 1000, 2)

    risk_level = "HIGH" if base_risk >= 70 else ("MEDIUM" if base_risk >= 35 else "LOW")
    status = "REJECTED" if base_risk >= 70 else ("FLAGGED" if base_risk >= 35 else "APPROVED")
    alignment_score = max(0, 100 - base_risk)

    sub_id = f"sub-{uuid.uuid4().hex[:12]}"
    version_id = f"v4.1-{int(time.time())}"
    version_hash = hashlib.sha256(f"{sub_id}|{clean_text}|{base_risk}|{version_id}".encode()).hexdigest()

    escalation = {
        "escalation_required": base_risk >= 70,
        "assigned_tier": "Tier-3 Legal Counsel (Gemini 2.5 Pro)" if base_risk >= 70 else "Tier-1 Automated Gate",
        "sla_minutes": 15 if base_risk >= 70 else 0,
    }

    record = SubmissionORM(
        submission_id=sub_id,
        content=clean_text,
        content_type=payload.content_type,
        status=status,
        risk_level=risk_level,
        risk_score=base_risk,
        confidence_score=0.98 if "verified" in gemini_status else 0.92,
        brand_alignment_score=alignment_score,
        violations=violations,
        sanitized_rewrite=sanitized_rewrite,
        explanation=explanation,
        evidence=evidence,
        version_id=version_id,
        version_hash=version_hash,
        sign_off_status="AUTO_CLEARED" if status == "APPROVED" else "PENDING_SIGN_OFF",
        escalation=escalation,
        injection_result=injection,
        stage1_ms=stage1_ms,
        stage2_ms=stage2_ms,
        total_ms=total_ms,
        gemini_status=gemini_status,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return serialize_submission(record)


@app.get("/submissions")
def list_submissions(limit: int = Query(default=25, ge=1, le=100), db: Session = Depends(get_db)):
    rows = db.scalars(select(SubmissionORM).order_by(SubmissionORM.id.desc()).limit(limit)).all()
    return [serialize_submission(r) for r in rows]


@app.get("/analytics")
def get_analytics(db: Session = Depends(get_db)):
    rows = db.scalars(select(SubmissionORM).order_by(SubmissionORM.id.desc()).limit(100)).all()
    total = len(rows)
    threats = sum(1 for r in rows if r.status in ("REJECTED", "FLAGGED"))
    avg_latency = round(sum(r.total_ms for r in rows) / total, 2) if total else 1.2
    avg_alignment = round(sum(r.brand_alignment_score for r in rows) / total, 1) if total else 98.5
    return {
        "total_evaluated": total,
        "threats_neutralized": threats,
        "pipeline_latency_ms": avg_latency,
        "guideline_health": f"{avg_alignment}%",
        "active_models": {"realtime": GEMINI_MODEL, "deep_reasoning": GEMINI_PRO_MODEL},
        "recent_submissions": [serialize_submission(r) for r in rows[:10]],
    }


@app.get("/audit-trail")
def get_audit_trail(db: Session = Depends(get_db)):
    rows = db.scalars(select(SubmissionORM).order_by(SubmissionORM.id.desc()).limit(50)).all()
    return {"count": len(rows), "items": [serialize_submission(r) for r in rows]}


@app.post("/sign-off")
def sign_off_submission(payload: SignOffRequest, db: Session = Depends(get_db)):
    sub = db.scalar(select(SubmissionORM).where(SubmissionORM.submission_id == payload.submission_id))
    if not sub:
        raise HTTPException(status_code=404, detail="Submission not found")
    if sub.version_hash != payload.version_hash:
        raise HTTPException(status_code=409, detail="Version hash mismatch! Content was modified after evaluation.")
    sub.sign_off_status = f"{payload.decision.upper()}_BY_{payload.reviewer.upper().replace(' ', '_')}"
    db.commit()
    db.refresh(sub)
    return serialize_submission(sub)


# ============================= Frontend Route Compatibility Aliases =============================
@app.post("/api/auth/token")
def api_login_alias(payload: LoginRequest):
    return login_for_token(payload)


@app.post("/api/auth/login")
def api_login_alias_v2(payload: LoginRequest):
    return login_for_token(payload)


@app.post("/api/review/analyze")
async def api_evaluate_alias_1(payload: EvaluateRequest, request: Request, db: Session = Depends(get_db)):
    return await evaluate_content(payload, request, db)


@app.post("/api/evaluate")
async def api_evaluate_alias_2(payload: EvaluateRequest, request: Request, db: Session = Depends(get_db)):
    return await evaluate_content(payload, request, db)