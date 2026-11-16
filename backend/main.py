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
JWT_SECRET = os.getenv("JWT_SECRET") or secrets.token_urlsafe(48)
if not os.getenv("JWT_SECRET"):
    logger.warning("JWT_SECRET is unset; using an ephemeral local key. Configure a persistent JWT_SECRET in deployment.")
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
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "").replace("ADMIN_PASSWORD=", "")

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


class AuditEventORM(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    event_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    submission_id: Mapped[str] = mapped_column(String(64), index=True)
    event_type: Mapped[str] = mapped_column(String(80), nullable=False)
    actor: Mapped[str] = mapped_column(String(200), default="system")
    outcome: Mapped[str] = mapped_column(String(80), default="")
    risk_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    details: Mapped[Any] = mapped_column(JSON, default=dict)
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
    model_config = ConfigDict(extra="ignore")
    username: str = Field(default="admin", validation_alias=AliasChoices("username", "email", "user", "id"))
    password: str = Field(default="admin")


class EvaluateRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")
    content: str = Field(..., min_length=1, max_length=12000, validation_alias=AliasChoices("content", "text"))
    content_type: str = Field(default="text")
    image_base64: Optional[str] = None
    model_preference: str = Field(default="auto", description="auto, gemini-2.5-flash, or gemini-2.5-pro")
    regulatory_preset: Optional[str] = None
    brand_rules: str = ""
    modules: list[str] = Field(default_factory=list)


class RuleCreateRequest(BaseModel):
    title: str
    category: str = "General"
    severity: str = "HIGH"
    pattern: str
    description: str = ""


class SignOffRequest(BaseModel):
    submission_id: str
    version_hash: str = Field(..., validation_alias=AliasChoices("version_hash", "expected_version_hash"))
    decision: str = "APPROVED"
    reviewer: Optional[str] = None


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
    if not ADMIN_PASSWORD:
        raise HTTPException(status_code=503, detail="Reviewer login is not configured on the backend.")
    valid_username = hmac.compare_digest(payload.username, ADMIN_USERNAME)
    valid_password = hmac.compare_digest(payload.password, ADMIN_PASSWORD)
    if not (valid_username and valid_password):
        raise HTTPException(status_code=401, detail="Invalid enterprise credentials")
    role = os.getenv("ADMIN_ROLE", "admin").strip().lower()
    if role not in {"admin", "legal"}:
        role = "admin"
    exp = datetime.now(timezone.utc) + timedelta(minutes=JWT_MINUTES)
    token = jwt.encode({"sub": payload.username, "exp": exp, "role": role}, JWT_SECRET, algorithm=JWT_ALGORITHM)
    user = {"username": payload.username, "display_name": payload.username, "role": role}
    return {"access_token": token, "token": token, "token_type": "bearer",
            "expires_in_minutes": JWT_MINUTES, "username": payload.username, "role": role, "user": user}


from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
bearer_scheme = HTTPBearer(auto_error=False)


def require_reviewer(credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme)):
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Reviewer authentication required.")
    try:
        claims = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Reviewer session is invalid or expired.")
    role = str(claims.get("role", "")).lower()
    if role not in {"admin", "legal"}:
        raise HTTPException(status_code=403, detail="Legal/Admin role required.")
    return {"username": str(claims.get("sub", "reviewer")), "role": role}
    

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

    # Apply simple explicit phrase restrictions supplied by the reviewer UI.
    for line in (payload.brand_rules or "").splitlines():
        match_rule = re.search(r"(?:never mention|do not mention|avoid mentioning)\s+(.+?)[.;]?$", line.strip(), re.IGNORECASE)
        if match_rule:
            phrase = re.sub(r"^(?:the rival|rival|competitor)\s+", "", match_rule.group(1), flags=re.IGNORECASE).strip().strip("\'\"")
            found = re.search(re.escape(phrase), clean_text, re.IGNORECASE) if phrase else None
            if found:
                violations.append({"rule": "User-supplied brand rule", "severity": "HIGH",
                                   "category": "Brand Integrity", "matched_text": found.group(0)})
                evidence.append(f"Matched user-supplied brand restriction for '{phrase}'.")

    if payload.image_base64:
        raise HTTPException(status_code=501, detail="Image analysis is not enabled in this backend build. Submit text content only.")

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
                f"Reviewer-supplied brand rules: {payload.brand_rules or 'None supplied'}\n"
                f"Requested review modules: {', '.join(payload.modules) if payload.modules else 'all configured checks'}\n"
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
    try:
        db.add(record)
        db.flush()
        db.add(AuditEventORM(
            event_id=f"evt-{uuid.uuid4().hex}", submission_id=sub_id,
            event_type="REVIEW_COMPLETED", actor="system", outcome=status,
            risk_score=base_risk,
            details={"risk_level": risk_level, "version_id": version_id, "gemini_status": gemini_status},
        ))
        db.commit()
        db.refresh(record)
    except Exception:
        db.rollback()
        logger.exception("Could not persist review and audit event")
        raise HTTPException(status_code=500, detail="Review could not be saved to the audit database.")
    return serialize_submission(record)


@app.get("/submissions")
def list_submissions(limit: int = Query(default=25, ge=1, le=100), db: Session = Depends(get_db)):
    try:
        rows = db.scalars(select(SubmissionORM).order_by(SubmissionORM.id.desc()).limit(limit)).all()
        return [serialize_submission(r) for r in rows]
    except Exception:
        db.rollback()
        logger.exception("Could not load submissions")
        raise HTTPException(status_code=503, detail="Submission storage is temporarily unavailable.")


@app.get("/analytics")
def get_analytics(db: Session = Depends(get_db)):
    try:
        rows = db.scalars(select(SubmissionORM).order_by(SubmissionORM.id.desc()).limit(100)).all()
    except Exception:
        db.rollback()
        logger.exception("Could not load analytics")
        raise HTTPException(status_code=503, detail="Analytics storage is temporarily unavailable.")

    total = len(rows)
    approved = sum(1 for r in rows if getattr(r, "status", "") == "APPROVED")
    flagged = sum(1 for r in rows if getattr(r, "status", "") in ("FLAGGED", "REJECTED", "BLOCKED"))
    blocked = sum(1 for r in rows if getattr(r, "status", "") == "BLOCKED")
    avg_risk = round(sum(getattr(r, "risk_score", 0) or 0 for r in rows) / total, 1) if total else 0.0
    avg_brand = round(sum(getattr(r, "brand_alignment_score", 100) or 100 for r in rows) / total, 1) if total else 100.0
    avg_latency = round(sum(getattr(r, "total_ms", 0) or 0 for r in rows) / total, 1) if total else 0.0
    items = [serialize_submission(r) for r in rows[:25]]
    status_distribution = {}
    risk_distribution = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
    for row in rows:
        status_distribution[row.status] = status_distribution.get(row.status, 0) + 1
        level = getattr(row, "risk_level", "LOW") or "LOW"
        risk_distribution[level] = risk_distribution.get(level, 0) + 1

    return {
        "total_submissions": total,
        "total_reviews": total,
        "total": total,
        "approved": approved,
        "approved_count": approved,
        "flagged": flagged,
        "flagged_count": flagged,
        "rejected": flagged,
        "rejected_count": flagged,
        "blocked": blocked,
        "blocked_count": blocked,
        "approval_rate": round((approved / total) * 100, 1) if total else 100.0,
        "avg_risk_score": avg_risk,
        "average_risk_score": avg_risk,
        "avg_brand_score": avg_brand,
        "brand_alignment_avg": avg_brand,
        "guideline_health_score": avg_brand,
        "avg_latency_ms": avg_latency,
        "average_latency_ms": avg_latency,
        "pipeline_latency_ms": avg_latency,
        "threats_neutralized": flagged,
        "status_distribution": status_distribution,
        "risk_distribution": risk_distribution,
        "recent": items,
        "items": items,
        "logs": items,
        "submissions": items,
    }


@app.get("/audit-trail")
def get_audit_trail(limit: int = Query(default=50, ge=1, le=200), db: Session = Depends(get_db)):
    items = list_submissions(limit=limit, db=db)
    return {
        "count": len(items),
        "total": len(items),
        "items": items,
        "logs": items,
        "submissions": items,
        "records": items,
        "audit_trail": items,
    }


@app.post("/sign-off")
def sign_off_submission(
    payload: SignOffRequest,
    db: Session = Depends(get_db),
    reviewer: dict[str, str] = Depends(require_reviewer),
):
    sub = db.scalar(select(SubmissionORM).where(SubmissionORM.submission_id == payload.submission_id))
    if not sub:
        raise HTTPException(status_code=404, detail="Submission not found")
    if sub.status == "REJECTED":
        raise HTTPException(status_code=409, detail="Rejected submissions must be corrected and re-reviewed; they cannot be signed off.")
    if not hmac.compare_digest(sub.version_hash or "", payload.version_hash or ""):
        raise HTTPException(status_code=409, detail="Version hash mismatch! Content was modified after evaluation.")
    decision = payload.decision.upper()
    sub.sign_off_status = f"{decision}_BY_{reviewer['username'].upper().replace(' ', '_')}"
    try:
        db.add(AuditEventORM(
            event_id=f"evt-{uuid.uuid4().hex}", submission_id=sub.submission_id,
            event_type="REVIEW_SIGNED_OFF", actor=reviewer["username"], outcome=decision,
            risk_score=sub.risk_score,
            details={"version_hash": sub.version_hash, "sign_off_status": sub.sign_off_status},
        ))
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Could not persist sign-off audit event")
        raise HTTPException(status_code=500, detail="Sign-off could not be saved to the audit database.")
    return serialize_submission(sub)


# ============================= Frontend Route Compatibility Aliases =============================
@app.get("/api/health")
@app.get("/api/ready")
def api_health_alias(db: Session = Depends(get_db)):
    return {"status": "ok", "healthy": True, "database": "connected", "gemini_active": GEMINI_AVAILABLE}


@app.post("/api/auth/token")
@app.post("/api/auth/login")
@app.post("/auth/login")
def api_login_alias(payload: LoginRequest):
    return login_for_token(payload)


@app.post("/api/review/analyze")
@app.post("/api/evaluate")
@app.post("/api/review")
async def api_evaluate_alias(payload: EvaluateRequest, request: Request, db: Session = Depends(get_db)):
    return await evaluate_content(payload, request, db)


@app.get("/api/review/analytics")
@app.get("/api/analytics")
@app.get("/api/insights")
@app.get("/insights")
def api_analytics_alias(db: Session = Depends(get_db)):
    return get_analytics(db)


@app.get("/api/review/logs")
@app.get("/api/logs")
@app.get("/api/audit-trail")
@app.get("/api/review/audit-trail")
def api_logs_alias(
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
    reviewer: dict[str, str] = Depends(require_reviewer),
):
    events = db.scalars(select(AuditEventORM).order_by(AuditEventORM.id.desc()).limit(limit)).all()
    items = []
    for event in events:
        sub = db.scalar(select(SubmissionORM).where(SubmissionORM.submission_id == event.submission_id))
        details = event.details or {}
        items.append({
            "event_id": event.event_id, "event_type": event.event_type,
            "time": event.created_at.isoformat() if event.created_at else None,
            "timestamp": event.created_at.isoformat() if event.created_at else None,
            "created_at": event.created_at.isoformat() if event.created_at else None,
            "actor": event.actor, "reviewer": event.actor, "action": event.event_type,
            "outcome": event.outcome, "status": sub.status if sub else event.outcome,
            "submission_id": event.submission_id,
            "text_snippet": (sub.content[:140] + ("…" if len(sub.content) > 140 else "")) if sub else "",
            "risk_score": event.risk_score,
            "sign_off_status": sub.sign_off_status if sub else event.outcome,
            "sha256_version_hash": sub.version_hash if sub else details.get("version_hash"),
            "immutable_lock_hash": sub.version_hash if sub else details.get("version_hash"),
            "details": details,
        })
    audited_ids = {item["submission_id"] for item in items}
    legacy = db.scalars(select(SubmissionORM).order_by(SubmissionORM.id.desc()).limit(limit)).all()
    for sub in legacy:
        if sub.submission_id in audited_ids or len(items) >= limit:
            continue
        items.append({
            "event_id": f"legacy-{sub.submission_id}", "event_type": "LEGACY_REVIEW_RECORD",
            "time": sub.created_at.isoformat() if sub.created_at else None,
            "timestamp": sub.created_at.isoformat() if sub.created_at else None,
            "created_at": sub.created_at.isoformat() if sub.created_at else None,
            "actor": "not recorded", "reviewer": "not recorded", "action": "LEGACY_REVIEW_RECORD",
            "outcome": sub.status, "status": sub.status, "submission_id": sub.submission_id,
            "text_snippet": sub.content[:140] + ("…" if len(sub.content) > 140 else ""),
            "risk_score": sub.risk_score, "sign_off_status": sub.sign_off_status,
            "sha256_version_hash": sub.version_hash, "immutable_lock_hash": sub.version_hash,
            "details": {"note": "Historical submission; actor/event details were not captured at creation."},
        })
    return {"count": len(items), "total": len(items), "items": items, "logs": items,
            "submissions": items, "records": items, "data": items}


@app.get("/api/review/rules")
@app.get("/api/rules")
def api_rules_get_alias(db: Session = Depends(get_db)):
    try:
        return list_rules(db)
    except Exception:
        db.rollback()
        return []


@app.post("/api/review/rules")
@app.post("/api/rules")
def api_rules_post_alias(payload: RuleCreateRequest, db: Session = Depends(get_db)):
    return create_rule(payload, db)


@app.post("/api/sign-off")
@app.post("/api/review/sign-off")
def api_sign_off_alias(
    payload: SignOffRequest,
    db: Session = Depends(get_db),
    reviewer: dict[str, str] = Depends(require_reviewer),
):
    return sign_off_submission(payload, db, reviewer)
