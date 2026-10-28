from pathlib import Path
from uuid import uuid4
from contextlib import asynccontextmanager
import hashlib, json, mimetypes, os
from datetime import datetime, timezone
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from sqlalchemy import select, inspect, text, delete
from .config import settings
from .db import Base, engine, get_db, SessionLocal
from .models import User, Application, Document, Finding, AuditEvent, OfficerReview
from .schemas import (
    LoginIn, TokenOut, UserOut, ApplicationIn, ApplicationOut, StatusUpdate,
    OfficerReviewIn, OfficerReviewOut, UserCreate, UserUpdate, AssignOfficerIn,
)
from .security import hash_password, verify_password, create_token, get_current_user, require_roles
from .audit import log_event
from .services import extract_text, classify_document, store_findings, heuristic_risk, gemini_memo
import logging

logger = logging.getLogger("brocode")
logging.getLogger("httpx").setLevel(logging.WARNING)

def log_gemini_startup_configuration() -> dict:
    """
    Logs effective Gemini configuration safely at startup:
    - Primary and fallback model IDs
    - Configuration source (environment variable override vs .env file)
    - Validates models against actual Google Gemini API models available to key/project
    - Never logs API keys or secrets.
    """
    from .config import get_model_config_diagnostics
    from .services import validate_gemini_models

    diag = get_model_config_diagnostics()
    primary = diag["effective_primary_model"]
    fallback = diag["effective_fallback_model"] or "none"
    has_key = diag["api_key_configured"]

    logger.info("================================================================================")
    logger.info("BroCode Gemini Startup Configuration:")
    logger.info("  Effective Primary Model:  '%s'", primary)
    logger.info("  Effective Fallback Model: '%s'", fallback)
    logger.info("  API Key Configured:       %s", "YES (masked)" if has_key else "NO (deterministic fallback only)")

    if diag["is_overridden_by_env"]:
        if diag["env_var_override_primary"]:
            logger.warning(
                "  NOTE: GEMINI_MODEL is overridden by OS/shell environment variable: '%s' "
                "(this takes precedence over values in backend/.env).",
                diag["env_var_override_primary"],
            )
        if diag["env_var_override_fallback"]:
            logger.warning(
                "  NOTE: GEMINI_FALLBACK_MODEL is overridden by OS/shell environment variable: '%s'.",
                diag["env_var_override_fallback"],
            )
    else:
        loaded = diag.get("loaded_env_files") or []
        logger.info("  Loaded from .env files:   %s", ", ".join(loaded) if loaded else "None (default settings)")

    # Validate against actual Google Gemini API models available to key/project
    val_report = validate_gemini_models(primary, fallback if fallback != "none" else "")
    logger.info("  Model Validation Source:  %s", val_report["validation_source"])
    if val_report["primary_valid"]:
        logger.info("  Primary Model Status:     VALID (%s)", val_report["detail"])
    else:
        logger.warning("  Primary Model Status:     INVALID / UNAVAILABLE (%s)", val_report["detail"])

    if fallback != "none":
        if val_report["fallback_valid"]:
            logger.info("  Fallback Model Status:    VALID")
        else:
            logger.warning("  Fallback Model Status:    INVALID / UNAVAILABLE")

    logger.info("================================================================================")
    return {
        "diagnostics": diag,
        "validation": val_report,
    }


# ---------------------------------------------------------------------------
# Startup: create tables, run schema migrations + seed demo users safely
# ---------------------------------------------------------------------------
def startup():
    Base.metadata.create_all(bind=engine)
    # Check and apply migrations for existing databases
    try:
        inspector = inspect(engine)
        existing_tables = inspector.get_table_names()
        with engine.connect() as conn:
            if "applications" in existing_tables:
                app_cols = [c["name"] for c in inspector.get_columns("applications")]
                if "assigned_officer_id" not in app_cols:
                    conn.execute(text("ALTER TABLE applications ADD COLUMN assigned_officer_id INTEGER REFERENCES users(id)"))
                if "submission_version" not in app_cols:
                    conn.execute(text("ALTER TABLE applications ADD COLUMN submission_version INTEGER DEFAULT 1"))

            if "documents" in existing_tables:
                doc_cols = [c["name"] for c in inspector.get_columns("documents")]
                if "uploaded_by" not in doc_cols:
                    conn.execute(text("ALTER TABLE documents ADD COLUMN uploaded_by INTEGER REFERENCES users(id)"))
                if "upload_type" not in doc_cols:
                    conn.execute(text("ALTER TABLE documents ADD COLUMN upload_type VARCHAR(30) DEFAULT 'institution_document'"))
                if "submission_version" not in doc_cols:
                    conn.execute(text("ALTER TABLE documents ADD COLUMN submission_version INTEGER DEFAULT 1"))

            if "officer_reviews" in existing_tables:
                rev_cols = [c["name"] for c in inspector.get_columns("officer_reviews")]
                if "finding_references" not in rev_cols:
                    conn.execute(text("ALTER TABLE officer_reviews ADD COLUMN finding_references JSON DEFAULT '[]'"))
                if "correction_instructions" not in rev_cols:
                    conn.execute(text("ALTER TABLE officer_reviews ADD COLUMN correction_instructions TEXT DEFAULT ''"))

            conn.commit()
    except Exception as e:
        logger.warning("Migration check: %s", e)

    if settings.seed_demo_users:
        db = SessionLocal()
        try:
            demos = [
                ("institution@example.com", "DemoInstitution123!", "Demo Institution User", "institution"),
                ("officer@example.com", "DemoOfficer123!", "Demo Compliance Officer", "officer"),
                ("admin@example.com", "DemoAdmin123!", "Demo Administrator", "admin"),
            ]
            for email, pw, name, role in demos:
                if not db.scalar(select(User).where(User.email == email.lower())):
                    db.add(User(email=email.lower(), password_hash=hash_password(pw), name=name, role=role))
            db.commit()
        finally:
            db.close()

    try:
        log_gemini_startup_configuration()
    except Exception as e:
        logger.warning("Gemini startup configuration log error: %s", e)


@asynccontextmanager
async def lifespan(app_instance: FastAPI):
    startup()
    yield


app = FastAPI(
    title=settings.app_name,
    version="1.2.0",
    description="Pre-screening aid only; not an official AICTE decision system.",
    lifespan=lifespan,
)
origins = [x.strip() for x in settings.cors_origins.split(",") if x.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)
UPLOAD_DIR = Path(settings.upload_dir).resolve()
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
ALLOWED = {"application/pdf", "image/png", "image/jpeg", "image/webp"}
MAX_BYTES = settings.max_upload_mb * 1024 * 1024


# ---------------------------------------------------------------------------
# Access Control Helpers
# ---------------------------------------------------------------------------
def can_access(app_record: Application, user: User) -> bool:
    """
    Access rules:
    - Draft applications: Visible ONLY to the institution that owns them.
      Neither officers nor admins may access another institution's draft.
    - Submitted / Active applications:
      - Admin: Full oversight access across all applications.
      - Institution: Access only to own applications.
      - Officer: Access to applications assigned to them, or unassigned applications (triage queue).
        Officers CANNOT access applications assigned exclusively to other officers.
    """
    if app_record.status == "DRAFT":
        if user.role == "institution":
            return app_record.owner_id == user.id
        # Neither officers nor admins may access draft applications
        return False

    if user.role == "admin":
        return True
    if user.role == "institution":
        return app_record.owner_id == user.id
    if user.role == "officer":
        return (app_record.assigned_officer_id == user.id) or (app_record.assigned_officer_id is None)
    return False


def can_modify_officer(app_record: Application, user: User) -> bool:
    """Only the explicitly assigned officer or an administrator may alter status or add reviews.
    Draft applications CANNOT be modified, assigned, or reviewed by officers prior to institutional submission."""
    if app_record.status == "DRAFT":
        return False
    if user.role == "admin":
        return True
    if user.role == "officer":
        return app_record.assigned_officer_id == user.id
    return False


def app_or_404(db: Session, app_id: int, user: User) -> Application:
    record = db.get(Application, app_id)
    if not record or not can_access(record, user):
        raise HTTPException(404, "Application not found")
    return record


def safe_unlink_stored_file(db: Session, stored_name: str, excluding_doc_ids: list[int] | None = None) -> bool:
    """Safely unlink a file from UPLOAD_DIR only if no remaining Document record in the database references it."""
    if not stored_name:
        return False
    q = select(Document).where(Document.stored_name == stored_name)
    if excluding_doc_ids:
        q = q.where(Document.id.not_in(excluding_doc_ids))
    other_ref = db.scalar(q)
    if other_ref:
        # File is still referenced by another record; preserve file on disk
        return False
    path = UPLOAD_DIR / stored_name
    try:
        path.unlink(missing_ok=True)
        return True
    except Exception as e:
        logger.warning("Failed to unlink stored file %s: %s", path, e)
        return False


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "mode": "pre-screening",
        "live_aicte_integration": False,
        "officer_assignment_model": "assigned_officer_enforced",
        "message": "Issuer verification requires an authorized integration; manual review otherwise.",
    }


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
@app.post("/api/auth/login", response_model=TokenOut)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == form.username.lower()))
    if not user or not verify_password(form.password, user.password_hash) or not user.active:
        raise HTTPException(401, "Incorrect email or password")
    log_event(db, user.id, "USER_LOGIN", "user", user.id, {"email": user.email})
    db.commit()
    return {"access_token": create_token(user), "user": user}


@app.get("/api/auth/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user


# ---------------------------------------------------------------------------
# Admin: User management
# ---------------------------------------------------------------------------
@app.get("/api/admin/users")
def list_users(db: Session = Depends(get_db), user: User = Depends(require_roles("admin"))):
    rows = db.scalars(select(User).order_by(User.id)).all()
    return [
        {"id": u.id, "email": u.email, "name": u.name, "role": u.role, "active": u.active}
        for u in rows
    ]


@app.post("/api/admin/users", response_model=UserOut)
def create_user(payload: UserCreate, db: Session = Depends(get_db), user: User = Depends(require_roles("admin"))):
    if db.scalar(select(User).where(User.email == payload.email.lower())):
        raise HTTPException(409, "Email already registered")
    new_user = User(
        email=payload.email.lower(),
        password_hash=hash_password(payload.password),
        name=payload.name,
        role=payload.role,
    )
    db.add(new_user)
    db.flush()
    log_event(db, user.id, "USER_CREATED", "user", new_user.id, {"email": new_user.email, "role": new_user.role})
    db.commit()
    db.refresh(new_user)
    return new_user


@app.patch("/api/admin/users/{user_id}")
def update_user(user_id: int, payload: UserUpdate, db: Session = Depends(get_db), user: User = Depends(require_roles("admin"))):
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(404, "User not found")
    changes = {}
    if payload.name is not None:
        target.name = payload.name
        changes["name"] = payload.name
    if payload.role is not None:
        target.role = payload.role
        changes["role"] = payload.role
    if payload.active is not None:
        target.active = payload.active
        changes["active"] = payload.active
    if not changes:
        raise HTTPException(400, "No changes provided")
    log_event(db, user.id, "USER_UPDATED", "user", target.id, changes)
    db.commit()
    return {"id": target.id, "email": target.email, "name": target.name, "role": target.role, "active": target.active}


@app.get("/api/officers")
def list_officers(db: Session = Depends(get_db), user: User = Depends(require_roles("officer", "admin"))):
    """List all active officers for assignment purposes."""
    rows = db.scalars(
        select(User).where(User.role == "officer", User.active == True).order_by(User.name)
    ).all()
    return [{"id": u.id, "name": u.name, "email": u.email} for u in rows]


# ---------------------------------------------------------------------------
# Applications
# ---------------------------------------------------------------------------
@app.post("/api/applications", response_model=ApplicationOut)
def create_application(
    payload: ApplicationIn,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles("institution")),
):
    record = Application(**payload.model_dump(), owner_id=user.id, submission_version=1)
    db.add(record)
    db.flush()
    log_event(
        db, user.id, "APPLICATION_CREATED", "application", record.id,
        {"academic_year": record.academic_year, "type": record.application_type},
    )
    db.commit()
    db.refresh(record)
    return record


@app.get("/api/applications")
def list_applications(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    q = select(Application).order_by(Application.updated_at.desc())
    if user.role == "institution":
        # Institutions see only their own applications (including their own drafts)
        q = q.where(Application.owner_id == user.id)
    elif user.role == "officer":
        # Officers never see draft applications; only see assigned-to-self or unassigned
        q = q.where(
            Application.status != "DRAFT",
            (Application.assigned_officer_id == user.id) | (Application.assigned_officer_id.is_(None)),
        )
    else:
        # Admins and any other role: never see draft applications
        q = q.where(Application.status != "DRAFT")

    rows = db.scalars(q).all()
    officer_ids = {a.assigned_officer_id for a in rows if a.assigned_officer_id}
    officer_map = {}
    if officer_ids:
        officers = db.scalars(select(User).where(User.id.in_(officer_ids))).all()
        officer_map = {o.id: o.name for o in officers}

    return [
        {
            "id": a.id,
            "institution_name": a.institution_name,
            "institution_code": a.institution_code,
            "application_type": a.application_type,
            "academic_year": a.academic_year,
            "programme": a.programme,
            "status": a.status,
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "owner_id": a.owner_id,
            "assigned_officer_id": a.assigned_officer_id,
            "assigned_officer_name": officer_map.get(a.assigned_officer_id),
            "submission_version": getattr(a, "submission_version", 1),
        }
        for a in rows
    ]


@app.delete("/api/applications/{app_id}")
def delete_draft_application(
    app_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles("institution")),
):
    a = db.get(Application, app_id)
    # Prevent one institution from deleting another institution's draft or discovering its existence
    if not a or a.owner_id != user.id:
        raise HTTPException(404, "Application not found")

    if a.status != "DRAFT":
        raise HTTPException(
            409,
            f"Cannot delete application with status '{a.status}'. Only Draft applications may be deleted. Submitted or reviewed applications must follow official compliance procedures.",
        )

    # Gather associated documents and files to clean up physical storage safely
    docs = db.scalars(select(Document).where(Document.application_id == app_id)).all()
    doc_ids = [d.id for d in docs]
    stored_names = [d.stored_name for d in docs if d.stored_name]

    app_meta = {
        "institution_name": a.institution_name,
        "institution_code": a.institution_code,
        "academic_year": a.academic_year,
        "application_type": a.application_type,
        "documents_count": len(docs),
    }

    # Clean up associated database records in a single transaction
    db.execute(delete(Finding).where(Finding.application_id == app_id))
    db.execute(delete(OfficerReview).where(OfficerReview.application_id == app_id))
    db.execute(delete(Document).where(Document.application_id == app_id))

    # Log deletion audit event before committing
    log_event(
        db, user.id, "APPLICATION_DRAFT_DELETED", "application", app_id, app_meta
    )

    db.delete(a)
    db.commit()

    # Safely remove physical files from storage after database commit (only if unreferenced elsewhere)
    for sname in stored_names:
        safe_unlink_stored_file(db, sname, excluding_doc_ids=doc_ids)

    return {
        "message": f"Draft application #{app_id} and all associated files have been permanently deleted.",
        "application_id": app_id,
    }


@app.get("/api/applications/{app_id}")
def application_detail(app_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    a = app_or_404(db, app_id, user)
    all_docs = db.scalars(select(Document).where(Document.application_id == app_id).order_by(Document.id)).all()
    finds = db.scalars(
        select(Finding).where(Finding.application_id == app_id).order_by(Finding.id.desc())
    ).all()
    reviews = db.scalars(
        select(OfficerReview).where(OfficerReview.application_id == app_id).order_by(OfficerReview.id.desc())
    ).all()

    # Document-level authorization: Filter officer evidence out for institution users
    if user.role == "institution":
        visible_docs = [d for d in all_docs if d.upload_type != "officer_evidence"]
    else:
        visible_docs = all_docs

    risk = heuristic_risk(finds)

    # Compute submission version history
    max_version = getattr(a, "submission_version", 1) or 1
    submission_history = []
    for v in range(1, max_version + 1):
        v_docs = [d for d in visible_docs if getattr(d, "submission_version", 1) == v]
        submission_history.append({
            "version": v,
            "stage": "Initial Submission" if v == 1 else f"Rectification Cycle #{v - 1}",
            "documents_count": len(v_docs),
            "documents": [{"id": d.id, "name": d.original_name, "type": d.doc_type} for d in v_docs],
        })

    assigned_officer = db.get(User, a.assigned_officer_id) if a.assigned_officer_id else None
    app_data = ApplicationOut.model_validate(a).model_dump()
    app_data["assigned_officer_name"] = assigned_officer.name if assigned_officer else None
    app_data["assigned_officer_email"] = assigned_officer.email if assigned_officer else None

    return {
        "application": app_data,
        "documents": [
            {
                "id": d.id,
                "original_name": d.original_name,
                "mime_type": d.mime_type,
                "doc_type": d.doc_type,
                "sha256": d.sha256,
                "verification_status": d.verification_status,
                "upload_type": d.upload_type,
                "submission_version": getattr(d, "submission_version", 1),
                "text_characters": len(d.extracted_text),
                "created_at": d.created_at.isoformat() if d.created_at else None,
            }
            for d in visible_docs
        ],
        "findings": [
            {
                "id": f.id,
                "document_id": f.document_id,
                "rule_id": f.rule_id,
                "severity": f.severity,
                "result": f.result,
                "message": f.message,
                "source_reference": f.source_reference,
                "evidence": f.evidence,
            }
            for f in finds
        ],
        "reviews": [
            {
                "id": r.id,
                "officer_id": r.officer_id,
                "action": r.action,
                "notes": r.notes,
                "finding_references": getattr(r, "finding_references", []) or [],
                "correction_instructions": getattr(r, "correction_instructions", "") or "",
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in reviews
        ],
        "submission_history": submission_history,
        "risk_score": risk,
        "risk_score_note": "Heuristic triage score, not a probability of fraud or a regulatory decision.",
        "live_issuer_verification": "NOT_CONFIGURED",
    }


# ---------------------------------------------------------------------------
# Officer Assignment Endpoint
# ---------------------------------------------------------------------------
@app.patch("/api/applications/{app_id}/assign")
def assign_application(
    app_id: int,
    payload: AssignOfficerIn,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles("officer", "admin")),
):
    a = db.get(Application, app_id)
    if not a or not can_access(a, user):
        raise HTTPException(404, "Application not found")

    if a.status == "DRAFT":
        raise HTTPException(409, "Draft applications cannot be assigned to officers before institutional submission")

    if user.role == "officer":
        # Officer can claim an unassigned application or release their own assignment
        if a.assigned_officer_id is not None and a.assigned_officer_id != user.id:
            raise HTTPException(403, "This application is already assigned to another officer")
        if payload.officer_id not in (user.id, None):
            raise HTTPException(403, "Officers can only assign applications to themselves")
        target_officer_id = payload.officer_id
    else:  # Admin
        if payload.officer_id is not None:
            target_user = db.get(User, payload.officer_id)
            if not target_user or target_user.role != "officer" or not target_user.active:
                raise HTTPException(400, "Assigned user must be an active officer")
        target_officer_id = payload.officer_id

    old_officer_id = a.assigned_officer_id
    a.assigned_officer_id = target_officer_id
    log_event(
        db, user.id, "APPLICATION_OFFICER_ASSIGNED", "application", a.id,
        {"from_officer_id": old_officer_id, "to_officer_id": target_officer_id},
    )
    db.commit()
    target_officer = db.get(User, target_officer_id) if target_officer_id else None
    return {
        "id": a.id,
        "assigned_officer_id": a.assigned_officer_id,
        "assigned_officer_name": target_officer.name if target_officer else None,
    }


# ---------------------------------------------------------------------------
# Document upload — INSTITUTION ONLY for institutional documents
# ---------------------------------------------------------------------------
@app.post("/api/applications/{app_id}/documents")
async def upload_document(
    app_id: int,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(require_roles("institution")),
):
    a = app_or_404(db, app_id, user)
    # Institution can only upload to their own applications
    if a.owner_id != user.id:
        raise HTTPException(403, "You can only upload documents to your own applications")
    if a.status not in ("DRAFT", "DEFICIENCY_RAISED", "RECTIFICATION_SUBMITTED"):
        raise HTTPException(409, "Application is not accepting documents in its current state")

    mime = file.content_type or mimetypes.guess_type(file.filename or "")[0] or "application/octet-stream"
    if mime not in ALLOWED:
        raise HTTPException(415, "Only PDF, PNG, JPEG and WebP files are accepted")

    data = await file.read(MAX_BYTES + 1)
    if not data:
        raise HTTPException(400, "Empty file")
    if len(data) > MAX_BYTES:
        raise HTTPException(413, f"File exceeds {settings.max_upload_mb} MB limit")

    # Validate file integrity
    if mime == "application/pdf":
        if not data.startswith(b"%PDF"):
            raise HTTPException(400, "File does not look like a valid PDF")
        try:
            import fitz
            doc_test = fitz.open(stream=data, filetype="pdf")
            if doc_test.page_count < 1:
                doc_test.close()
                raise HTTPException(400, "PDF contains no pages")
            doc_test.close()
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(400, "Corrupted or invalid PDF file")
    elif mime.startswith("image/"):
        try:
            from PIL import Image
            import io as _io
            img = Image.open(_io.BytesIO(data))
            img.verify()
        except Exception:
            raise HTTPException(400, "Invalid or unsupported image file")

    digest = hashlib.sha256(data).hexdigest()

    # Scope-aware duplicate detection with zero cross-institution leakage
    dup_in_app = db.scalar(
        select(Document).where(Document.sha256 == digest, Document.application_id == app_id)
    )
    dup_global = db.scalar(
        select(Document).where(Document.sha256 == digest, Document.application_id != app_id)
    )

    duplicate_info = None
    if dup_in_app:
        duplicate_info = {
            "scope": "same_application",
            "matched_document_id": dup_in_app.id,
            "matched_filename": dup_in_app.original_name,
            "message": f"Exact duplicate of '{dup_in_app.original_name}' (Document #{dup_in_app.id}) in this application.",
        }
    elif dup_global:
        dup_app = db.get(Application, dup_global.application_id)
        if dup_app and dup_app.owner_id == user.id:
            # Same institution's own prior application
            duplicate_info = {
                "scope": "own_prior_application",
                "matched_document_id": dup_global.id,
                "matched_filename": dup_global.original_name,
                "message": f"Exact duplicate of your previously uploaded document '{dup_global.original_name}' from Application #{dup_global.application_id}.",
            }
        else:
            # Cross-institution: STRICT PRIVACY - never expose other institution's filename or application ID!
            duplicate_info = {
                "scope": "cross_institution",
                "matched_document_id": None,
                "matched_filename": None,
                "message": "Identical file hash matches a document previously registered in the compliance system.",
            }

    stored = f"{uuid4().hex}{'.pdf' if mime == 'application/pdf' else '.img'}"
    path = UPLOAD_DIR / stored
    path.write_bytes(data)

    try:
        text_content = extract_text(path, mime)
        doc_type = classify_document(text_content, file.filename or "")
    except Exception:
        path.unlink(missing_ok=True)
        raise HTTPException(422, "Document processing failed: file may be corrupted or unreadable")

    doc = Document(
        application_id=app_id,
        original_name=(file.filename or "upload")[:255],
        stored_name=stored,
        mime_type=mime,
        sha256=digest,
        extracted_text=text_content,
        doc_type=doc_type,
        uploaded_by=user.id,
        upload_type="institution_document",
        submission_version=getattr(a, "submission_version", 1) or 1,
    )
    db.add(doc)
    db.flush()
    is_duplicate = bool(dup_in_app or dup_global)
    findings = store_findings(db, app_id, doc, is_duplicate, duplicate_info)
    log_event(
        db, user.id, "DOCUMENT_UPLOADED", "document", doc.id,
        {
            "application_id": app_id,
            "sha256": digest,
            "mime_type": mime,
            "duplicate_hash": is_duplicate,
            "bytes": len(data),
            "version": doc.submission_version,
        },
    )
    db.commit()
    return {
        "document_id": doc.id,
        "filename": doc.original_name,
        "document_type": doc.doc_type,
        "text_characters": len(text_content),
        "duplicate_hash_match": is_duplicate,
        "duplicate_info": duplicate_info,
        "verification_status": doc.verification_status,
        "findings_created": len(findings),
        "submission_version": doc.submission_version,
        "message": "Uploaded and screened. This does not authenticate the issuer or establish compliance.",
    }


# ---------------------------------------------------------------------------
# Document download/view endpoint (Document-Level Authorization)
# ---------------------------------------------------------------------------
@app.get("/api/applications/{app_id}/documents/{doc_id}/download")
def download_document(
    app_id: int,
    doc_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    a = app_or_404(db, app_id, user)
    doc = db.get(Document, doc_id)
    if not doc or doc.application_id != app_id:
        raise HTTPException(404, "Document not found")

    # Explicit access control for Officer Evidence vs Institutional Documents
    if doc.upload_type == "officer_evidence":
        if user.role == "institution":
            raise HTTPException(403, "Institutions are not authorized to download officer evidence attachments")
        if user.role == "officer" and a.assigned_officer_id != user.id and a.assigned_officer_id is not None:
            raise HTTPException(403, "Only the assigned compliance officer may download documents for this application")

    if doc.upload_type == "institution_document":
        if user.role == "institution" and a.owner_id != user.id:
            raise HTTPException(403, "You can only download documents from your own application")
        if user.role == "officer" and a.assigned_officer_id != user.id and a.assigned_officer_id is not None:
            raise HTTPException(403, "Only the assigned compliance officer may download documents for this application")

    path = UPLOAD_DIR / doc.stored_name
    if not path.exists():
        raise HTTPException(404, "File content not found on storage")

    log_event(db, user.id, "DOCUMENT_DOWNLOADED", "document", doc.id, {"application_id": app_id, "doc_type": doc.doc_type})
    db.commit()

    return FileResponse(
        path=str(path),
        media_type=doc.mime_type,
        filename=doc.original_name,
    )


# ---------------------------------------------------------------------------
# Document Removal & Replacement (Institution editable states only)
# ---------------------------------------------------------------------------
@app.delete("/api/applications/{app_id}/documents/{doc_id}")
def delete_document(
    app_id: int,
    doc_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles("institution")),
):
    a = db.get(Application, app_id)
    if not a or a.owner_id != user.id:
        raise HTTPException(404, "Application not found")

    if a.status not in ("DRAFT", "DEFICIENCY_RAISED"):
        raise HTTPException(
            409,
            f"Documents cannot be removed while application is in '{a.status}' status. Document removal is locked during formal review.",
        )

    doc = db.get(Document, doc_id)
    if not doc or doc.application_id != app_id:
        raise HTTPException(404, "Document not found")

    if doc.upload_type == "officer_evidence":
        raise HTTPException(403, "Officer evidence cannot be removed by institutions")

    stored_name = doc.stored_name
    doc_id = doc.id

    # Remove all findings associated with this document so obsolete findings do not linger
    db.execute(delete(Finding).where(Finding.document_id == doc.id))

    doc_meta = {
        "application_id": app_id,
        "document_id": doc.id,
        "filename": doc.original_name,
        "doc_type": doc.doc_type,
        "sha256": doc.sha256,
        "submission_version": doc.submission_version,
    }

    db.delete(doc)
    log_event(db, user.id, "DOCUMENT_REMOVED", "document", doc_id, doc_meta)
    db.commit()

    # Safely remove stored physical file only if unreferenced elsewhere
    safe_unlink_stored_file(db, stored_name, excluding_doc_ids=[doc_id])

    return {
        "message": f"Document '{doc_meta['filename']}' (#{doc_id}) removed successfully.",
        "document_id": doc_id,
        "application_id": app_id,
    }


@app.put("/api/applications/{app_id}/documents/{doc_id}")
@app.post("/api/applications/{app_id}/documents/{doc_id}/replace")
async def replace_document(
    app_id: int,
    doc_id: int,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(require_roles("institution")),
):
    a = db.get(Application, app_id)
    if not a or a.owner_id != user.id:
        raise HTTPException(404, "Application not found")

    if a.status not in ("DRAFT", "DEFICIENCY_RAISED"):
        raise HTTPException(
            409,
            f"Documents cannot be replaced while application is in '{a.status}' status. Document modification is locked during formal review.",
        )

    doc = db.get(Document, doc_id)
    if not doc or doc.application_id != app_id:
        raise HTTPException(404, "Document not found")

    if doc.upload_type == "officer_evidence":
        raise HTTPException(403, "Officer evidence cannot be replaced by institutions")

    mime = file.content_type or mimetypes.guess_type(file.filename or "")[0] or "application/octet-stream"
    if mime not in ALLOWED:
        raise HTTPException(415, "Only PDF, PNG, JPEG and WebP files are accepted")

    data = await file.read(MAX_BYTES + 1)
    if not data:
        raise HTTPException(400, "Empty file")
    if len(data) > MAX_BYTES:
        raise HTTPException(413, f"File exceeds {settings.max_upload_mb} MB limit")

    if mime == "application/pdf":
        if not data.startswith(b"%PDF"):
            raise HTTPException(400, "File does not look like a valid PDF")
        try:
            import fitz
            doc_test = fitz.open(stream=data, filetype="pdf")
            if doc_test.page_count < 1:
                doc_test.close()
                raise HTTPException(400, "PDF contains no pages")
            doc_test.close()
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(400, "Corrupted or invalid PDF file")
    elif mime.startswith("image/"):
        try:
            from PIL import Image
            import io as _io
            img = Image.open(_io.BytesIO(data))
            img.verify()
        except Exception:
            raise HTTPException(400, "Invalid or unsupported image file")

    digest = hashlib.sha256(data).hexdigest()

    # Scope-aware duplicate check excluding this document itself
    dup_in_app = db.scalar(
        select(Document).where(Document.sha256 == digest, Document.application_id == app_id, Document.id != doc.id)
    )
    dup_global = db.scalar(
        select(Document).where(Document.sha256 == digest, Document.application_id != app_id)
    )

    duplicate_info = None
    if dup_in_app:
        duplicate_info = {
            "scope": "same_application",
            "matched_document_id": dup_in_app.id,
            "matched_filename": dup_in_app.original_name,
            "message": f"Exact duplicate of '{dup_in_app.original_name}' (Document #{dup_in_app.id}) in this application.",
        }
    elif dup_global:
        dup_app = db.get(Application, dup_global.application_id)
        if dup_app and dup_app.owner_id == user.id:
            duplicate_info = {
                "scope": "own_prior_application",
                "matched_document_id": dup_global.id,
                "matched_filename": dup_global.original_name,
                "message": f"Exact duplicate of your previously uploaded document '{dup_global.original_name}' from Application #{dup_global.application_id}.",
            }
        else:
            duplicate_info = {
                "scope": "cross_institution",
                "matched_document_id": None,
                "matched_filename": None,
                "message": "Identical file hash matches a document previously registered in the compliance system.",
            }

    stored = f"{uuid4().hex}{'.pdf' if mime == 'application/pdf' else '.img'}"
    path = UPLOAD_DIR / stored
    path.write_bytes(data)

    try:
        text_content = extract_text(path, mime)
        doc_type = classify_document(text_content, file.filename or "")
    except Exception:
        path.unlink(missing_ok=True)
        raise HTTPException(422, "Document processing failed: replacement file may be corrupted or unreadable")

    # Remember old stored file info for safe post-commit cleanup
    old_stored = doc.stored_name
    old_doc_id = doc.id

    # Remove obsolete screening findings attached to this document
    db.execute(delete(Finding).where(Finding.document_id == doc.id))

    old_meta = {
        "old_name": doc.original_name,
        "old_sha256": doc.sha256,
        "old_type": doc.doc_type,
    }

    doc.original_name = (file.filename or "replacement")[:255]
    doc.stored_name = stored
    doc.mime_type = mime
    doc.sha256 = digest
    doc.extracted_text = text_content
    doc.doc_type = doc_type
    doc.verification_status = "PENDING_CLASSIFICATION"
    doc.created_at = datetime.now(timezone.utc)

    db.flush()

    is_duplicate = bool(dup_in_app or dup_global)
    findings = store_findings(db, app_id, doc, is_duplicate, duplicate_info)

    log_event(
        db, user.id, "DOCUMENT_REPLACED", "document", doc.id,
        {
            "application_id": app_id,
            "old": old_meta,
            "new_filename": doc.original_name,
            "new_sha256": digest,
            "duplicate_hash": is_duplicate,
            "findings_created": len(findings),
        },
    )
    db.commit()

    # Clean up old stored physical file safely only if unreferenced elsewhere
    safe_unlink_stored_file(db, old_stored, excluding_doc_ids=[old_doc_id])
    db.commit()

    return {
        "document_id": doc.id,
        "filename": doc.original_name,
        "document_type": doc.doc_type,
        "text_characters": len(text_content),
        "duplicate_hash_match": is_duplicate,
        "duplicate_info": duplicate_info,
        "verification_status": doc.verification_status,
        "findings_created": len(findings),
        "submission_version": doc.submission_version,
        "message": "Document replaced and re-screened successfully. Obsolete findings removed.",
    }


# ---------------------------------------------------------------------------
# Officer evidence attachment (separate from institution documents)
# ---------------------------------------------------------------------------
@app.post("/api/applications/{app_id}/officer-evidence")
async def upload_officer_evidence(
    app_id: int,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(require_roles("officer", "admin")),
):
    a = db.get(Application, app_id)
    if not a or not can_access(a, user):
        raise HTTPException(404, "Application not found")

    if a.status == "DRAFT":
        raise HTTPException(409, "Evidence cannot be attached to a draft application before institutional submission")

    # Enforce officer assignment: only assigned officer or admin can attach evidence
    if not can_modify_officer(a, user):
        raise HTTPException(403, "Only the assigned compliance officer can upload evidence for this application")

    mime = file.content_type or mimetypes.guess_type(file.filename or "")[0] or "application/octet-stream"
    if mime not in ALLOWED:
        raise HTTPException(415, "Only PDF, PNG, JPEG and WebP files are accepted")

    data = await file.read(MAX_BYTES + 1)
    if not data:
        raise HTTPException(400, "Empty file")
    if len(data) > MAX_BYTES:
        raise HTTPException(413, f"File exceeds {settings.max_upload_mb} MB limit")

    if mime == "application/pdf":
        if not data.startswith(b"%PDF"):
            raise HTTPException(400, "File does not look like a valid PDF")
        try:
            import fitz
            doc_test = fitz.open(stream=data, filetype="pdf")
            if doc_test.page_count < 1:
                doc_test.close()
                raise HTTPException(400, "PDF contains no pages")
            doc_test.close()
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(400, "Corrupted or invalid PDF file")
    elif mime.startswith("image/"):
        try:
            from PIL import Image
            import io as _io
            img = Image.open(_io.BytesIO(data))
            img.verify()
        except Exception:
            raise HTTPException(400, "Invalid or unsupported image file")

    digest = hashlib.sha256(data).hexdigest()
    stored = f"{uuid4().hex}{'.pdf' if mime == 'application/pdf' else '.img'}"
    path = UPLOAD_DIR / stored
    path.write_bytes(data)

    doc = Document(
        application_id=app_id,
        original_name=(file.filename or "evidence")[:255],
        stored_name=stored,
        mime_type=mime,
        sha256=digest,
        extracted_text="",
        doc_type="Officer Evidence",
        uploaded_by=user.id,
        upload_type="officer_evidence",
        verification_status="N/A",
        submission_version=getattr(a, "submission_version", 1) or 1,
    )
    db.add(doc)
    db.flush()
    log_event(
        db, user.id, "OFFICER_EVIDENCE_UPLOADED", "document", doc.id,
        {"application_id": app_id, "sha256": digest, "mime_type": mime, "bytes": len(data)},
    )
    db.commit()
    return {
        "document_id": doc.id,
        "filename": doc.original_name,
        "upload_type": "officer_evidence",
        "submission_version": doc.submission_version,
        "message": "Officer evidence attached. Labeled separately from institution documents.",
    }


# ---------------------------------------------------------------------------
# Status transitions
# ---------------------------------------------------------------------------
TRANSITION_MAP = {
    "DRAFT": {"UNDER_REVIEW"},
    "UNDER_REVIEW": {"DEFICIENCY_RAISED", "OFFICER_RECOMMENDATION_RECORDED", "CLOSED"},
    "DEFICIENCY_RAISED": {"RECTIFICATION_SUBMITTED", "CLOSED"},
    "RECTIFICATION_SUBMITTED": {"UNDER_REVIEW", "DEFICIENCY_RAISED", "OFFICER_RECOMMENDATION_RECORDED"},
    "OFFICER_RECOMMENDATION_RECORDED": {"CLOSED"},
    "CLOSED": set(),
}

STATUS_ROLE_PERMISSIONS = {
    "UNDER_REVIEW": ("institution", "officer", "admin"),
    "DEFICIENCY_RAISED": ("officer", "admin"),
    "RECTIFICATION_SUBMITTED": ("institution",),
    "OFFICER_RECOMMENDATION_RECORDED": ("officer", "admin"),
    "CLOSED": ("officer", "admin"),
}


@app.patch("/api/applications/{app_id}/status")
def update_status(
    app_id: int,
    payload: StatusUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    a = db.get(Application, app_id)
    if not a or not can_access(a, user):
        raise HTTPException(404, "Application not found")

    allowed_roles = STATUS_ROLE_PERMISSIONS.get(payload.status, ())
    if user.role not in allowed_roles:
        raise HTTPException(403, f"Role '{user.role}' cannot transition to '{payload.status}'")

    if a.status == "DRAFT":
        if user.role != "institution" or a.owner_id != user.id:
            raise HTTPException(403, "Officers and administrators cannot transition or submit a draft on behalf of an institution. Only the institution owner may submit their draft.")
        if payload.status != "UNDER_REVIEW":
            raise HTTPException(409, "Draft applications can only transition to UNDER_REVIEW upon institutional submission.")

    if user.role == "institution":
        if a.owner_id != user.id:
            raise HTTPException(403, "You can only update your own applications")
        # Institution can only transition from DRAFT to UNDER_REVIEW, or DEFICIENCY_RAISED to RECTIFICATION_SUBMITTED
        if payload.status == "UNDER_REVIEW" and a.status != "DRAFT":
            raise HTTPException(403, "Institution can only transition from DRAFT to UNDER_REVIEW")
    elif user.role == "officer":
        # Enforce officer assignment
        if not can_modify_officer(a, user):
            raise HTTPException(403, "Only the assigned compliance officer can update the status of this application")

    if payload.status not in TRANSITION_MAP.get(a.status, set()):
        raise HTTPException(409, f"Invalid transition: {a.status} -> {payload.status}")

    old = a.status
    a.status = payload.status

    # When institution submits rectification, increment submission version
    if payload.status == "RECTIFICATION_SUBMITTED":
        a.submission_version = (getattr(a, "submission_version", 1) or 1) + 1

    log_event(
        db, user.id, "APPLICATION_STATUS_CHANGED", "application", a.id,
        {"from": old, "to": a.status, "submission_version": a.submission_version},
    )
    db.commit()
    return {
        "id": a.id,
        "previous_status": old,
        "status": a.status,
        "submission_version": a.submission_version,
        "final_approval_granted": False,
    }


# ---------------------------------------------------------------------------
# Officer reviews
# ---------------------------------------------------------------------------
@app.post("/api/applications/{app_id}/reviews")
def create_review(
    app_id: int,
    payload: OfficerReviewIn,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles("officer", "admin")),
):
    a = db.get(Application, app_id)
    if not a or not can_access(a, user):
        raise HTTPException(404, "Application not found")

    if a.status == "DRAFT":
        raise HTTPException(409, "Draft applications cannot be reviewed before institutional submission")

    # Enforce officer assignment
    if not can_modify_officer(a, user):
        raise HTTPException(403, "Only the assigned compliance officer can record reviews for this application")

    review = OfficerReview(
        application_id=app_id,
        officer_id=user.id,
        action=payload.action,
        notes=payload.notes,
        finding_references=payload.finding_references or [],
        correction_instructions=payload.correction_instructions or "",
    )
    db.add(review)
    db.flush()
    log_event(
        db, user.id, "OFFICER_REVIEW_RECORDED", "officer_review", review.id,
        {
            "application_id": app_id,
            "action": payload.action,
            "finding_references": review.finding_references,
            "has_correction_instructions": bool(review.correction_instructions),
        },
    )
    db.commit()
    db.refresh(review)
    return {
        "id": review.id,
        "application_id": app_id,
        "officer_id": user.id,
        "action": review.action,
        "notes": review.notes,
        "finding_references": review.finding_references,
        "correction_instructions": review.correction_instructions,
        "created_at": review.created_at.isoformat() if review.created_at else None,
    }


@app.get("/api/applications/{app_id}/reviews")
def list_reviews(
    app_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    app_or_404(db, app_id, user)
    reviews = db.scalars(
        select(OfficerReview).where(OfficerReview.application_id == app_id).order_by(OfficerReview.id.desc())
    ).all()
    return [
        {
            "id": r.id,
            "officer_id": r.officer_id,
            "action": r.action,
            "notes": r.notes,
            "finding_references": getattr(r, "finding_references", []) or [],
            "correction_instructions": getattr(r, "correction_instructions", "") or "",
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in reviews
    ]


# ---------------------------------------------------------------------------
# Deficiency memo
# ---------------------------------------------------------------------------
@app.post("/api/applications/{app_id}/memo")
def memo(
    app_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles("officer", "admin")),
):
    a = db.get(Application, app_id)
    if not a or not can_access(a, user):
        raise HTTPException(404, "Application not found")
    if a.status == "DRAFT":
        raise HTTPException(409, "Deficiency memo cannot be generated for an unsubmitted draft application")
    if not can_modify_officer(a, user):
        raise HTTPException(403, "Only the assigned compliance officer or authorized administrator can generate memos for this application")

    assigned_officer = db.get(User, a.assigned_officer_id) if a.assigned_officer_id else None
    memo_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    app_meta = {
        "id": a.id,
        "reference": f"AICTE-APP-{a.id:06d}",
        "institution_name": a.institution_name,
        "institution_code": a.institution_code or "Not provided",
        "application_type": a.application_type,
        "academic_year": a.academic_year,
        "programme": a.programme or "Not specified",
        "current_intake": a.current_intake if a.current_intake is not None else "Not provided",
        "proposed_intake": a.proposed_intake if a.proposed_intake is not None else "Not provided",
        "status": a.status,
        "submission_version": getattr(a, "submission_version", 1) or 1,
        "assigned_officer_name": assigned_officer.name if assigned_officer else "Unassigned (Triage Queue)",
        "assigned_officer_id": a.assigned_officer_id,
        "memo_date": memo_date,
    }

    finds = db.scalars(select(Finding).where(Finding.application_id == app_id)).all()
    payload = [
        {
            "rule_id": f.rule_id,
            "severity": f.severity,
            "result": f.result,
            "message": f.message,
            "source_reference": f.source_reference,
            "evidence": f.evidence,
            "document_id": f.document_id,
        }
        for f in finds
    ]
    memo_result = gemini_memo(app_meta, payload)
    is_fallback = memo_result.get("is_fallback", False)
    fallback_reason = memo_result.get("fallback_reason")
    model_used = memo_result.get("model_used")
    if is_fallback:
        logger.info("Application #%d memo generated via deterministic fallback: %s", a.id, fallback_reason)
    else:
        logger.info("Application #%d memo generated via Gemini (%s)", a.id, model_used or "gemini")

    log_event(
        db, user.id, "MEMO_GENERATED", "application", a.id,
        {
            "provider": "gemini" if memo_result.get("ai_assisted") else "deterministic_fallback",
            "is_fallback": is_fallback,
            "fallback_reason": fallback_reason,
            "model_used": model_used,
        },
    )
    db.commit()
    return memo_result


# ---------------------------------------------------------------------------
# Officer summary + audit
# ---------------------------------------------------------------------------
@app.get("/api/officer/summary")
def officer_summary(
    db: Session = Depends(get_db),
    user: User = Depends(require_roles("officer", "admin")),
):
    if user.role == "officer":
        apps = db.scalars(
            select(Application).where(
                Application.status != "DRAFT",
                (Application.assigned_officer_id == user.id) | (Application.assigned_officer_id.is_(None)),
            ).order_by(Application.updated_at.desc())
        ).all()
    else:
        apps = db.scalars(
            select(Application).where(Application.status != "DRAFT").order_by(Application.updated_at.desc())
        ).all()

    events = db.scalars(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(20)).all()
    return {
        "total_applications": len(apps),
        "by_status": {
            s: sum(1 for a in apps if a.status == s)
            for s in sorted({a.status for a in apps})
        },
        "recent_audit": [
            {
                "id": e.id,
                "action": e.action,
                "entity_type": e.entity_type,
                "entity_id": e.entity_id,
                "created_at": e.created_at.isoformat() if e.created_at else None,
                "event_hash": e.event_hash[:16] + "…",
            }
            for e in events
        ],
    }


@app.get("/api/audit/events")
def list_audit_events(
    limit: int = Query(default=50, ge=1, le=500),
    db: Session = Depends(get_db),
    user: User = Depends(require_roles("admin")),
):
    rows = db.scalars(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(limit)).all()
    return [
        {
            "id": e.id,
            "actor_id": e.actor_id,
            "action": e.action,
            "entity_type": e.entity_type,
            "entity_id": e.entity_id,
            "created_at": e.created_at.isoformat() if e.created_at else None,
            "event_hash": e.event_hash[:16] + "…",
        }
        for e in rows
    ]


@app.get("/api/audit/verify")
def verify_audit(
    db: Session = Depends(get_db),
    user: User = Depends(require_roles("admin")),
):
    rows = db.scalars(select(AuditEvent).order_by(AuditEvent.id.asc())).all()
    previous = "0" * 64
    broken = []
    for e in rows:
        material = f"{previous}|{e.actor_id}|{e.action}|{e.entity_type}|{e.entity_id}|{e.payload_json}"
        expected = hashlib.sha256(material.encode()).hexdigest()
        if e.previous_hash != previous or e.event_hash != expected:
            broken.append(e.id)
        previous = e.event_hash
    return {
        "valid": not broken,
        "events_checked": len(rows),
        "broken_event_ids": broken,
        "note": "Hash-chain verification is tamper-evident within this database; use external immutable storage for stronger guarantees.",
    }
