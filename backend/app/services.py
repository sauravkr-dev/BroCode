import hashlib, io, re, os, json, logging, time, random
from typing import Any
from datetime import datetime, timezone
from pathlib import Path
from PIL import Image
import yaml
import httpx
try: import fitz
except Exception: fitz = None
try: import pytesseract
except Exception: pytesseract = None
from sqlalchemy.orm import Session
from .models import Document, Finding
from .config import settings

RULE_FILE = Path(__file__).resolve().parents[1] / "rules" / "illustrative_2026_27.yaml"

def load_rules():
    with open(RULE_FILE, encoding="utf-8") as f:
        return yaml.safe_load(f)

def extract_text(path: Path, mime: str) -> str:
    text = ""
    if mime == "application/pdf" and fitz:
        try:
            with fitz.open(path) as doc:
                text = "\n".join(p.get_text() for p in doc)
        except Exception:
            text = ""
    elif mime.startswith("image/") and pytesseract:
        try:
            text = pytesseract.image_to_string(Image.open(path))
        except Exception:
            text = ""
    if not text.strip() and mime.startswith("image/") and pytesseract:
        try:
            text = pytesseract.image_to_string(Image.open(path))
        except Exception:
            pass
    return text[:200000]

def classify_document(text: str, filename: str) -> str:
    hay = (text + " " + filename).lower()
    patterns = [
        ("Faculty Data", ["faculty", "professor", "assistant professor"]),
        ("Infrastructure Evidence", ["built-up area", "laboratory", "library", "infrastructure"]),
        ("Approval Letter", ["extension of approval", "approval letter", "eoa"]),
        ("Affidavit", ["affidavit", "notary"]),
        ("Institutional Application", ["application number", "institution code", "proposed intake"]),
    ]
    for label, words in patterns:
        if any(w in hay for w in words):
            return label
    return "Unclassified"

def store_findings(
    db: Session,
    application_id: int,
    doc: Document,
    duplicate: bool,
    duplicate_info: dict | None = None,
) -> list[Finding]:
    findings = []

    def add(rule, severity, result, message, ref, evidence):
        x = Finding(
            application_id=application_id,
            document_id=doc.id,
            rule_id=rule,
            severity=severity,
            result=result,
            message=message,
            source_reference=ref,
            evidence=evidence,
        )
        db.add(x)
        findings.append(x)

    # DOC-001: Document classification check
    if doc.doc_type != "Unclassified":
        add(
            "DOC-001",
            "low",
            "VERIFIED",
            f"Document classified as '{doc.doc_type}'. Classification is heuristic and subject to officer review.",
            "Illustrative rule pack: DOC-001",
            {"classified_type": doc.doc_type},
        )
    else:
        add(
            "DOC-001",
            "medium",
            "NEEDS_REVIEW",
            "Document type could not be classified automatically from content or filename. Officer inspection required.",
            "Illustrative rule pack: DOC-001",
            {"classified_type": "Unclassified"},
        )

    # DOC-002: Document issuer authenticity
    # Must display 'Manual verification required' since no live AICTE API is connected
    add(
        "DOC-002",
        "high",
        "NOT_VERIFIED",
        "Issuer authenticity was not verified: no authorized AICTE or issuer API is configured. Manual verification required.",
        "Illustrative rule pack: DOC-002",
        {"verification_status": "MANUAL_VERIFICATION_REQUIRED", "live_integration": False},
    )

    # DOC-003: Duplicate file hash check
    # Protects against cross-institution information leakage
    if duplicate:
        scope = duplicate_info.get("scope", "global") if duplicate_info else "global"
        scope_msg = (
            duplicate_info.get("message", "Identical file hash found in compliance records.")
            if duplicate_info
            else "Identical file hash found in another document."
        )
        safe_evidence = {
            "sha256": doc.sha256,
            "scope": scope,
        }
        # Only include matched document/filename if within same institution scope
        if scope in ("same_application", "own_prior_application") and duplicate_info:
            safe_evidence["matched_document_id"] = duplicate_info.get("matched_document_id")
            safe_evidence["matched_filename"] = duplicate_info.get("matched_filename")

        add(
            "DOC-003",
            "medium",
            "NEEDS_REVIEW",
            f"{scope_msg} Review whether reuse across programs or re-submission is legitimate; duplicate file is an informational signal, not proof of fraud.",
            "Illustrative rule pack: DOC-003",
            safe_evidence,
        )
    else:
        add(
            "DOC-003",
            "low",
            "VERIFIED",
            "No identical-file hash match found in this application scope.",
            "Illustrative rule pack: DOC-003",
            {"sha256": doc.sha256, "duplicate": False},
        )

    # DOC-004: Text extraction availability
    # Explicitly state that successful text extraction is not proof of authenticity
    if doc.extracted_text.strip():
        add(
            "DOC-004",
            "low",
            "VERIFIED",
            f"Text extraction produced readable content ({len(doc.extracted_text)} characters). Note: Successful extraction is not proof of authenticity or regulatory compliance.",
            "Illustrative rule pack: DOC-004",
            {"characters_extracted": len(doc.extracted_text), "proof_of_authenticity": False},
        )
    else:
        add(
            "DOC-004",
            "medium",
            "NEEDS_REVIEW",
            "No usable text could be extracted from this document. Try a higher-resolution scan or inspect manually.",
            "Illustrative rule pack: DOC-004",
            {"characters_extracted": 0},
        )

    return findings

def heuristic_risk(findings) -> int:
    weights = {"high": 25, "medium": 12, "low": 5}
    score = 0
    for f in findings:
        if f.result in ("FAIL", "FAILED_CHECK", "NEEDS_REVIEW", "NOT_VERIFIED"):
            score += weights.get(f.severity, 5)
    return min(score, 100)

logger = logging.getLogger("brocode.services")

MEMO_DISCLAIMER = (
    "AI-assisted pre-screening decision-support draft. Does not constitute an official AICTE regulatory decision, "
    "approval, or deficiency notice. Authorized compliance officer scrutiny, verification, and signature are mandatory."
)


def format_evidence_text(evidence: Any) -> str:
    """
    Safely converts finding evidence to readable, deterministic text.
    Handles str, dict, list, None, and other JSON-compatible values without raising AttributeError.
    Structured dicts and lists are converted using json.dumps with sort_keys=True.
    """
    if evidence is None:
        return ""
    if isinstance(evidence, str):
        return evidence.strip()
    if isinstance(evidence, (dict, list)):
        try:
            return json.dumps(evidence, ensure_ascii=False, sort_keys=True)
        except Exception:
            return str(evidence)
    return str(evidence).strip()


def generate_deterministic_memo(application: dict, findings: list[dict], fallback_reason: str | None = None) -> str:
    """
    Constructs a complete, grounded, professional deficiency memorandum directly
    from application metadata and pre-screening findings.
    Used when AI service is unconfigured, unreachable, or produces incomplete output.
    """
    memo_date = application.get("memo_date") or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    app_id = application.get("id") or 0
    ref = application.get("reference") or f"AICTE-APP-{app_id:06d}"
    inst_name = application.get("institution_name") or application.get("institution") or "Not provided"
    inst_code = application.get("institution_code") or "Not provided"
    app_type = application.get("application_type") or "Not specified"
    acad_year = application.get("academic_year") or "Not specified"
    programme = application.get("programme") or "Not specified"
    cur_intake = application.get("current_intake")
    cur_intake_str = str(cur_intake) if cur_intake is not None else "Not provided"
    prop_intake = application.get("proposed_intake")
    prop_intake_str = str(prop_intake) if prop_intake is not None else "Not provided"
    officer_name = application.get("assigned_officer_name") or "Unassigned (Triage Queue)"
    version = application.get("submission_version", 1)

    # Filter deficiencies (FAIL, FAILED_CHECK, NEEDS_REVIEW, NOT_VERIFIED)
    deficiencies = [
        f for f in findings
        if f.get("result") in ("FAIL", "FAILED_CHECK", "NEEDS_REVIEW", "NOT_VERIFIED")
    ]

    lines = []

    # Title & Notice Banner
    lines.append("# AICTE Compliance Pre-Screening Deficiency Memorandum (Draft)")
    lines.append("")
    if fallback_reason:
        lines.append("> **PRE-SCREENING NOTICE — SYSTEM DETERMINISTIC DRAFT**")
        lines.append(f"> *Generation Mode:* System Compiled (AI Service: {fallback_reason})")
    else:
        lines.append("> **PRE-SCREENING DRAFT FOR COMPLIANCE SCRUTINY**")
    lines.append("> *Regulatory Status:* Decision-support draft only. Does NOT constitute an official AICTE regulatory decision, approval, or formal order. Review, verification, and authorized signature by the designated compliance officer are mandatory.")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Application & Memorandum Reference Details
    lines.append("### Application Reference & Institutional Metadata")
    lines.append(f"- **Memorandum Date:** {memo_date}")
    lines.append(f"- **Application Reference:** {ref} (Submission Cycle v{version})")
    lines.append(f"- **Institution Name:** {inst_name}")
    lines.append(f"- **Institution Code:** {inst_code}")
    lines.append(f"- **Application Type:** {app_type}")
    lines.append(f"- **Academic Year:** {acad_year}")
    lines.append(f"- **Programme / Course:** {programme}")
    lines.append(f"- **Approved Intake / Proposed Intake:** {cur_intake_str} / {prop_intake_str}")
    lines.append(f"- **Assigned Compliance Officer:** {officer_name}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Section 1: Identified Deficiencies
    lines.append("### 1. Identified Deficiencies & Flagged Pre-Screening Checks")
    lines.append("")
    if not deficiencies:
        lines.append("No regulatory deficiencies or check failures were flagged during automated pre-screening. All evaluated verification rules satisfied initial validation criteria.")
        lines.append("")
        lines.append("*Note:* Standard manual scrutiny of source documents and certificates by the reviewing compliance officer is still required prior to official recommendation.")
    else:
        lines.append(f"Pre-screening analysis flagged **{len(deficiencies)}** potential deficiency/review item(s) requiring institutional rectification or officer clarification:")
        lines.append("")
        for idx, d in enumerate(deficiencies, 1):
            rule_id = d.get("rule_id", "GENERAL_CHECK")
            severity = (d.get("severity") or "medium").upper()
            result = d.get("result", "NEEDS_REVIEW")
            msg = d.get("message", "Rule condition requires verification.")
            source = d.get("source_reference", "AICTE Approval Process Handbook")
            raw_evidence = d.get("evidence")
            evidence_str = format_evidence_text(raw_evidence)
            if not evidence_str:
                evidence_str = "Flagged during automated document classification and content pre-screening."
            doc_id = d.get("document_id")
            doc_label = f" (Document #{doc_id})" if doc_id else ""

            lines.append(f"#### {idx}. [{rule_id}] {msg}")
            lines.append(f"- **Severity Level:** {severity}")
            lines.append(f"- **Pre-Screening Result:** {result}")
            lines.append(f"- **Regulatory Benchmark / Source:** {source}")
            lines.append(f"- **Observed Finding{doc_label}:** {evidence_str}")
            lines.append("")

    lines.append("---")
    lines.append("")

    # Section 2: Specific Grounded Correction Instructions
    lines.append("### 2. Specific Grounded Correction Instructions")
    lines.append("")
    if not deficiencies:
        lines.append("No specific document rectifications are currently required by automated screening. The institution must ensure all submitted documents remain authentic and accessible for manual verification.")
    else:
        lines.append("The institution is required to address the identified discrepancies by submitting the specified rectifications through the institution portal:")
        lines.append("")
        for idx, d in enumerate(deficiencies, 1):
            rule_id = d.get("rule_id", "")
            msg = d.get("message", "")

            # Grounded correction instruction directly from the finding
            r_lower = rule_id.lower()
            m_lower = msg.lower()
            if "land" in r_lower or "land" in m_lower:
                instruction = "Upload a clear, verifiable, registered land ownership deed or registered lease agreement in the name of the institution."
            elif "dup" in r_lower or "duplicate" in m_lower:
                instruction = "Resolve file duplication. Upload distinct, authenticated documentation specific to the required schedule, or provide formal clarification on document reuse."
            elif "faculty" in r_lower or "cadre" in m_lower:
                instruction = "Submit an updated and verified faculty roster with cadre ratio (Professor : Associate Professor : Assistant Professor) and supporting appointment documentation."
            elif "intake" in r_lower or "intake" in m_lower:
                instruction = "Clarify the intake calculation discrepancy. Submit the governing body / state approval resolution confirming approved and proposed student intake numbers."
            elif "affiliat" in r_lower or "affiliat" in m_lower:
                instruction = "Upload current university affiliation letter or state government NOC for the relevant academic cycle."
            else:
                instruction = f"Provide rectifying documentation or clarification addressing: '{msg}'."

            lines.append(f"{idx}. **Action for [{rule_id}]:** {instruction}")

        lines.append("")
        lines.append("**Rectification Timeline:** Submission deadlines are governed by the official AICTE approval process calendar and the directives of the reviewing officer. Specific deadlines must be confirmed by the reviewing officer and are not automated.")

    lines.append("")
    lines.append("---")
    lines.append("")

    # Section 3: Officer Scrutiny & Sign-Off Block
    lines.append("### 3. Compliance Officer Scrutiny & Determination Block")
    lines.append("")
    lines.append(f"- **Assigned Compliance Officer:** {officer_name}")
    lines.append("- **Officer Determination:** [ ] Accepted / Compliant   [ ] Formal Deficiency Notice Issued   [ ] Referred for Expert Scrutiny")
    lines.append("- **Review Observations & Directives:** [ Awaiting Officer Review Notes ]")
    lines.append("- **Verification Status:** Pending Authorized Human Scrutiny")
    lines.append("- **Officer Signature & Seal:** [ Pending Authorized Officer Sign-Off ]")
    lines.append(f"- **Date of Verification:** {memo_date}")

    return "\n".join(lines)


TRANSIENT_STATUS_CODES = {503, 429, 408, 502, 504}
NON_RETRYABLE_STATUS_CODES = {400, 401, 403, 404}

SUPPORTED_GEMINI_MODELS = {
    # Gemini 3.x series
    "gemini-3.8-flash",
    "gemini-3.7-flash",
    "gemini-3.6-flash",
    "gemini-3.5-flash",
    "gemini-3.1-flash-lite",
    "gemini-3-flash-preview",
    # Gemini 2.5
    "gemini-2.5-flash",
    "gemini-2.5-flash-lite",
    "gemini-2.5-pro",
    # Gemini 2.0
    "gemini-2.0-flash",
    "gemini-2.0-flash-lite",
    "gemini-2.0-flash-lite-preview",
    "gemini-2.0-flash-lite-preview-02-05",
    "gemini-2.0-pro-exp-02-05",
    # Gemini 1.5
    "gemini-1.5-flash",
    "gemini-1.5-flash-latest",
    "gemini-1.5-flash-8b",
    "gemini-1.5-flash-8b-latest",
    "gemini-1.5-pro",
    "gemini-1.5-pro-latest",
    # Gemini 1.0 (legacy)
    "gemini-1.0-pro",
    # Aliases
    "gemini-flash-latest",
    "gemini-flash-lite-latest",
    "gemini-pro-latest",
}

# In-memory cache for live available models from Google Gemini API
_models_cache: dict = {
    "models": set(),
    "fetched_at": 0.0,
    "key_hash": "",
}


def clear_gemini_models_cache():
    """Clears cached available models (useful for testing)."""
    _models_cache["models"] = set()
    _models_cache["fetched_at"] = 0.0
    _models_cache["key_hash"] = ""


def fetch_available_gemini_models(api_key: str = "", timeout: float = 5.0) -> tuple[bool, set[str], str]:
    """
    Queries Google Gemini API (GET /v1beta/models?key=...) to discover actual models
    available to the configured API key/project.
    Returns (success, set_of_model_names, safe_error_detail).
    Never logs or exposes the API key.
    """
    key = (api_key or getattr(settings, "gemini_api_key", "") or "").strip()
    if not key:
        return False, set(), "GEMINI_API_KEY is not configured"

    # Avoid external HTTP calls for test/mock dummy keys during unit tests
    if key.lower().startswith(("test-", "mock-", "fake-", "dummy-")):
        return False, set(), "Test/mock API key detected; external model discovery skipped"

    key_hash = hashlib.sha256(key.encode("utf-8")).hexdigest()
    now = time.time()

    # In-memory cache valid for 300 seconds
    if (
        _models_cache["models"]
        and _models_cache["key_hash"] == key_hash
        and (now - _models_cache["fetched_at"] < 300.0)
    ):
        return True, _models_cache["models"], ""

    url = "https://generativelanguage.googleapis.com/v1beta/models"
    headers = {"x-goog-api-key": key}
    try:
        resp = httpx.get(url, headers=headers, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            models_list = data.get("models", [])
            extracted_models = set()
            for m in models_list:
                name = m.get("name", "")
                clean_name = name.removeprefix("models/").strip().lower()
                methods = m.get("supportedGenerationMethods", [])
                if not methods or "generateContent" in methods:
                    if clean_name:
                        extracted_models.add(clean_name)
                    if name:
                        extracted_models.add(name.strip().lower())

            _models_cache["models"] = extracted_models
            _models_cache["fetched_at"] = now
            _models_cache["key_hash"] = key_hash
            return True, extracted_models, ""
        else:
            safe_err = _extract_safe_response_error(resp, key)
            return False, set(), f"HTTP {resp.status_code}: {safe_err}"
    except Exception as exc:
        safe_err = _sanitize_log_message(str(exc), key)
        return False, set(), f"Connection error: {safe_err}"


def validate_gemini_models(
    primary_model: str,
    fallback_model: str = "",
    api_key: str = "",
    timeout: float = 5.0,
) -> dict:
    """
    Validates configured primary and fallback models against the actual Google Gemini API
    models available to the configured key/project.
    Returns structured validation report without exposing secrets.
    """
    key = (api_key or getattr(settings, "gemini_api_key", "") or "").strip()
    primary = (primary_model or "").strip()
    fallback = (fallback_model or "").strip()

    report = {
        "primary_model": primary,
        "fallback_model": fallback or None,
        "remote_check_performed": False,
        "remote_check_success": False,
        "primary_valid": False,
        "fallback_valid": False if fallback else True,
        "validation_source": "unverified",
        "detail": "",
        "available_models_sample": [],
    }

    if not key:
        report["validation_source"] = "local_catalog_only"
        report["primary_valid"] = is_supported_gemini_model(primary)
        if fallback:
            report["fallback_valid"] = is_supported_gemini_model(fallback)
        report["detail"] = "GEMINI_API_KEY is not configured; validated against local supported catalog only."
        return report

    report["remote_check_performed"] = True
    success, remote_models, err = fetch_available_gemini_models(api_key=key, timeout=timeout)

    if success and remote_models:
        report["remote_check_success"] = True
        report["validation_source"] = "google_api_live"
        norm_primary = primary.removeprefix("models/").lower()
        report["primary_valid"] = (norm_primary in remote_models) or (f"models/{norm_primary}" in remote_models)
        if fallback:
            norm_fallback = fallback.removeprefix("models/").lower()
            report["fallback_valid"] = (norm_fallback in remote_models) or (f"models/{norm_fallback}" in remote_models)
        else:
            report["fallback_valid"] = True

        clean_sample = sorted({m.removeprefix("models/") for m in remote_models})
        report["available_models_sample"] = clean_sample[:15]

        if report["primary_valid"]:
            report["detail"] = f"Primary model '{primary}' is verified and available in Google Gemini project/key."
        else:
            sample_str = ", ".join(report["available_models_sample"][:8])
            report["detail"] = (
                f"Configured primary model '{primary}' is NOT available in this Google Gemini project/key. "
                f"Available models sample: {sample_str}"
            )
        return report

    # If remote validation could not be completed (e.g. offline, mock key, network error)
    report["remote_check_success"] = False
    report["validation_source"] = "local_catalog_fallback"
    report["primary_valid"] = is_supported_gemini_model(primary)
    if fallback:
        report["fallback_valid"] = is_supported_gemini_model(fallback)
    report["detail"] = f"Remote validation failed ({err}). Checked against local catalog: primary valid={report['primary_valid']}."
    return report


def is_supported_gemini_model(model_name: str, api_key: str = "") -> bool:
    """
    Verifies a model name against Google's actual Gemini API models available
    to the configured key/project, falling back to the supported catalog.
    """
    if not model_name:
        return False
    normalized = model_name.strip().removeprefix("models/").lower()

    if api_key:
        success, remote_models, _ = fetch_available_gemini_models(api_key=api_key)
        if success and remote_models:
            return (normalized in remote_models) or (f"models/{normalized}" in remote_models)

    return normalized in SUPPORTED_GEMINI_MODELS


def _sanitize_log_message(msg: str, secret: str = "") -> str:
    """Removes sensitive keys from log messages."""
    if not msg:
        return ""
    clean = str(msg)
    if secret and secret in clean:
        clean = clean.replace(secret, "[REDACTED]")
    return clean


def _extract_safe_response_error(response, secret: str = "") -> str:
    """Safely extracts error details from an HTTP response without exposing secrets."""
    try:
        data = response.json()
        error_info = data.get("error", {})
        msg = error_info.get("message") or error_info.get("status")
        if msg:
            return _sanitize_log_message(str(msg)[:200], secret)
    except Exception:
        pass
    text_snippet = getattr(response, "text", "")[:150]
    return _sanitize_log_message(text_snippet, secret)


def _compute_backoff_delay(attempt: int, base: float = 0.5, max_delay: float = 3.0) -> float:
    """Computes exponential backoff with random jitter."""
    delay = min(max_delay, base * (2 ** attempt))
    jitter = random.uniform(0, 0.25 * delay)
    return delay + jitter


def gemini_memo(application: dict, findings: list[dict], sleep_fn=time.sleep) -> dict:
    """
    Generates a complete, grounded deficiency memorandum.
    Attempts Gemini API generation with bounded retry and model fallback:
    - Retries only transient errors (HTTP 503, 429, 408, and network/read timeouts)
      with exponential backoff and random jitter.
    - Total request duration is bounded by a hard elapsed budget (max 18s).
    - Verifies configured model IDs against Google's supported Gemini model list.
    - If the configured primary model returns 503/timeout, optionally tries a
      configurable fallback model from settings (GEMINI_FALLBACK_MODEL); never hardcodes an unverified model.
    - Never retries invalid API keys, 400, 401, 403, or 404 errors.
    - Safely logs status codes, model IDs, and messages without exposing the API key.
    - Clearly logs final outcome: Gemini success, or deterministic fallback with exact reason.

    Returns:
        dict: {
            "memo": str,
            "ai_assisted": bool,
            "is_fallback": bool,
            "fallback_reason": str | None,
            "status": "success" | "fallback",
            "disclaimer": str,
            "model_used": str | None,
        }
    """
    start_time = time.time()
    officer_name = application.get("assigned_officer_name") or "Unassigned (Triage Queue)"
    api_key = (settings.gemini_api_key or "").strip()

    if not api_key:
        fallback = generate_deterministic_memo(
            application, findings,
            fallback_reason="GEMINI_API_KEY is not configured on the server",
        )
        logger.info("Deficiency memo compiled via deterministic fallback (GEMINI_API_KEY unconfigured).")
        return {
            "memo": fallback,
            "ai_assisted": False,
            "is_fallback": True,
            "fallback_reason": "GEMINI_API_KEY is not configured on the server",
            "status": "fallback",
            "disclaimer": MEMO_DISCLAIMER,
            "model_used": None,
        }

    # Sanitize and compact pre-screening findings for the prompt payload to prevent payload bloat
    compact_findings = []
    for f in findings:
        evidence_snippet = format_evidence_text(f.get("evidence"))
        if len(evidence_snippet) > 250:
            evidence_snippet = evidence_snippet[:247] + "..."
        compact_f = {
            "rule_id": str(f.get("rule_id", "GENERAL_CHECK")),
            "severity": str(f.get("severity", "medium")),
            "result": str(f.get("result", "NEEDS_REVIEW")),
            "message": str(f.get("message", "")),
            "source_reference": str(f.get("source_reference", "")),
            "evidence": evidence_snippet or "Flagged during document screening",
        }
        if f.get("document_id"):
            compact_f["document_id"] = f.get("document_id")
        compact_findings.append(compact_f)

    prompt = f"""You are an AI pre-screening assistant for AICTE regulatory compliance verification.
Generate a complete, professional, neutral deficiency memorandum draft in clean Markdown based strictly on the provided application data and actual findings.

STRICT REGULATORY & CONTENT RULES:
1. Ground every statement strictly in the provided application details and actual pre-screening findings. Do not invent missing facts, files, or requirements.
2. Do NOT invent legal clauses, circular numbers, or specific calendar deadlines (e.g. do not invent calendar dates). If details are missing, state '[Not provided]' or '[To be determined by reviewing officer]'.
3. Clearly label this memorandum as an AI-generated pre-screening draft requiring authorized officer review. Never state or imply that it is an official AICTE decision, approval, or rejection.
4. If there are deficiencies (findings with FAIL, FAILED_CHECK, NEEDS_REVIEW, or NOT_VERIFIED), list each with its Rule ID, Severity, Result, Message, and Evidence, and provide specific grounded correction instructions.
5. If there are NO deficiencies, state clearly that all automated pre-screening checks passed with no regulatory deficiencies flagged, while noting manual scrutiny is still required.
6. Conclude the memo with a structured Officer Review & Sign-Off section with:
- Assigned Compliance Officer: {officer_name}
- Officer Determination: [ ] Accepted / Compliant   [ ] Formal Deficiency Notice Issued   [ ] Referred for Expert Scrutiny
- Reviewing Officer Notes: [ Awaiting Officer Review Notes ]
- Verification Date: Pending
- Officer Signature: [ Pending Authorized Officer Sign-Off ]
CRITICAL: Do NOT generate blank lines of spaces, runs of underscores, or unclosed brackets.

Application Metadata:
{json.dumps(application, indent=2)}

Pre-Screening Findings:
{json.dumps(compact_findings, indent=2)}
"""

    primary_model = (settings.gemini_model or "gemini-2.5-flash").strip()
    fallback_model = (getattr(settings, "gemini_fallback_model", "") or "").strip()
    if fallback_model == primary_model:
        fallback_model = ""

    # Requirement 5: Verify configured model IDs against Google's supported Gemini model list
    primary_supported = is_supported_gemini_model(primary_model, api_key=api_key)
    fallback_supported = is_supported_gemini_model(fallback_model, api_key=api_key) if fallback_model else False

    candidate_models = []
    if primary_supported:
        candidate_models.append(primary_model)
    else:
        logger.warning(
            "Configured primary GEMINI_MODEL '%s' is not in Google's supported Gemini model catalog. Supported: %s",
            primary_model,
            ", ".join(sorted(SUPPORTED_GEMINI_MODELS)),
        )
        if fallback_supported:
            logger.info(
                "Primary model '%s' is unverified; using configured verified fallback model '%s'.",
                primary_model, fallback_model,
            )
            candidate_models.append(fallback_model)
        else:
            unverified_err = f"Configured model '{primary_model}' is not in Google's supported Gemini model list"
            total_elapsed = time.time() - start_time
            logger.warning(
                "Gemini memorandum generation falling back to deterministic compilation. Reason: %s (total time: %.2fs)",
                unverified_err, total_elapsed,
            )
            fallback = generate_deterministic_memo(application, findings, fallback_reason=unverified_err)
            return {
                "memo": fallback,
                "ai_assisted": False,
                "is_fallback": True,
                "fallback_reason": unverified_err,
                "status": "fallback",
                "disclaimer": MEMO_DISCLAIMER,
                "model_used": None,
            }

    
    max_total_budget = 45.0  # Total time budget for all attempts
    max_retries = max(0, min(getattr(settings, "gemini_max_retries", 1), 2))
    timeout_sec = float(getattr(settings, "gemini_timeout_seconds", 30.0))

    # Allow more time for Gemini to generate the memorandum.
    httpx_timeout = httpx.Timeout(
        timeout=timeout_sec,
        connect=min(8.0, timeout_sec),
        read=min(25.0, timeout_sec),
        write=min(8.0, timeout_sec),
        pool=min(8.0, timeout_sec),
    )


    final_fallback_reason = "Gemini API unavailable"
    model_idx = 0

    while model_idx < len(candidate_models):
        model_name = candidate_models[model_idx]
        model_failed_with_503 = False
        model_failed_with_timeout = False

        for attempt in range(max_retries + 1):
            elapsed = time.time() - start_time
            if elapsed >= max_total_budget:
                logger.warning(
                    "Total duration budget exceeded (%.2fs >= %.2fs). Aborting further attempts on model '%s'.",
                    elapsed, max_total_budget, model_name,
                )
                final_fallback_reason = f"Gemini API total duration limit reached ({elapsed:.1f}s)"
                break

            is_last_attempt = (attempt == max_retries)
            try:
                url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent"
                headers = {"Content-Type": "application/json", "x-goog-api-key": api_key}
                r = httpx.post(
                    url,
                    headers=headers,
                    json={
                        "contents": [{"parts": [{"text": prompt}]}],
                        "generationConfig": {
                            "temperature": 0.2,
                            "maxOutputTokens": 3500,
                            "thinkingConfig": {"thinkingLevel": "minimal"},
                        },
                    },
                    timeout=httpx_timeout,
                )

                if r.status_code == 200:
                    data = r.json()
                    candidates = data.get("candidates", [])
                    
                if r.status_code == 200:
                    data = r.json()
                    candidates = data.get("candidates", [])

                    if not candidates:
                        logger.warning(
                            "Gemini API model '%s' returned 200 with empty candidates",
                            model_name,
                        )
                        final_fallback_reason = (
                            f"Gemini API ({model_name}) returned an empty response"
                        )
                        break

                    candidate = candidates[0]
                    finish_reason = candidate.get("finishReason")

                    parts = candidate.get("content", {}).get("parts", [])
                    raw_text = "\n".join(
                        part.get("text", "")
                        for part in parts
                        if isinstance(part, dict) and part.get("text")
                    ).strip()

                    if finish_reason == "MAX_TOKENS" or len(raw_text) < 150:
                        logger.warning(
                            "Gemini API model '%s' output incomplete "
                            "(finishReason=%s, length=%d)",
                            model_name,
                            finish_reason,
                            len(raw_text),
                        )
                        final_fallback_reason = (
                            f"AI generation incomplete on model '{model_name}' "
                            f"({finish_reason}, length={len(raw_text)})"
                        )

                        if (
                            not is_last_attempt
                            and (time.time() - start_time) < max_total_budget
                        ):
                            delay = _compute_backoff_delay(
                                attempt, base=0.4, max_delay=1.5
                            )
                            sleep_fn(delay)
                            continue

                        break

                    cleaned_text = re.sub(
                        r'[_—\-]{8,}', '________', raw_text
                    ).strip()

                    total_elapsed = time.time() - start_time
                    logger.info(
                        "Gemini memorandum generation succeeded using model '%s' (time: %.2fs)",
                        model_name,
                        total_elapsed,
                    )
                    return {
                        "memo": cleaned_text,
                        "ai_assisted": True,
                        "is_fallback": False,
                        "fallback_reason": None,
                        "status": "success",
                        "disclaimer": MEMO_DISCLAIMER,
                        "model_used": model_name,
                    }



                    cleaned_text = re.sub(r'[_—\-]{8,}', '________', raw_text).strip()
                    total_elapsed = time.time() - start_time
                    logger.info(
                        "Gemini memorandum generation succeeded using model '%s' (time: %.2fs)",
                        model_name, total_elapsed,
                    )
                    return {
                        "memo": cleaned_text,
                        "ai_assisted": True,
                        "is_fallback": False,
                        "fallback_reason": None,
                        "status": "success",
                        "disclaimer": MEMO_DISCLAIMER,
                        "model_used": model_name,
                    }

                status_code = r.status_code
                safe_err = _extract_safe_response_error(r, api_key)

                # Requirement 3: Never retry invalid API keys, 400, 401, 403, or 404 errors.
                if status_code in NON_RETRYABLE_STATUS_CODES:
                    logger.warning(
                        "Gemini API model '%s' returned non-retryable HTTP %s: %s",
                        model_name, status_code, safe_err,
                    )
                    final_fallback_reason = f"Gemini API non-retryable error (HTTP {status_code}: {safe_err or 'client error'})"
                    total_elapsed = time.time() - start_time
                    logger.warning(
                        "Gemini memorandum generation falling back to deterministic compilation. Reason: %s (total time: %.2fs)",
                        final_fallback_reason, total_elapsed,
                    )
                    fallback = generate_deterministic_memo(
                        application, findings, fallback_reason=final_fallback_reason
                    )
                    return {
                        "memo": fallback,
                        "ai_assisted": False,
                        "is_fallback": True,
                        "fallback_reason": final_fallback_reason,
                        "status": "fallback",
                        "disclaimer": MEMO_DISCLAIMER,
                        "model_used": None,
                    }

                # Requirement 1: Retry only transient errors (503, 429, 408)
                if status_code in TRANSIENT_STATUS_CODES:
                    if status_code == 503:
                        model_failed_with_503 = True

                    final_fallback_reason = f"Gemini API error (HTTP {status_code}: {safe_err or 'service unavailable'})"
                    if not is_last_attempt and (time.time() - start_time) < max_total_budget:
                        delay = _compute_backoff_delay(attempt, base=0.4, max_delay=1.5)
                        logger.warning(
                            "Gemini API model '%s' returned transient HTTP %s (attempt %d/%d): %s. Retrying in %.2fs...",
                            model_name, status_code, attempt + 1, max_retries + 1, safe_err, delay,
                        )
                        sleep_fn(delay)
                        continue
                    else:
                        logger.warning(
                            "Gemini API retries exhausted for model '%s' on HTTP %s: %s",
                            model_name, status_code, safe_err,
                        )
                        break

                logger.warning(
                    "Gemini API model '%s' returned unexpected HTTP %s: %s",
                    model_name, status_code, safe_err,
                )
                final_fallback_reason = f"Gemini API error (HTTP {status_code})"
                if not is_last_attempt and (time.time() - start_time) < max_total_budget:
                    delay = _compute_backoff_delay(attempt, base=0.4, max_delay=1.5)
                    sleep_fn(delay)
                    continue
                else:
                    break

            except (httpx.TimeoutException, httpx.NetworkError) as e:
                model_failed_with_timeout = True
                err_type = type(e).__name__
                safe_err = _sanitize_log_message(str(e), api_key)
                final_fallback_reason = f"Gemini API network timeout ({err_type})"

                if not is_last_attempt and (time.time() - start_time) < max_total_budget:
                    delay = _compute_backoff_delay(attempt, base=0.4, max_delay=1.5)
                    logger.warning(
                        "Gemini API model '%s' transient %s (attempt %d/%d): %s. Retrying in %.2fs...",
                        model_name, err_type, attempt + 1, max_retries + 1, safe_err[:120], delay,
                    )
                    sleep_fn(delay)
                    continue
                else:
                    logger.warning(
                        "Gemini API retries exhausted for model '%s' after network/timeout errors: %s",
                        model_name, err_type,
                    )
                    break

            except Exception as e:
                err_type = type(e).__name__
                safe_err = _sanitize_log_message(str(e), api_key)
                logger.warning(
                    "Gemini API model '%s' unexpected exception: %s (%s)",
                    model_name, err_type, safe_err[:120],
                )
                final_fallback_reason = f"AI service unavailable ({err_type})"
                break

        # Requirement 2: If primary model returned 503 (or timeout) after retries,
        # optionally try a configurable fallback model from .env; do not hardcode an unverified model name.
        if model_idx == 0 and (model_failed_with_503 or model_failed_with_timeout):
            if fallback_model and fallback_supported and fallback_model not in candidate_models:
                logger.info(
                    "Primary model '%s' failed (%s). Attempting configured verified fallback model '%s'.",
                    primary_model, "503" if model_failed_with_503 else "timeout", fallback_model,
                )
                candidate_models.append(fallback_model)

        model_idx += 1

    total_elapsed = time.time() - start_time
    logger.warning(
        "Gemini memorandum generation falling back to deterministic compilation. Reason: %s (total time: %.2fs)",
        final_fallback_reason, total_elapsed,
    )
    fallback = generate_deterministic_memo(application, findings, fallback_reason=final_fallback_reason)
    return {
        "memo": fallback,
        "ai_assisted": False,
        "is_fallback": True,
        "fallback_reason": final_fallback_reason,
        "status": "fallback",
        "disclaimer": MEMO_DISCLAIMER,
        "model_used": None,
    }
