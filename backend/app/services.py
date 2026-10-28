import hashlib, io, re, os
from pathlib import Path
from PIL import Image
import yaml
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

def gemini_memo(application: dict, findings: list[dict]) -> str:
    if not settings.gemini_api_key:
        return (
            "AI memo unavailable: GEMINI_API_KEY is not configured on the server. "
            "Review the evidence-linked findings manually. No automated compliance decision has been made."
        )
    try:
        import httpx
        prompt = (
            "Write a concise, neutral compliance screening memo. Only summarize supplied findings. "
            "Do not invent legal clauses or official requirements. Do not claim fraud. "
            "Clearly state that officer review is required.\n"
            f"Application: {application}\nFindings: {findings}"
        )
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{settings.gemini_model}:generateContent"
        r = httpx.post(
            url,
            params={"key": settings.gemini_api_key},
            json={
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"temperature": 0.2, "maxOutputTokens": 700},
            },
            timeout=20,
        )
        r.raise_for_status()
        data = r.json()
        return data["candidates"][0]["content"]["parts"][0]["text"]
    except Exception:
        return (
            "AI memo generation failed. Use the evidence-linked findings and conduct manual review; "
            "no compliance decision has been made."
        )
