"""
Comprehensive backend tests for BroCode AICTE Compliance Pre-Screening System.
Tests cover:
- Institution, Officer, and Admin permissions
- Unauthorized document upload attempts by officers
- Cross-institution data access prevention & information leakage prevention
- Explicit document-level authorization in download endpoint (officer evidence vs institutional docs)
- Officer assignment workflow and authorization enforcement
- Demo-user initialization and login
- Document screening, OCR extraction, and malformed file handling
- Duplicate-file detection and privacy scoping (no foreign metadata leaked)
- Finding-to-document associations and status distinctions
- Deficiency handling with structured finding references, correction instructions, and submission versioning
- Audit logging and verification
"""
import io
import os
import sys
import shutil
from pathlib import Path
import pytest
from PIL import Image

# Ensure app package is importable
backend_dir = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(backend_dir))

# Configure test environment variables BEFORE importing app
os.environ["DATABASE_URL"] = "sqlite:///./test_brocode.db"
os.environ["SEED_DEMO_USERS"] = "true"
os.environ["SECRET_KEY"] = "test-secret-key-for-automated-tests-only"
os.environ["UPLOAD_DIR"] = "./test_uploads"

from fastapi.testclient import TestClient
from app.main import app, startup
from app.db import Base, engine, SessionLocal
from app.models import User, Application, Document, Finding, OfficerReview


def make_valid_pdf(text: str = "Extension of Approval AICTE Faculty Data") -> bytes:
    """Generate a real valid PDF in memory using fitz or standard minimal syntax."""
    try:
        import fitz
        doc = fitz.open()
        page = doc.new_page()
        page.insert_text((50, 72), text)
        data = doc.write()
        doc.close()
        return data
    except Exception:
        return (
            b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
            b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
            b"3 0 obj<</Type/Page/MediaBox[0 0 300 144]/Parent 2 0 R/Contents 4 0 R>>endobj\n"
            b"4 0 obj<</Length 44>>stream\nBT /F1 12 Tf 72 712 Td (" + text.encode() + b") Tj ET\nendstream\nendobj\n"
            b"xref\n0 5\n0000000000 65535 f\n0000000010 00000 n\n0000000060 00000 n\n0000000115 00000 n\n0000000203 00000 n\n"
            b"trailer<</Size 5/Root 1 0 R>>\nstartxref\n298\n%%EOF\n"
        )


def make_valid_png() -> bytes:
    """Generate a valid 20x20 PNG in memory."""
    buf = io.BytesIO()
    img = Image.new("RGB", (20, 20), color=(73, 109, 137))
    img.save(buf, format="PNG")
    return buf.getvalue()


@pytest.fixture(scope="session", autouse=True)
def setup_test_suite():
    """Initializes the test database and uploads directory once for the session."""
    test_db = Path("./test_brocode.db").resolve()
    test_uploads = Path("./test_uploads").resolve()
    test_uploads.mkdir(parents=True, exist_ok=True)
    if test_db.exists():
        try:
            test_db.unlink(missing_ok=True)
        except Exception:
            pass

    # Run startup hooks (tables, migrations, demo seeding)
    startup()
    yield
    # Cleanup after session
    try:
        engine.dispose()
    except Exception:
        pass
    if test_uploads.exists():
        shutil.rmtree(test_uploads, ignore_errors=True)
    if test_db.exists():
        try:
            test_db.unlink(missing_ok=True)
        except Exception:
            pass


client = TestClient(app)


def login_token(email: str, password: str) -> str:
    res = client.post("/api/auth/login", data={"username": email, "password": password})
    assert res.status_code == 200, f"Login failed for {email}: {res.text}"
    return res.json()["access_token"]


# ===========================================================================
# 1. Authentication & Demo-User Seeding Tests
# ===========================================================================
class TestAuthAndDemoUsers:
    def test_health_check(self):
        res = client.get("/api/health")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
        assert data["live_aicte_integration"] is False
        assert data["officer_assignment_model"] == "assigned_officer_enforced"
        assert "manual review" in data["message"].lower()

    def test_demo_users_login(self):
        for email, pw in [
            ("institution@example.com", "DemoInstitution123!"),
            ("officer@example.com", "DemoOfficer123!"),
            ("admin@example.com", "DemoAdmin123!"),
        ]:
            token = login_token(email, pw)
            assert isinstance(token, str) and len(token) > 20

    def test_invalid_credentials_rejected(self):
        res = client.post("/api/auth/login", data={"username": "fake@example.com", "password": "wrongpassword"})
        assert res.status_code == 401

    def test_me_endpoint_security(self):
        token = login_token("institution@example.com", "DemoInstitution123!")
        res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert res.status_code == 200
        data = res.json()
        assert data["role"] == "institution"
        assert "password" not in data
        assert "password_hash" not in data

    def test_demo_user_seeding_is_idempotent(self):
        startup()
        db = SessionLocal()
        try:
            inst_count = len(db.query(User).filter(User.email == "institution@example.com").all())
            assert inst_count == 1
        finally:
            db.close()


# ===========================================================================
# 2. Role-Based Permissions & Workspace Isolation
# ===========================================================================
class TestRolePermissions:
    def test_institution_creates_application(self):
        token = login_token("institution@example.com", "DemoInstitution123!")
        payload = {
            "institution_name": "Government Polytechnic Pune",
            "institution_code": "GP-101",
            "application_type": "Extension of Approval",
            "academic_year": "2026-27",
            "programme": "Civil Engineering",
            "current_intake": 60,
            "proposed_intake": 60,
        }
        res = client.post("/api/applications", json=payload, headers={"Authorization": f"Bearer {token}"})
        assert res.status_code == 200
        data = res.json()
        assert data["institution_name"] == "Government Polytechnic Pune"
        assert data["status"] == "DRAFT"
        assert data["submission_version"] == 1

    def test_officer_cannot_create_application(self):
        token = login_token("officer@example.com", "DemoOfficer123!")
        res = client.post(
            "/api/applications",
            json={"institution_name": "Unauthorized College", "academic_year": "2026-27"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert res.status_code == 403

    def test_officer_cannot_upload_institutional_document(self):
        """Officers MUST NOT be permitted to upload into the institution's document collection."""
        inst_token = login_token("institution@example.com", "DemoInstitution123!")
        app_res = client.post(
            "/api/applications",
            json={"institution_name": "Testing Document Lockout", "academic_year": "2026-27"},
            headers={"Authorization": f"Bearer {inst_token}"},
        )
        app_id = app_res.json()["id"]

        officer_token = login_token("officer@example.com", "DemoOfficer123!")
        pdf = make_valid_pdf()
        res = client.post(
            f"/api/applications/{app_id}/documents",
            files={"file": ("officer_attempt.pdf", pdf, "application/pdf")},
            headers={"Authorization": f"Bearer {officer_token}"},
        )
        assert res.status_code == 403

    def test_cross_institution_isolation(self):
        """Institution B must not view or upload to Institution A's application."""
        admin_token = login_token("admin@example.com", "DemoAdmin123!")
        client.post(
            "/api/admin/users",
            json={
                "email": "inst2@example.com",
                "name": "Second Institution",
                "password": "Password123!",
                "role": "institution",
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        inst1_token = login_token("institution@example.com", "DemoInstitution123!")
        app1_res = client.post(
            "/api/applications",
            json={"institution_name": "Institute 1 Private App", "academic_year": "2026-27"},
            headers={"Authorization": f"Bearer {inst1_token}"},
        )
        app1_id = app1_res.json()["id"]

        inst2_token = login_token("inst2@example.com", "Password123!")

        res_view = client.get(f"/api/applications/{app1_id}", headers={"Authorization": f"Bearer {inst2_token}"})
        assert res_view.status_code == 404

        pdf = make_valid_pdf()
        res_up = client.post(
            f"/api/applications/{app1_id}/documents",
            files={"file": ("cross.pdf", pdf, "application/pdf")},
            headers={"Authorization": f"Bearer {inst2_token}"},
        )
        assert res_up.status_code in (403, 404)

        res_list = client.get("/api/applications", headers={"Authorization": f"Bearer {inst2_token}"})
        assert res_list.status_code == 200
        for item in res_list.json():
            assert item["id"] != app1_id


# ===========================================================================
# 3. Privacy & Cross-Institution Information Leakage Prevention
# ===========================================================================
class TestDuplicateHashPrivacy:
    def test_cross_institution_duplicate_leakage_prevented(self):
        """
        When Institution B uploads an identical file that was previously uploaded
        by Institution A, the system MUST NOT leak Institution A's filename,
        document ID, application ID, or any identifying metadata.
        """
        inst1_token = login_token("institution@example.com", "DemoInstitution123!")
        inst2_token = login_token("inst2@example.com", "Password123!")

        # Inst1 creates App 1 and uploads a sensitive document
        app1_res = client.post(
            "/api/applications",
            json={"institution_name": "Institute Alpha Confidential", "academic_year": "2026-27"},
            headers={"Authorization": f"Bearer {inst1_token}"},
        )
        app1_id = app1_res.json()["id"]
        secret_pdf = make_valid_pdf("Shared Blueprint Document 2026-2027")

        res_orig = client.post(
            f"/api/applications/{app1_id}/documents",
            files={"file": ("alpha_secret_blueprint.pdf", secret_pdf, "application/pdf")},
            headers={"Authorization": f"Bearer {inst1_token}"},
        )
        assert res_orig.status_code == 200
        doc1_id = res_orig.json()["document_id"]

        # Inst2 creates App 2 and uploads the exact same file
        app2_res = client.post(
            "/api/applications",
            json={"institution_name": "Institute Beta Discovery Test", "academic_year": "2026-27"},
            headers={"Authorization": f"Bearer {inst2_token}"},
        )
        app2_id = app2_res.json()["id"]

        res_dup = client.post(
            f"/api/applications/{app2_id}/documents",
            files={"file": ("beta_own_file.pdf", secret_pdf, "application/pdf")},
            headers={"Authorization": f"Bearer {inst2_token}"},
        )
        assert res_dup.status_code == 200
        data_dup = res_dup.json()

        assert data_dup["duplicate_hash_match"] is True
        dup_info = data_dup["duplicate_info"]
        assert dup_info is not None
        assert dup_info["scope"] == "cross_institution"

        # STRICT PRIVACY CHECKS: No foreign metadata leaked to Inst2!
        assert dup_info.get("matched_filename") is None
        assert dup_info.get("matched_document_id") is None
        assert "matched_application_id" not in dup_info
        assert "alpha_secret_blueprint.pdf" not in str(data_dup)

        # Also inspect detail response for App 2
        detail2 = client.get(f"/api/applications/{app2_id}", headers={"Authorization": f"Bearer {inst2_token}"}).json()
        for f in detail2["findings"]:
            if f["rule_id"] == "DOC-003":
                assert "alpha_secret_blueprint.pdf" not in str(f)
                evidence = f.get("evidence", {})
                assert "matched_application_id" not in evidence
                assert evidence.get("matched_document_id") is None
                assert evidence.get("matched_filename") is None


# ===========================================================================
# 4. Document-Level Authorization in Download Endpoint
# ===========================================================================
class TestDocumentLevelDownloadAuthorization:
    def test_download_authorization_rules(self):
        """
        Verify:
        - Institution cannot download officer evidence (403 Forbidden).
        - Institution cannot download other institution's documents (404/403).
        - Assigned officer can download institutional documents and officer evidence.
        - Unassigned / other officers cannot download documents for an assigned application.
        """
        admin_token = login_token("admin@example.com", "DemoAdmin123!")
        inst1_token = login_token("institution@example.com", "DemoInstitution123!")
        inst2_token = login_token("inst2@example.com", "Password123!")
        off1_token = login_token("officer@example.com", "DemoOfficer123!")

        # Create second officer for testing officer assignment lockout
        client.post(
            "/api/admin/users",
            json={
                "email": "officer2@example.com",
                "name": "Officer Two",
                "password": "Password123!",
                "role": "officer",
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        off2_token = login_token("officer2@example.com", "Password123!")

        # Inst1 creates app
        app_res = client.post(
            "/api/applications",
            json={"institution_name": "Auth Download Institute", "academic_year": "2026-27"},
            headers={"Authorization": f"Bearer {inst1_token}"},
        )
        app_id = app_res.json()["id"]

        # Inst1 uploads institutional doc
        inst_pdf = make_valid_pdf("Institution confidential syllabus doc")
        up_res = client.post(
            f"/api/applications/{app_id}/documents",
            files={"file": ("syllabus.pdf", inst_pdf, "application/pdf")},
            headers={"Authorization": f"Bearer {inst1_token}"},
        )
        inst_doc_id = up_res.json()["document_id"]

        # Inst1 submits application for compliance review
        sub_res = client.patch(
            f"/api/applications/{app_id}/status",
            json={"status": "UNDER_REVIEW"},
            headers={"Authorization": f"Bearer {inst1_token}"},
        )
        assert sub_res.status_code == 200

        # Assign app to Officer 1
        off1_info = client.get("/api/auth/me", headers={"Authorization": f"Bearer {off1_token}"}).json()
        off1_id = off1_info["id"]
        client.patch(
            f"/api/applications/{app_id}/assign",
            json={"officer_id": off1_id},
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        # Officer 1 uploads officer evidence
        off_pdf = make_valid_pdf("Officer confidential inspection report")
        ev_res = client.post(
            f"/api/applications/{app_id}/officer-evidence",
            files={"file": ("inspection_memo.pdf", off_pdf, "application/pdf")},
            headers={"Authorization": f"Bearer {off1_token}"},
        )
        assert ev_res.status_code == 200
        off_doc_id = ev_res.json()["document_id"]

        # 1. Institution owner CAN download institutional document
        res_dl1 = client.get(
            f"/api/applications/{app_id}/documents/{inst_doc_id}/download",
            headers={"Authorization": f"Bearer {inst1_token}"},
        )
        assert res_dl1.status_code == 200
        assert res_dl1.content == inst_pdf

        # 2. Institution MUST NOT download officer evidence
        res_dl_ev = client.get(
            f"/api/applications/{app_id}/documents/{off_doc_id}/download",
            headers={"Authorization": f"Bearer {inst1_token}"},
        )
        assert res_dl_ev.status_code == 403

        # 3. Foreign institution MUST NOT download institutional doc or officer evidence
        res_dl_cross = client.get(
            f"/api/applications/{app_id}/documents/{inst_doc_id}/download",
            headers={"Authorization": f"Bearer {inst2_token}"},
        )
        assert res_dl_cross.status_code in (403, 404)

        # 4. Assigned Officer 1 CAN download both
        assert client.get(f"/api/applications/{app_id}/documents/{inst_doc_id}/download", headers={"Authorization": f"Bearer {off1_token}"}).status_code == 200
        assert client.get(f"/api/applications/{app_id}/documents/{off_doc_id}/download", headers={"Authorization": f"Bearer {off1_token}"}).status_code == 200

        # 5. Non-assigned Officer 2 CANNOT access or download documents for an application assigned to Officer 1
        res_dl_off2 = client.get(
            f"/api/applications/{app_id}/documents/{inst_doc_id}/download",
            headers={"Authorization": f"Bearer {off2_token}"},
        )
        assert res_dl_off2.status_code == 404  # Not found due to officer assignment scoping

        # 6. Institution detail response does not leak officer evidence
        detail_inst = client.get(f"/api/applications/{app_id}", headers={"Authorization": f"Bearer {inst1_token}"}).json()
        assert not any(d["upload_type"] == "officer_evidence" for d in detail_inst["documents"])


# ===========================================================================
# 5. Officer Assignment & Application Management
# ===========================================================================
class TestOfficerAssignmentWorkflow:
    def test_assignment_enforcement(self):
        admin_token = login_token("admin@example.com", "DemoAdmin123!")
        off1_token = login_token("officer@example.com", "DemoOfficer123!")
        off2_token = login_token("officer2@example.com", "Password123!")
        inst_token = login_token("institution@example.com", "DemoInstitution123!")

        off1_id = client.get("/api/auth/me", headers={"Authorization": f"Bearer {off1_token}"}).json()["id"]
        off2_id = client.get("/api/auth/me", headers={"Authorization": f"Bearer {off2_token}"}).json()["id"]

        # Create unassigned application
        app_res = client.post(
            "/api/applications",
            json={"institution_name": "Assignment Test Academy", "academic_year": "2026-27"},
            headers={"Authorization": f"Bearer {inst_token}"},
        )
        app_id = app_res.json()["id"]
        assert app_res.json()["assigned_officer_id"] is None

        # Institution submits application for review (DRAFT -> UNDER_REVIEW)
        sub_res = client.patch(
            f"/api/applications/{app_id}/status",
            json={"status": "UNDER_REVIEW"},
            headers={"Authorization": f"Bearer {inst_token}"},
        )
        assert sub_res.status_code == 200

        # Officer 1 claims the unassigned application
        claim_res = client.patch(
            f"/api/applications/{app_id}/assign",
            json={"officer_id": off1_id},
            headers={"Authorization": f"Bearer {off1_token}"},
        )
        assert claim_res.status_code == 200
        assert claim_res.json()["assigned_officer_id"] == off1_id

        # Officer 2 tries to claim an application already assigned to Officer 1 -> 403/404
        claim_conflict = client.patch(
            f"/api/applications/{app_id}/assign",
            json={"officer_id": off2_id},
            headers={"Authorization": f"Bearer {off2_token}"},
        )
        assert claim_conflict.status_code in (403, 404)

        # Officer 2 tries to review application assigned to Officer 1 -> 404 (not in access scope)
        review_blocked = client.post(
            f"/api/applications/{app_id}/reviews",
            json={"action": "REVIEW_NOTE", "notes": "Unauthorized review attempt"},
            headers={"Authorization": f"Bearer {off2_token}"},
        )
        assert review_blocked.status_code in (403, 404)

        # Assigned Officer 1 successfully reviews
        review_ok = client.post(
            f"/api/applications/{app_id}/reviews",
            json={"action": "REVIEW_NOTE", "notes": "Authorized review by assigned officer"},
            headers={"Authorization": f"Bearer {off1_token}"},
        )
        assert review_ok.status_code == 200


# ===========================================================================
# 6. Structured Deficiency Handling & Submission History
# ===========================================================================
class TestDeficiencyHandlingAndVersioning:
    def test_structured_deficiency_and_version_progression(self):
        inst_token = login_token("institution@example.com", "DemoInstitution123!")
        off_token = login_token("officer@example.com", "DemoOfficer123!")
        off_id = client.get("/api/auth/me", headers={"Authorization": f"Bearer {off_token}"}).json()["id"]

        # 1. Institution creates application (Cycle v1)
        app_res = client.post(
            "/api/applications",
            json={"institution_name": "Versioning Institute of Tech", "academic_year": "2026-27"},
            headers={"Authorization": f"Bearer {inst_token}"},
        )
        app_id = app_res.json()["id"]

        # Upload initial doc in cycle v1
        pdf1 = make_valid_pdf("Initial cycle document 1")
        up1 = client.post(
            f"/api/applications/{app_id}/documents",
            files={"file": ("v1_doc.pdf", pdf1, "application/pdf")},
            headers={"Authorization": f"Bearer {inst_token}"},
        )
        assert up1.json()["submission_version"] == 1

        # Submit v1 (transitions DRAFT -> UNDER_REVIEW)
        sub_res = client.patch(f"/api/applications/{app_id}/status", json={"status": "UNDER_REVIEW"}, headers={"Authorization": f"Bearer {inst_token}"})
        assert sub_res.status_code == 200

        # Claim app for officer now that it is submitted
        claim_res = client.patch(
            f"/api/applications/{app_id}/assign",
            json={"officer_id": off_id},
            headers={"Authorization": f"Bearer {off_token}"},
        )
        assert claim_res.status_code == 200

        # Officer raises deficiency with structured finding references and instructions
        client.patch(f"/api/applications/{app_id}/status", json={"status": "DEFICIENCY_RAISED"}, headers={"Authorization": f"Bearer {off_token}"})
        rev_res = client.post(
            f"/api/applications/{app_id}/reviews",
            json={
                "action": "DEFICIENCY_REQUEST",
                "notes": "Land deed missing registration stamp. Faculty list incomplete.",
                "finding_references": ["DOC-001", "DOC-004"],
                "correction_instructions": "Upload certified land registration deed and signed faculty roster.",
            },
            headers={"Authorization": f"Bearer {off_token}"},
        )
        assert rev_res.status_code == 200
        rev_data = rev_res.json()
        assert rev_data["finding_references"] == ["DOC-001", "DOC-004"]
        assert "certified land registration" in rev_data["correction_instructions"]

        # Institution uploads corrected doc and submits rectification
        pdf2 = make_valid_pdf("Rectified certified land deed and faculty roster")
        up2 = client.post(
            f"/api/applications/{app_id}/documents",
            files={"file": ("rectified_land_deed.pdf", pdf2, "application/pdf")},
            headers={"Authorization": f"Bearer {inst_token}"},
        )
        assert up2.status_code == 200

        # Submitting rectification increments cycle to v2!
        sub_rect = client.patch(
            f"/api/applications/{app_id}/status",
            json={"status": "RECTIFICATION_SUBMITTED"},
            headers={"Authorization": f"Bearer {inst_token}"},
        )
        assert sub_rect.status_code == 200
        assert sub_rect.json()["submission_version"] == 2

        # Check detail response returns structured submission history
        detail = client.get(f"/api/applications/{app_id}", headers={"Authorization": f"Bearer {inst_token}"}).json()
        assert detail["application"]["submission_version"] == 2
        assert len(detail["submission_history"]) >= 2
        assert detail["submission_history"][0]["version"] == 1
        assert detail["submission_history"][1]["version"] == 2


# ===========================================================================
# 7. Document Screening, Validation & Corrupted Files
# ===========================================================================
class TestDocumentScreeningIntegrity:
    def test_upload_empty_file_rejected(self):
        token = login_token("institution@example.com", "DemoInstitution123!")
        app_res = client.post(
            "/api/applications",
            json={"institution_name": "Validation Test App"},
            headers={"Authorization": f"Bearer {token}"},
        )
        app_id = app_res.json()["id"]

        res = client.post(
            f"/api/applications/{app_id}/documents",
            files={"file": ("empty.pdf", b"", "application/pdf")},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert res.status_code == 400
        assert "empty" in res.json()["detail"].lower()

    def test_upload_unsupported_mime_rejected(self):
        token = login_token("institution@example.com", "DemoInstitution123!")
        app_res = client.post(
            "/api/applications",
            json={"institution_name": "MIME Test App"},
            headers={"Authorization": f"Bearer {token}"},
        )
        app_id = app_res.json()["id"]

        res = client.post(
            f"/api/applications/{app_id}/documents",
            files={"file": ("script.sh", b"#!/bin/bash\necho hi", "application/x-sh")},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert res.status_code == 415

    def test_upload_corrupted_pdf_rejected(self):
        token = login_token("institution@example.com", "DemoInstitution123!")
        app_res = client.post(
            "/api/applications",
            json={"institution_name": "Corrupt Test App"},
            headers={"Authorization": f"Bearer {token}"},
        )
        app_id = app_res.json()["id"]

        res = client.post(
            f"/api/applications/{app_id}/documents",
            files={"file": ("corrupt.pdf", b"%PDF-1.4 [broken stream data with no catalog", "application/pdf")},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert res.status_code == 400


# ===========================================================================
# 8. Admin & Audit Logging Integrity Tests
# ===========================================================================
class TestAdminAndAudit:
    def test_admin_manages_users(self):
        admin_token = login_token("admin@example.com", "DemoAdmin123!")
        users = client.get("/api/admin/users", headers={"Authorization": f"Bearer {admin_token}"}).json()
        assert len(users) >= 3

        target = users[0]
        up_res = client.patch(
            f"/api/admin/users/{target['id']}",
            json={"name": "Updated Test Name"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert up_res.status_code == 200
        assert up_res.json()["name"] == "Updated Test Name"

    def test_audit_hash_chain_verification(self):
        admin_token = login_token("admin@example.com", "DemoAdmin123!")
        verify_res = client.get("/api/audit/verify", headers={"Authorization": f"Bearer {admin_token}"})
        assert verify_res.status_code == 200
        data = verify_res.json()
        assert data["valid"] is True


# ===========================================================================
# 9. Draft Application Visibility & Privacy
# ===========================================================================
class TestDraftVisibilityAndPrivacy:
    def test_officer_cannot_view_or_act_on_drafts(self):
        inst_token = login_token("institution@example.com", "DemoInstitution123!")
        off_token = login_token("officer@example.com", "DemoOfficer123!")
        admin_token = login_token("admin@example.com", "DemoAdmin123!")

        # Institution creates draft application
        app_res = client.post(
            "/api/applications",
            json={"institution_name": "Private Draft Academy", "academic_year": "2026-27"},
            headers={"Authorization": f"Bearer {inst_token}"},
        )
        assert app_res.status_code == 200
        app_id = app_res.json()["id"]
        assert app_res.json()["status"] == "DRAFT"

        # Institution uploads a document to draft
        pdf = make_valid_pdf("Draft syllabus content")
        up_res = client.post(
            f"/api/applications/{app_id}/documents",
            files={"file": ("draft_doc.pdf", pdf, "application/pdf")},
            headers={"Authorization": f"Bearer {inst_token}"},
        )
        assert up_res.status_code == 200
        doc_id = up_res.json()["document_id"]

        # 1. Officer listing applications MUST NOT contain the draft
        off_list = client.get("/api/applications", headers={"Authorization": f"Bearer {off_token}"}).json()
        assert not any(a["id"] == app_id for a in off_list)

        # 2. Officer detail query for draft MUST return 404
        off_detail = client.get(f"/api/applications/{app_id}", headers={"Authorization": f"Bearer {off_token}"})
        assert off_detail.status_code == 404

        # 3. Officer document download for draft MUST return 404
        off_dl = client.get(f"/api/applications/{app_id}/documents/{doc_id}/download", headers={"Authorization": f"Bearer {off_token}"})
        assert off_dl.status_code == 404

        # 4. Officer assign on draft MUST return 404
        off_info = client.get("/api/auth/me", headers={"Authorization": f"Bearer {off_token}"}).json()
        off_assign = client.patch(
            f"/api/applications/{app_id}/assign",
            json={"officer_id": off_info["id"]},
            headers={"Authorization": f"Bearer {off_token}"},
        )
        assert off_assign.status_code in (404, 409)

        # 5. Officer review on draft MUST return 404
        off_rev = client.post(
            f"/api/applications/{app_id}/reviews",
            json={"action": "REVIEW_NOTE", "notes": "Premature review attempt"},
            headers={"Authorization": f"Bearer {off_token}"},
        )
        assert off_rev.status_code in (404, 409)

        # 6. Officer evidence upload on draft MUST return 404
        off_ev = client.post(
            f"/api/applications/{app_id}/officer-evidence",
            files={"file": ("ev.pdf", pdf, "application/pdf")},
            headers={"Authorization": f"Bearer {off_token}"},
        )
        assert off_ev.status_code in (404, 409)

        # 7. Admin queue: by default excludes drafts; includes drafts with include_drafts=true
        admin_list_default = client.get("/api/applications", headers={"Authorization": f"Bearer {admin_token}"}).json()
        assert not any(a["id"] == app_id for a in admin_list_default)

        admin_list_oversight = client.get("/api/applications?include_drafts=true", headers={"Authorization": f"Bearer {admin_token}"}).json()
        assert any(a["id"] == app_id for a in admin_list_oversight)

        # 8. Admin assigning draft returns 409 Conflict
        admin_assign = client.patch(
            f"/api/applications/{app_id}/assign",
            json={"officer_id": off_info["id"]},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert admin_assign.status_code == 409


# ===========================================================================
# 10. Delete Draft Application
# ===========================================================================
class TestDeleteDraftApplication:
    def test_institution_deletes_own_draft_with_cascaded_file_cleanup(self):
        inst1_token = login_token("institution@example.com", "DemoInstitution123!")
        inst2_token = login_token("inst2@example.com", "Password123!")
        off_token = login_token("officer@example.com", "DemoOfficer123!")
        from app.main import UPLOAD_DIR, SessionLocal
        from app.models import Document as DocModel, Finding as FindingModel

        # 1. Create draft application
        app_res = client.post(
            "/api/applications",
            json={"institution_name": "Ephemeral Draft Institute", "academic_year": "2026-27"},
            headers={"Authorization": f"Bearer {inst1_token}"},
        )
        app_id = app_res.json()["id"]

        # 2. Upload document to draft
        pdf = make_valid_pdf("Draft test content for deletion cascade")
        up_res = client.post(
            f"/api/applications/{app_id}/documents",
            files={"file": ("to_delete.pdf", pdf, "application/pdf")},
            headers={"Authorization": f"Bearer {inst1_token}"},
        )
        doc_id = up_res.json()["document_id"]

        # Verify physical file and database records exist
        with SessionLocal() as db:
            doc_record = db.get(DocModel, doc_id)
            assert doc_record is not None
            stored_name = doc_record.stored_name
            stored_file_path = UPLOAD_DIR / stored_name
            assert stored_file_path.exists()
            findings_count = db.query(FindingModel).filter(FindingModel.application_id == app_id).count()
            assert findings_count > 0

        # 3. Another institution attempts to delete it -> 404 (isolation)
        del_cross = client.delete(f"/api/applications/{app_id}", headers={"Authorization": f"Bearer {inst2_token}"})
        assert del_cross.status_code == 404

        # 4. Officer attempts to delete draft -> 403 (unauthorized role)
        del_officer = client.delete(f"/api/applications/{app_id}", headers={"Authorization": f"Bearer {off_token}"})
        assert del_officer.status_code == 403

        # 5. Owner institution deletes own draft -> 200 OK
        del_res = client.delete(f"/api/applications/{app_id}", headers={"Authorization": f"Bearer {inst1_token}"})
        assert del_res.status_code == 200
        assert "deleted" in del_res.json()["message"].lower()

        # 6. Verify physical file is cleaned up safely from disk
        assert not stored_file_path.exists()

        # 7. Verify database records are cascade-deleted
        with SessionLocal() as db:
            assert db.get(DocModel, doc_id) is None
            assert db.query(FindingModel).filter(FindingModel.application_id == app_id).count() == 0

        # 8. Subsequent GET returns 404
        get_res = client.get(f"/api/applications/{app_id}", headers={"Authorization": f"Bearer {inst1_token}"})
        assert get_res.status_code == 404

    def test_cannot_delete_submitted_or_reviewed_application(self):
        inst_token = login_token("institution@example.com", "DemoInstitution123!")

        # Create application and submit it
        app_res = client.post(
            "/api/applications",
            json={"institution_name": "Submitted Non-Deletable Academy", "academic_year": "2026-27"},
            headers={"Authorization": f"Bearer {inst_token}"},
        )
        app_id = app_res.json()["id"]

        # Submit application (DRAFT -> UNDER_REVIEW)
        sub_res = client.patch(
            f"/api/applications/{app_id}/status",
            json={"status": "UNDER_REVIEW"},
            headers={"Authorization": f"Bearer {inst_token}"},
        )
        assert sub_res.status_code == 200

        # Attempt to delete submitted application -> 409 Conflict
        del_res = client.delete(f"/api/applications/{app_id}", headers={"Authorization": f"Bearer {inst_token}"})
        assert del_res.status_code == 409
        assert "Cannot delete application" in del_res.json()["detail"]


# ===========================================================================
# 11. Remove & Replace Document in Editable Application
# ===========================================================================
class TestRemoveAndReplaceDocument:
    def test_remove_document_and_clean_up_obsolete_findings(self):
        inst_token = login_token("institution@example.com", "DemoInstitution123!")
        from app.main import UPLOAD_DIR, SessionLocal
        from app.models import Document as DocModel, Finding as FindingModel

        # Create draft application
        app_res = client.post(
            "/api/applications",
            json={"institution_name": "Doc Removal Academy", "academic_year": "2026-27"},
            headers={"Authorization": f"Bearer {inst_token}"},
        )
        app_id = app_res.json()["id"]

        # Upload document
        pdf = make_valid_pdf("Document to be removed")
        up_res = client.post(
            f"/api/applications/{app_id}/documents",
            files={"file": ("wrong_doc.pdf", pdf, "application/pdf")},
            headers={"Authorization": f"Bearer {inst_token}"},
        )
        doc_id = up_res.json()["document_id"]

        with SessionLocal() as db:
            stored_name = db.get(DocModel, doc_id).stored_name
            stored_file_path = UPLOAD_DIR / stored_name
            assert stored_file_path.exists()
            assert db.query(FindingModel).filter(FindingModel.document_id == doc_id).count() > 0

        # Remove the document
        del_doc = client.delete(
            f"/api/applications/{app_id}/documents/{doc_id}",
            headers={"Authorization": f"Bearer {inst_token}"},
        )
        assert del_doc.status_code == 200

        # Physical file unlinked
        assert not stored_file_path.exists()

        # Database document and findings removed
        with SessionLocal() as db:
            assert db.get(DocModel, doc_id) is None
            assert db.query(FindingModel).filter(FindingModel.document_id == doc_id).count() == 0

    def test_replace_document_updates_file_and_reruns_screening(self):
        inst_token = login_token("institution@example.com", "DemoInstitution123!")
        from app.main import UPLOAD_DIR, SessionLocal
        from app.models import Document as DocModel, Finding as FindingModel

        # Create draft application
        app_res = client.post(
            "/api/applications",
            json={"institution_name": "Doc Replacement Tech", "academic_year": "2026-27"},
            headers={"Authorization": f"Bearer {inst_token}"},
        )
        app_id = app_res.json()["id"]

        # Upload initial document
        pdf1 = make_valid_pdf("Old syllabus v1")
        up1 = client.post(
            f"/api/applications/{app_id}/documents",
            files={"file": ("old_syllabus.pdf", pdf1, "application/pdf")},
            headers={"Authorization": f"Bearer {inst_token}"},
        )
        doc_id = up1.json()["document_id"]

        with SessionLocal() as db:
            old_stored = db.get(DocModel, doc_id).stored_name
            old_path = UPLOAD_DIR / old_stored
            assert old_path.exists()

        # Replace document with new file
        pdf2 = make_valid_pdf("Corrected land deed document with registered title")
        rep_res = client.put(
            f"/api/applications/{app_id}/documents/{doc_id}",
            files={"file": ("land_deed_corrected.pdf", pdf2, "application/pdf")},
            headers={"Authorization": f"Bearer {inst_token}"},
        )
        assert rep_res.status_code == 200
        rep_data = rep_res.json()
        assert rep_data["filename"] == "land_deed_corrected.pdf"
        assert rep_data["findings_created"] > 0

        # Old file should be unlinked
        assert not old_path.exists()

        # New file exists on disk
        with SessionLocal() as db:
            updated_doc = db.get(DocModel, doc_id)
            assert updated_doc.original_name == "land_deed_corrected.pdf"
            new_path = UPLOAD_DIR / updated_doc.stored_name
            assert new_path.exists()
            assert new_path != old_path
            # Check findings are present and linked to this doc
            assert db.query(FindingModel).filter(FindingModel.document_id == doc_id).count() > 0

    def test_cannot_remove_or_replace_on_locked_application(self):
        inst_token = login_token("institution@example.com", "DemoInstitution123!")

        app_res = client.post(
            "/api/applications",
            json={"institution_name": "Locked Application College", "academic_year": "2026-27"},
            headers={"Authorization": f"Bearer {inst_token}"},
        )
        app_id = app_res.json()["id"]

        pdf = make_valid_pdf("Mandatory curriculum document")
        up_res = client.post(
            f"/api/applications/{app_id}/documents",
            files={"file": ("curriculum.pdf", pdf, "application/pdf")},
            headers={"Authorization": f"Bearer {inst_token}"},
        )
        doc_id = up_res.json()["document_id"]

        # Transition to UNDER_REVIEW (locks document modification)
        sub_res = client.patch(
            f"/api/applications/{app_id}/status",
            json={"status": "UNDER_REVIEW"},
            headers={"Authorization": f"Bearer {inst_token}"},
        )
        assert sub_res.status_code == 200

        # Attempt to delete document -> 409 Conflict
        del_res = client.delete(
            f"/api/applications/{app_id}/documents/{doc_id}",
            headers={"Authorization": f"Bearer {inst_token}"},
        )
        assert del_res.status_code == 409
        assert "locked" in del_res.json()["detail"].lower()

        # Attempt to replace document -> 409 Conflict
        pdf2 = make_valid_pdf("New replacement attempt")
        rep_res = client.put(
            f"/api/applications/{app_id}/documents/{doc_id}",
            files={"file": ("new.pdf", pdf2, "application/pdf")},
            headers={"Authorization": f"Bearer {inst_token}"},
        )
        assert rep_res.status_code == 409
        assert "locked" in rep_res.json()["detail"].lower()

    def test_safe_unlink_preserves_shared_file_references(self):
        """safe_unlink_stored_file does not unlink files while an active document record in the database references it."""
        from app.main import UPLOAD_DIR, SessionLocal, safe_unlink_stored_file
        from app.models import Document as DocModel

        inst_token = login_token("institution@example.com", "DemoInstitution123!")
        app_res = client.post(
            "/api/applications",
            json={"institution_name": "Shared Storage Academy", "academic_year": "2026-27"},
            headers={"Authorization": f"Bearer {inst_token}"},
        )
        app_id = app_res.json()["id"]

        pdf = make_valid_pdf("Shared storage test file")
        up_res = client.post(
            f"/api/applications/{app_id}/documents",
            files={"file": ("original.pdf", pdf, "application/pdf")},
            headers={"Authorization": f"Bearer {inst_token}"},
        )
        doc_id = up_res.json()["document_id"]

        with SessionLocal() as db:
            doc = db.get(DocModel, doc_id)
            stored_name = doc.stored_name
            file_path = UPLOAD_DIR / stored_name
            assert file_path.exists()

            # Attempt unlink while excluding another ID (so doc_id is still seen as an active reference in DB)
            unlinked = safe_unlink_stored_file(db, stored_name, excluding_doc_ids=[doc_id + 9999])
            assert unlinked is False
            assert file_path.exists()

            # Now unlink excluding doc_id (no remaining active references)
            unlinked_now = safe_unlink_stored_file(db, stored_name, excluding_doc_ids=[doc_id])
            assert unlinked_now is True
            assert not file_path.exists()


# ===========================================================================
# 11. Role-Specific Officer and Admin Permissions & Governance
# ===========================================================================
class TestRoleSpecificOfficerAndAdminPermissions:
    def test_list_officers_endpoint_permissions(self):
        admin_token = login_token("admin@example.com", "DemoAdmin123!")
        off_token = login_token("officer@example.com", "DemoOfficer123!")
        inst_token = login_token("institution@example.com", "DemoInstitution123!")

        # Admin can list active officers
        admin_res = client.get("/api/officers", headers={"Authorization": f"Bearer {admin_token}"})
        assert admin_res.status_code == 200
        officers = admin_res.json()
        assert isinstance(officers, list)
        assert len(officers) >= 1
        assert any(o["email"] == "officer@example.com" for o in officers)
        assert all("id" in o and "name" in o and "email" in o for o in officers)

        # Officer can list active officers
        off_res = client.get("/api/officers", headers={"Authorization": f"Bearer {off_token}"})
        assert off_res.status_code == 200
        assert len(off_res.json()) >= 1

        # Institution CANNOT list officers
        inst_res = client.get("/api/officers", headers={"Authorization": f"Bearer {inst_token}"})
        assert inst_res.status_code == 403

    def test_admin_assignment_governance(self):
        admin_token = login_token("admin@example.com", "DemoAdmin123!")
        inst_token = login_token("institution@example.com", "DemoInstitution123!")
        off_token = login_token("officer@example.com", "DemoOfficer123!")
        off_id = client.get("/api/auth/me", headers={"Authorization": f"Bearer {off_token}"}).json()["id"]

        # 1. Institution creates application
        app_res = client.post(
            "/api/applications",
            json={"institution_name": "Admin Governance College", "academic_year": "2026-27"},
            headers={"Authorization": f"Bearer {inst_token}"},
        )
        app_id = app_res.json()["id"]

        # 2. Cannot assign draft application -> 409
        assign_draft = client.patch(
            f"/api/applications/{app_id}/assign",
            json={"officer_id": off_id},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert assign_draft.status_code == 409

        # Submit application
        client.patch(
            f"/api/applications/{app_id}/status",
            json={"status": "UNDER_REVIEW"},
            headers={"Authorization": f"Bearer {inst_token}"},
        )

        # 3. Admin cannot assign invalid/non-officer user
        inst_id = client.get("/api/auth/me", headers={"Authorization": f"Bearer {inst_token}"}).json()["id"]
        bad_assign = client.patch(
            f"/api/applications/{app_id}/assign",
            json={"officer_id": inst_id},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert bad_assign.status_code == 400

        # 4. Admin assigns active officer -> 200 with officer name
        good_assign = client.patch(
            f"/api/applications/{app_id}/assign",
            json={"officer_id": off_id},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert good_assign.status_code == 200
        assert good_assign.json()["assigned_officer_id"] == off_id
        assert good_assign.json()["assigned_officer_name"] is not None

        # 5. Detail reflects assigned officer name
        detail = client.get(f"/api/applications/{app_id}", headers={"Authorization": f"Bearer {admin_token}"}).json()
        assert detail["application"]["assigned_officer_id"] == off_id
        assert detail["application"]["assigned_officer_name"] == good_assign.json()["assigned_officer_name"]

        # 6. Admin unassigns application -> 200 with None
        unassign = client.patch(
            f"/api/applications/{app_id}/assign",
            json={"officer_id": None},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert unassign.status_code == 200
        assert unassign.json()["assigned_officer_id"] is None
        assert unassign.json()["assigned_officer_name"] is None

    def test_officer_claim_and_release_lifecycle(self):
        admin_token = login_token("admin@example.com", "DemoAdmin123!")
        inst_token = login_token("institution@example.com", "DemoInstitution123!")
        off1_token = login_token("officer@example.com", "DemoOfficer123!")
        off1_id = client.get("/api/auth/me", headers={"Authorization": f"Bearer {off1_token}"}).json()["id"]

        # Ensure officer2 exists
        client.post(
            "/api/admin/users",
            json={"email": "officer2@example.com", "name": "Officer Two", "password": "Password123!", "role": "officer"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        off2_token = login_token("officer2@example.com", "Password123!")
        off2_id = client.get("/api/auth/me", headers={"Authorization": f"Bearer {off2_token}"}).json()["id"]

        app_res = client.post(
            "/api/applications",
            json={"institution_name": "Claim Release Academy", "academic_year": "2026-27"},
            headers={"Authorization": f"Bearer {inst_token}"},
        )
        app_id = app_res.json()["id"]

        client.patch(
            f"/api/applications/{app_id}/status",
            json={"status": "UNDER_REVIEW"},
            headers={"Authorization": f"Bearer {inst_token}"},
        )

        # Officer 1 claims application
        claim1 = client.patch(
            f"/api/applications/{app_id}/assign",
            json={"officer_id": off1_id},
            headers={"Authorization": f"Bearer {off1_token}"},
        )
        assert claim1.status_code == 200
        assert claim1.json()["assigned_officer_id"] == off1_id

        # Officer 1 cannot assign another officer
        assign_other = client.patch(
            f"/api/applications/{app_id}/assign",
            json={"officer_id": off2_id},
            headers={"Authorization": f"Bearer {off1_token}"},
        )
        assert assign_other.status_code == 403

        # Officer 1 releases assignment
        release1 = client.patch(
            f"/api/applications/{app_id}/assign",
            json={"officer_id": None},
            headers={"Authorization": f"Bearer {off1_token}"},
        )
        assert release1.status_code == 200
        assert release1.json()["assigned_officer_id"] is None

        # Now Officer 2 can claim it
        claim2 = client.patch(
            f"/api/applications/{app_id}/assign",
            json={"officer_id": off2_id},
            headers={"Authorization": f"Bearer {off2_token}"},
        )
        assert claim2.status_code == 200
        assert claim2.json()["assigned_officer_id"] == off2_id

    def test_unassigned_officer_restrictions(self):
        inst_token = login_token("institution@example.com", "DemoInstitution123!")
        off_token = login_token("officer@example.com", "DemoOfficer123!")

        app_res = client.post(
            "/api/applications",
            json={"institution_name": "Unassigned Restriction College", "academic_year": "2026-27"},
            headers={"Authorization": f"Bearer {inst_token}"},
        )
        app_id = app_res.json()["id"]

        client.patch(
            f"/api/applications/{app_id}/status",
            json={"status": "UNDER_REVIEW"},
            headers={"Authorization": f"Bearer {inst_token}"},
        )

        # Unassigned officer CANNOT update status
        st_res = client.patch(
            f"/api/applications/{app_id}/status",
            json={"status": "DEFICIENCY_RAISED"},
            headers={"Authorization": f"Bearer {off_token}"},
        )
        assert st_res.status_code == 403

        # Unassigned officer CANNOT create review
        rev_res = client.post(
            f"/api/applications/{app_id}/reviews",
            json={"action": "REVIEW_NOTE", "notes": "Premature unassigned review"},
            headers={"Authorization": f"Bearer {off_token}"},
        )
        assert rev_res.status_code == 403

        # Unassigned officer CANNOT upload evidence
        png = make_valid_png()
        ev_res = client.post(
            f"/api/applications/{app_id}/officer-evidence",
            files={"file": ("evidence.png", png, "image/png")},
            headers={"Authorization": f"Bearer {off_token}"},
        )
        assert ev_res.status_code == 403

        # Unassigned officer CANNOT generate memo
        memo_res = client.post(
            f"/api/applications/{app_id}/memo",
            headers={"Authorization": f"Bearer {off_token}"},
        )
        assert memo_res.status_code == 403

    def test_admin_administrative_workflow_closure(self):
        admin_token = login_token("admin@example.com", "DemoAdmin123!")
        inst_token = login_token("institution@example.com", "DemoInstitution123!")

        app_res = client.post(
            "/api/applications",
            json={"institution_name": "Admin Workflow Close College", "academic_year": "2026-27"},
            headers={"Authorization": f"Bearer {inst_token}"},
        )
        app_id = app_res.json()["id"]

        client.patch(
            f"/api/applications/{app_id}/status",
            json={"status": "UNDER_REVIEW"},
            headers={"Authorization": f"Bearer {inst_token}"},
        )

        # Admin can administratively close the workflow
        close_res = client.patch(
            f"/api/applications/{app_id}/status",
            json={"status": "CLOSED"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert close_res.status_code == 200
        assert close_res.json()["status"] == "CLOSED"

    def test_system_compliance_and_prescreening_metadata(self):
        admin_token = login_token("admin@example.com", "DemoAdmin123!")
        inst_token = login_token("institution@example.com", "DemoInstitution123!")

        # Health endpoint transparency
        h_res = client.get("/api/health")
        assert h_res.status_code == 200
        h_data = h_res.json()
        assert h_data["mode"] == "pre-screening"
        assert h_data["live_aicte_integration"] is False
        assert h_data["officer_assignment_model"] == "assigned_officer_enforced"

        # Application detail transparency
        app_res = client.post(
            "/api/applications",
            json={"institution_name": "Metadata Check College", "academic_year": "2026-27"},
            headers={"Authorization": f"Bearer {inst_token}"},
        )
        app_id = app_res.json()["id"]

        client.patch(
            f"/api/applications/{app_id}/status",
            json={"status": "UNDER_REVIEW"},
            headers={"Authorization": f"Bearer {inst_token}"},
        )

        detail_res = client.get(
            f"/api/applications/{app_id}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert detail_res.status_code == 200
        d_data = detail_res.json()
        assert d_data["live_issuer_verification"] == "NOT_CONFIGURED"
        assert "Heuristic triage score" in d_data["risk_score_note"]

