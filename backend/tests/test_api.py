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
    def test_draft_applications_visible_only_to_owning_institution(self):
        """
        Enforce strict draft privacy:
        - Owning institution can see its own drafts in listing and detail.
        - Other institutions CANNOT see the draft in listing or detail.
        - Neither Officers nor Admins can see drafts in listing (even with ?include_drafts=true).
        - Neither Officers nor Admins can access draft detail, download draft documents,
          assign officers, review, or change status on drafts.
        """
        admin_token = login_token("admin@example.com", "DemoAdmin123!")
        inst_token = login_token("institution@example.com", "DemoInstitution123!")
        off_token = login_token("officer@example.com", "DemoOfficer123!")

        # Ensure second institution exists
        client.post(
            "/api/admin/users",
            json={"email": "inst2@example.com", "name": "Second Institution", "password": "Password123!", "role": "institution"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        inst2_token = login_token("inst2@example.com", "Password123!")

        # 1. Institution creates draft application
        app_res = client.post(
            "/api/applications",
            json={"institution_name": "Private Draft Academy", "academic_year": "2026-27"},
            headers={"Authorization": f"Bearer {inst_token}"},
        )
        assert app_res.status_code == 200
        app_id = app_res.json()["id"]
        assert app_res.json()["status"] == "DRAFT"

        # 2. Institution uploads a document to draft
        pdf = make_valid_pdf("Draft syllabus content")
        up_res = client.post(
            f"/api/applications/{app_id}/documents",
            files={"file": ("draft_doc.pdf", pdf, "application/pdf")},
            headers={"Authorization": f"Bearer {inst_token}"},
        )
        assert up_res.status_code == 200
        doc_id = up_res.json()["document_id"]

        # 3. Owner institution CAN view its own draft in listing and detail
        owner_list = client.get("/api/applications", headers={"Authorization": f"Bearer {inst_token}"}).json()
        assert any(a["id"] == app_id for a in owner_list)
        owner_detail = client.get(f"/api/applications/{app_id}", headers={"Authorization": f"Bearer {inst_token}"})
        assert owner_detail.status_code == 200
        assert owner_detail.json()["application"]["status"] == "DRAFT"

        # 4. Other institution (inst2) CANNOT see draft in listing, detail, or document download
        inst2_list = client.get("/api/applications", headers={"Authorization": f"Bearer {inst2_token}"}).json()
        assert not any(a["id"] == app_id for a in inst2_list)
        inst2_detail = client.get(f"/api/applications/{app_id}", headers={"Authorization": f"Bearer {inst2_token}"})
        assert inst2_detail.status_code == 404
        inst2_dl = client.get(f"/api/applications/{app_id}/documents/{doc_id}/download", headers={"Authorization": f"Bearer {inst2_token}"})
        assert inst2_dl.status_code in (403, 404)

        # 5. Officer CANNOT see draft in listing, with or without query params
        off_list = client.get("/api/applications", headers={"Authorization": f"Bearer {off_token}"}).json()
        assert not any(a["id"] == app_id for a in off_list)
        off_list_query = client.get("/api/applications?include_drafts=true", headers={"Authorization": f"Bearer {off_token}"}).json()
        assert not any(a["id"] == app_id for a in off_list_query)

        # 6. Officer detail, download, assign, review, evidence upload on draft MUST return 404/409
        assert client.get(f"/api/applications/{app_id}", headers={"Authorization": f"Bearer {off_token}"}).status_code == 404
        assert client.get(f"/api/applications/{app_id}/documents/{doc_id}/download", headers={"Authorization": f"Bearer {off_token}"}).status_code == 404

        off_info = client.get("/api/auth/me", headers={"Authorization": f"Bearer {off_token}"}).json()
        assert client.patch(
            f"/api/applications/{app_id}/assign",
            json={"officer_id": off_info["id"]},
            headers={"Authorization": f"Bearer {off_token}"},
        ).status_code in (404, 409)

        assert client.post(
            f"/api/applications/{app_id}/reviews",
            json={"action": "REVIEW_NOTE", "notes": "Premature review attempt"},
            headers={"Authorization": f"Bearer {off_token}"},
        ).status_code in (404, 409)

        assert client.post(
            f"/api/applications/{app_id}/officer-evidence",
            files={"file": ("ev.pdf", pdf, "application/pdf")},
            headers={"Authorization": f"Bearer {off_token}"},
        ).status_code in (404, 409)

        # 7. Admin CANNOT see draft in listing, with or without include_drafts query param
        admin_list = client.get("/api/applications", headers={"Authorization": f"Bearer {admin_token}"}).json()
        assert not any(a["id"] == app_id for a in admin_list)

        admin_list_oversight = client.get("/api/applications?include_drafts=true", headers={"Authorization": f"Bearer {admin_token}"}).json()
        assert not any(a["id"] == app_id for a in admin_list_oversight)

        # 8. Admin CANNOT access draft detail or download draft documents
        assert client.get(f"/api/applications/{app_id}", headers={"Authorization": f"Bearer {admin_token}"}).status_code == 404
        assert client.get(f"/api/applications/{app_id}/documents/{doc_id}/download", headers={"Authorization": f"Bearer {admin_token}"}).status_code == 404

        # 9. Admin CANNOT assign, review, or modify draft application
        assert client.patch(
            f"/api/applications/{app_id}/assign",
            json={"officer_id": off_info["id"]},
            headers={"Authorization": f"Bearer {admin_token}"},
        ).status_code in (404, 409)

        assert client.post(
            f"/api/applications/{app_id}/reviews",
            json={"action": "REVIEW_NOTE", "notes": "Admin review on draft"},
            headers={"Authorization": f"Bearer {admin_token}"},
        ).status_code in (404, 409)

        assert client.patch(
            f"/api/applications/{app_id}/status",
            json={"status": "UNDER_REVIEW"},
            headers={"Authorization": f"Bearer {admin_token}"},
        ).status_code in (403, 404)


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

        # 2. Cannot assign draft application -> 404 or 409
        assign_draft = client.patch(
            f"/api/applications/{app_id}/assign",
            json={"officer_id": off_id},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert assign_draft.status_code in (404, 409)

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


# ===========================================================================
# 13. Deficiency Memo Assistant Tests
# ===========================================================================
class TestDeficiencyMemoAssistant:
    def test_memo_access_control(self):
        admin_token = login_token("admin@example.com", "DemoAdmin123!")
        inst_token = login_token("institution@example.com", "DemoInstitution123!")
        off_token = login_token("officer@example.com", "DemoOfficer123!")
        off_id = client.get("/api/auth/me", headers={"Authorization": f"Bearer {off_token}"}).json()["id"]

        # Ensure officer2 exists
        client.post(
            "/api/admin/users",
            json={"email": "off_memo2@example.com", "name": "Officer Memo Two", "password": "Password123!", "role": "officer"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        off2_token = login_token("off_memo2@example.com", "Password123!")

        # 1. Institution creates draft
        app_res = client.post(
            "/api/applications",
            json={"institution_name": "Memo Security Institute", "academic_year": "2026-27"},
            headers={"Authorization": f"Bearer {inst_token}"},
        )
        app_id = app_res.json()["id"]

        # 2. Institution cannot call /memo endpoint -> 403
        inst_memo = client.post(f"/api/applications/{app_id}/memo", headers={"Authorization": f"Bearer {inst_token}"})
        assert inst_memo.status_code == 403

        # 3. Cannot generate memo on draft application -> 404 for officer (draft is hidden) or 409
        off_draft_memo = client.post(f"/api/applications/{app_id}/memo", headers={"Authorization": f"Bearer {off_token}"})
        assert off_draft_memo.status_code in (404, 409)

        # 4. Submit application
        client.patch(
            f"/api/applications/{app_id}/status",
            json={"status": "UNDER_REVIEW"},
            headers={"Authorization": f"Bearer {inst_token}"},
        )

        # 5. Unassigned officer cannot generate memo -> 403
        unassigned_memo = client.post(f"/api/applications/{app_id}/memo", headers={"Authorization": f"Bearer {off_token}"})
        assert unassigned_memo.status_code == 403

        # 6. Assign to off_id
        client.patch(
            f"/api/applications/{app_id}/assign",
            json={"officer_id": off_id},
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        # 7. Other officer (off2) cannot access or generate memo -> 403 or 404 (due to assignment isolation)
        other_officer_memo = client.post(f"/api/applications/{app_id}/memo", headers={"Authorization": f"Bearer {off2_token}"})
        assert other_officer_memo.status_code in (403, 404)

        # 8. Assigned officer can generate memo -> 200
        assigned_memo = client.post(f"/api/applications/{app_id}/memo", headers={"Authorization": f"Bearer {off_token}"})
        assert assigned_memo.status_code == 200
        data = assigned_memo.json()
        assert "memo" in data
        assert "disclaimer" in data
        assert "status" in data

        # 9. Admin can also generate memo -> 200
        admin_memo = client.post(f"/api/applications/{app_id}/memo", headers={"Authorization": f"Bearer {admin_token}"})
        assert admin_memo.status_code == 200

    def test_memo_contains_required_sections_and_grounded_findings(self):
        admin_token = login_token("admin@example.com", "DemoAdmin123!")
        inst_token = login_token("institution@example.com", "DemoInstitution123!")
        off_token = login_token("officer@example.com", "DemoOfficer123!")
        off_id = client.get("/api/auth/me", headers={"Authorization": f"Bearer {off_token}"}).json()["id"]

        # Create application with detailed metadata
        app_res = client.post(
            "/api/applications",
            json={
                "institution_name": "Apex Engineering Institute",
                "institution_code": "APEX-ENG-777",
                "application_type": "Extension of Approval",
                "academic_year": "2026-27",
                "programme": "Engineering and Technology",
                "current_intake": 120,
                "proposed_intake": 180,
            },
            headers={"Authorization": f"Bearer {inst_token}"},
        )
        app_id = app_res.json()["id"]

        # Upload document that creates findings
        pdf = make_valid_pdf("Land ownership document with partial registration survey number")
        client.post(
            f"/api/applications/{app_id}/documents",
            files={"file": ("land_record.pdf", pdf, "application/pdf")},
            headers={"Authorization": f"Bearer {inst_token}"},
        )

        # Submit and assign
        client.patch(
            f"/api/applications/{app_id}/status",
            json={"status": "UNDER_REVIEW"},
            headers={"Authorization": f"Bearer {inst_token}"},
        )
        client.patch(
            f"/api/applications/{app_id}/assign",
            json={"officer_id": off_id},
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        res = client.post(f"/api/applications/{app_id}/memo", headers={"Authorization": f"Bearer {off_token}"})
        assert res.status_code == 200
        data = res.json()
        memo_text = data["memo"]

        # Verify Header & Metadata
        assert "AICTE Compliance Pre-Screening Deficiency Memorandum (Draft)" in memo_text
        assert "Apex Engineering Institute" in memo_text
        assert "APEX-ENG-777" in memo_text
        assert f"AICTE-APP-{app_id:06d}" in memo_text
        assert "Engineering and Technology" in memo_text
        assert "120 / 180" in memo_text

        # Verify Section 1: Identified Deficiencies
        assert "### 1. Identified Deficiencies & Flagged Pre-Screening Checks" in memo_text

        # Verify Section 2: Specific Grounded Correction Instructions
        assert "### 2. Specific Grounded Correction Instructions" in memo_text
        assert "Rectification Timeline:" in memo_text
        assert "official AICTE approval process calendar" in memo_text

        # Verify Section 3: Compliance Officer Scrutiny & Determination Block
        assert "### 3. Compliance Officer Scrutiny & Determination Block" in memo_text
        assert "Officer Determination:" in memo_text
        assert "Officer Signature & Seal:" in memo_text

        # Verify Regulatory Disclaimers & Non-Official Marking
        assert "Decision-support draft only" in memo_text
        assert "Does NOT constitute an official AICTE regulatory decision" in memo_text
        assert data["disclaimer"] is not None

    def test_memo_clean_state_without_deficiencies(self):
        admin_token = login_token("admin@example.com", "DemoAdmin123!")
        inst_token = login_token("institution@example.com", "DemoInstitution123!")
        off_token = login_token("officer@example.com", "DemoOfficer123!")
        off_id = client.get("/api/auth/me", headers={"Authorization": f"Bearer {off_token}"}).json()["id"]

        # Create clean application without documents/deficiencies
        app_res = client.post(
            "/api/applications",
            json={"institution_name": "Pristine Compliance College", "academic_year": "2026-27"},
            headers={"Authorization": f"Bearer {inst_token}"},
        )
        app_id = app_res.json()["id"]

        client.patch(
            f"/api/applications/{app_id}/status",
            json={"status": "UNDER_REVIEW"},
            headers={"Authorization": f"Bearer {inst_token}"},
        )
        client.patch(
            f"/api/applications/{app_id}/assign",
            json={"officer_id": off_id},
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        res = client.post(f"/api/applications/{app_id}/memo", headers={"Authorization": f"Bearer {off_token}"})
        assert res.status_code == 200
        memo_text = res.json()["memo"]

        assert "No regulatory deficiencies or check failures were flagged" in memo_text
        assert "No specific document rectifications are currently required" in memo_text
        assert "### 3. Compliance Officer Scrutiny & Determination Block" in memo_text

    def test_memo_deterministic_fallback_when_unconfigured(self, monkeypatch):
        from app.config import settings
        admin_token = login_token("admin@example.com", "DemoAdmin123!")
        inst_token = login_token("institution@example.com", "DemoInstitution123!")
        off_token = login_token("officer@example.com", "DemoOfficer123!")
        off_id = client.get("/api/auth/me", headers={"Authorization": f"Bearer {off_token}"}).json()["id"]

        app_res = client.post(
            "/api/applications",
            json={"institution_name": "Fallback Test Academy", "academic_year": "2026-27"},
            headers={"Authorization": f"Bearer {inst_token}"},
        )
        app_id = app_res.json()["id"]
        client.patch(f"/api/applications/{app_id}/status", json={"status": "UNDER_REVIEW"}, headers={"Authorization": f"Bearer {inst_token}"})
        client.patch(f"/api/applications/{app_id}/assign", json={"officer_id": off_id}, headers={"Authorization": f"Bearer {admin_token}"})

        # Monkeypatch GEMINI_API_KEY to empty string
        monkeypatch.setattr(settings, "gemini_api_key", "")

        res = client.post(f"/api/applications/{app_id}/memo", headers={"Authorization": f"Bearer {off_token}"})
        assert res.status_code == 200
        data = res.json()
        assert data["ai_assisted"] is False
        assert data["is_fallback"] is True
        assert data["status"] == "fallback"
        assert "GEMINI_API_KEY is not configured" in data["fallback_reason"]
        assert len(data["memo"]) > 100
        assert "### 1. Identified Deficiencies & Flagged Pre-Screening Checks" in data["memo"]

    def test_memo_fallback_on_gemini_truncation_or_error(self, monkeypatch):
        from app import services
        from unittest.mock import MagicMock
        from app.config import settings

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "candidates": [
                {
                    "finishReason": "MAX_TOKENS",
                    "content": {"parts": [{"text": "DATE: [Current date]"}]}
                }
            ]
        }

        monkeypatch.setattr("httpx.post", lambda *args, **kwargs: mock_response)
        monkeypatch.setattr(settings, "gemini_api_key", "test-key-12345")

        app_dict = {"id": 101, "institution_name": "Truncation Test College", "assigned_officer_name": "Demo Officer"}
        result = services.gemini_memo(app_dict, [])
        assert result["is_fallback"] is True
        assert result["ai_assisted"] is False
        assert "incomplete or truncated" in result["fallback_reason"] or "MAX_TOKENS" in result["fallback_reason"]
        assert "### 1. Identified Deficiencies & Flagged Pre-Screening Checks" in result["memo"]

    def test_memo_transient_503_retry_success(self, monkeypatch):
        from app import services
        from unittest.mock import MagicMock
        from app.config import settings

        attempts = []

        def mock_post(url, **kwargs):
            attempts.append(url)
            mock_res = MagicMock()
            if len(attempts) == 1:
                mock_res.status_code = 503
                mock_res.json.return_value = {"error": {"message": "Model overloaded"}}
                mock_res.text = "Model overloaded"
                return mock_res
            else:
                mock_res.status_code = 200
                mock_res.json.return_value = {
                    "candidates": [
                        {
                            "finishReason": "STOP",
                            "content": {
                                "parts": [
                                    {"text": "# AICTE Compliance Pre-Screening Deficiency Memorandum (Draft)\n\nThis memorandum summarizes identified deficiencies grounded strictly in pre-screening findings.\n\nAll pre-screening checks scrutinized. Compliance officer scrutiny and determination are required."}
                                ]
                            },
                        }
                    ]
                }
                return mock_res

        monkeypatch.setattr("httpx.post", mock_post)
        monkeypatch.setattr(settings, "gemini_api_key", "test-key-safe")
        monkeypatch.setattr(settings, "gemini_max_retries", 2)

        app_dict = {"id": 102, "institution_name": "Retry Success Academy", "assigned_officer_name": "Officer Test"}
        result = services.gemini_memo(app_dict, [], sleep_fn=lambda _: None)

        assert len(attempts) == 2  # 1 initial + 1 retry
        assert result["ai_assisted"] is True
        assert result["is_fallback"] is False
        assert result["status"] == "success"
        assert "AICTE Compliance Pre-Screening Deficiency Memorandum" in result["memo"]

    def test_memo_transient_503_exhausts_retries_deterministic_fallback(self, monkeypatch):
        from app import services
        from unittest.mock import MagicMock
        from app.config import settings

        attempts = []

        def mock_post(url, **kwargs):
            attempts.append(url)
            mock_res = MagicMock()
            mock_res.status_code = 503
            mock_res.json.return_value = {"error": {"message": "Service Unavailable"}}
            mock_res.text = "Service Unavailable"
            return mock_res

        monkeypatch.setattr("httpx.post", mock_post)
        monkeypatch.setattr(settings, "gemini_api_key", "test-key-safe")
        monkeypatch.setattr(settings, "gemini_model", "gemini-2.5-flash")
        monkeypatch.setattr(settings, "gemini_fallback_model", "")
        monkeypatch.setattr(settings, "gemini_max_retries", 2)

        app_dict = {"id": 103, "institution_name": "503 Fallback Academy", "assigned_officer_name": "Officer Test"}
        result = services.gemini_memo(app_dict, [], sleep_fn=lambda _: None)

        assert len(attempts) == 3  # initial + 2 retries
        assert result["ai_assisted"] is False
        assert result["is_fallback"] is True
        assert result["status"] == "fallback"
        assert "503" in result["fallback_reason"]
        assert "### 1. Identified Deficiencies & Flagged Pre-Screening Checks" in result["memo"]

    def test_memo_503_fallback_model_success(self, monkeypatch):
        from app import services
        from unittest.mock import MagicMock
        from app.config import settings

        model_calls = []

        def mock_post(url, **kwargs):
            model_calls.append(url)
            mock_res = MagicMock()
            if "gemini-2.5-flash" in url:
                mock_res.status_code = 503
                mock_res.json.return_value = {"error": {"message": "Primary model unavailable"}}
                mock_res.text = "Primary model unavailable"
                return mock_res
            elif "gemini-2.0-flash" in url:
                mock_res.status_code = 200
                mock_res.json.return_value = {
                    "candidates": [
                        {
                            "finishReason": "STOP",
                            "content": {
                                "parts": [
                                    {"text": "# AICTE Fallback Memorandum\n\nSuccessfully generated via configured fallback model after primary 503 error.\n\nAll pre-screening checks have been systematically reviewed and noted for officer determination."}
                                ]
                            },
                        }
                    ]
                }
                return mock_res
            mock_res.status_code = 500
            return mock_res

        monkeypatch.setattr("httpx.post", mock_post)
        monkeypatch.setattr(settings, "gemini_api_key", "test-key-safe")
        monkeypatch.setattr(settings, "gemini_model", "gemini-2.5-flash")
        monkeypatch.setattr(settings, "gemini_fallback_model", "gemini-2.0-flash")
        monkeypatch.setattr(settings, "gemini_max_retries", 1)  # 1 retry on primary, then fallback

        app_dict = {"id": 104, "institution_name": "Fallback Model College", "assigned_officer_name": "Officer Test"}
        result = services.gemini_memo(app_dict, [], sleep_fn=lambda _: None)

        # Primary was called 2 times (initial + 1 retry), then fallback was called 1 time and succeeded
        assert any("gemini-2.5-flash" in u for u in model_calls)
        assert any("gemini-2.0-flash" in u for u in model_calls)
        assert result["ai_assisted"] is True
        assert result["is_fallback"] is False
        assert result["status"] == "success"
        assert "AICTE Fallback Memorandum" in result["memo"]

    def test_memo_non_retryable_error_no_retry(self, monkeypatch):
        from app import services
        from unittest.mock import MagicMock
        from app.config import settings

        attempts = []

        def mock_post(url, **kwargs):
            attempts.append(url)
            mock_res = MagicMock()
            mock_res.status_code = 403
            mock_res.json.return_value = {"error": {"message": "API_KEY_INVALID: API key not valid"}}
            mock_res.text = "API_KEY_INVALID"
            return mock_res

        monkeypatch.setattr("httpx.post", mock_post)
        monkeypatch.setattr(settings, "gemini_api_key", "invalid-key")
        monkeypatch.setattr(settings, "gemini_fallback_model", "gemini-other")
        monkeypatch.setattr(settings, "gemini_max_retries", 3)

        app_dict = {"id": 105, "institution_name": "No Retry College", "assigned_officer_name": "Officer Test"}
        result = services.gemini_memo(app_dict, [], sleep_fn=lambda _: None)

        # Non-retryable error (403 invalid key): MUST NOT retry and MUST NOT call fallback model
        assert len(attempts) == 1
        assert result["ai_assisted"] is False
        assert result["is_fallback"] is True
        assert "403" in result["fallback_reason"]

    def test_memo_read_timeout_retry_success(self, monkeypatch):
        import httpx
        from app import services
        from unittest.mock import MagicMock
        from app.config import settings

        attempts = []

        def mock_post(url, **kwargs):
            attempts.append(url)
            if len(attempts) == 1:
                raise httpx.ReadTimeout("Connection read timed out while waiting for Gemini")
            mock_res = MagicMock()
            mock_res.status_code = 200
            mock_res.json.return_value = {
                "candidates": [
                    {
                        "finishReason": "STOP",
                        "content": {
                            "parts": [
                                {"text": "# AICTE Pre-Screening Memorandum\n\nSuccessfully generated on retry after transient read timeout occurred.\n\nAll pre-screening checks have been systematically reviewed and noted for compliance officer determination."}
                            ]
                        },
                    }
                ]
            }
            return mock_res

        monkeypatch.setattr("httpx.post", mock_post)
        monkeypatch.setattr(settings, "gemini_api_key", "test-key-safe")
        monkeypatch.setattr(settings, "gemini_max_retries", 2)

        app_dict = {"id": 106, "institution_name": "Timeout Retry College", "assigned_officer_name": "Officer Test"}
        result = services.gemini_memo(app_dict, [], sleep_fn=lambda _: None)

        assert len(attempts) == 2  # 1st timed out, 2nd succeeded
        assert result["ai_assisted"] is True
        assert result["is_fallback"] is False
        assert "AICTE Pre-Screening Memorandum" in result["memo"]

    def test_safe_logging_never_exposes_api_key(self):
        from app.services import _sanitize_log_message, _extract_safe_response_error
        from unittest.mock import MagicMock

        secret = "AIzaSySecretKey999"
        msg_with_key = f"Error calling url https://api.google.com?key={secret} - failed"
        sanitized = _sanitize_log_message(msg_with_key, secret)
        assert secret not in sanitized
        assert "[REDACTED]" in sanitized

        mock_res = MagicMock()
        mock_res.json.side_effect = Exception("not json")
        mock_res.text = f"Invalid key: {secret}"
        safe_err = _extract_safe_response_error(mock_res, secret)
        assert secret not in safe_err
        assert "[REDACTED]" in safe_err

    def test_memo_unverified_model_fails_fast_without_network_call(self, monkeypatch):
        from app import services
        from unittest.mock import MagicMock
        from app.config import settings

        network_calls = []

        def mock_post(url, **kwargs):
            network_calls.append(url)
            return MagicMock(status_code=200)

        monkeypatch.setattr("httpx.post", mock_post)
        monkeypatch.setattr(settings, "gemini_api_key", "test-key-safe")
        # Configure the exact unverified model from the user's issue
        monkeypatch.setattr(settings, "gemini_model", "gemini-3.5-flash-lite")
        monkeypatch.setattr(settings, "gemini_fallback_model", "")

        app_dict = {"id": 107, "institution_name": "Unverified Model College", "assigned_officer_name": "Officer Test"}
        result = services.gemini_memo(app_dict, [], sleep_fn=lambda _: None)

        # MUST NOT make network calls to unverified models
        assert len(network_calls) == 0
        assert result["ai_assisted"] is False
        assert result["is_fallback"] is True
        assert result["status"] == "fallback"
        assert "gemini-3.5-flash-lite" in result["fallback_reason"]
        assert "not in Google's supported Gemini model list" in result["fallback_reason"]
        assert "### 1. Identified Deficiencies & Flagged Pre-Screening Checks" in result["memo"]

    def test_memo_read_timeout_exhausts_retries_deterministic_fallback(self, monkeypatch):
        import httpx
        from app import services
        from app.config import settings

        attempts = []

        def mock_post(url, **kwargs):
            attempts.append(url)
            raise httpx.ReadTimeout("Server took too long to stream response")

        monkeypatch.setattr("httpx.post", mock_post)
        monkeypatch.setattr(settings, "gemini_api_key", "test-key-safe")
        monkeypatch.setattr(settings, "gemini_model", "gemini-2.5-flash")
        monkeypatch.setattr(settings, "gemini_fallback_model", "")
        monkeypatch.setattr(settings, "gemini_max_retries", 1)

        app_dict = {"id": 108, "institution_name": "Persistent Timeout College", "assigned_officer_name": "Officer Test"}
        result = services.gemini_memo(app_dict, [], sleep_fn=lambda _: None)

        # 1 initial + 1 retry = 2 attempts
        assert len(attempts) == 2
        assert result["ai_assisted"] is False
        assert result["is_fallback"] is True
        assert result["status"] == "fallback"
        assert "ReadTimeout" in result["fallback_reason"] or "network timeout" in result["fallback_reason"]
        assert "### 1. Identified Deficiencies & Flagged Pre-Screening Checks" in result["memo"]

    def test_memo_with_dict_list_string_and_missing_evidence(self, monkeypatch):
        """
        Regression test: findings evidence can be a dict, list, string, or None/missing.
        Ensure format_evidence_text and gemini_memo / generate_deterministic_memo
        safely process all evidence types without raising AttributeError: 'dict' object has no attribute 'strip'.
        """
        from app import services
        from unittest.mock import MagicMock
        from app.config import settings

        captured_prompt = []

        def mock_post(url, **kwargs):
            captured_prompt.append(kwargs.get("json", {}))
            mock_res = MagicMock()
            mock_res.status_code = 200
            mock_res.json.return_value = {
                "candidates": [
                    {
                        "finishReason": "STOP",
                        "content": {
                            "parts": [
                                {
                                    "text": "# AICTE Pre-Screening Memorandum\n\nVerified findings with dictionary and structured evidence.\n\nAll pre-screening checks have been systematically reviewed and noted for compliance officer determination."
                                }
                            ]
                        },
                    }
                ]
            }
            return mock_res

        monkeypatch.setattr("httpx.post", mock_post)
        monkeypatch.setattr(settings, "gemini_api_key", "test-key-safe")
        monkeypatch.setattr(settings, "gemini_model", "gemini-2.5-flash")

        diverse_findings = [
            # 1. Dictionary evidence (like DOC-003 duplicate hash check)
            {
                "rule_id": "DOC-003",
                "severity": "medium",
                "result": "NEEDS_REVIEW",
                "message": "Duplicate file hash detected in compliance database",
                "source_reference": "Illustrative rule pack: DOC-003",
                "evidence": {
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "scope": "same_application",
                    "matched_document_id": 42,
                    "matched_filename": "syllabus_duplicate.pdf",
                },
                "document_id": 101,
            },
            # 2. String evidence
            {
                "rule_id": "DOC-001",
                "severity": "low",
                "result": "NEEDS_REVIEW",
                "message": "Document classification requires manual verification",
                "source_reference": "Illustrative rule pack: DOC-001",
                "evidence": "Matched keywords: 'extension of approval', 'aicte approval'",
                "document_id": 102,
            },
            # 3. List evidence
            {
                "rule_id": "DOC-004",
                "severity": "medium",
                "result": "NEEDS_REVIEW",
                "message": "Missing required endorsements",
                "source_reference": "AICTE Handbook clause 4.2",
                "evidence": ["Notarized Stamp Missing", "Authorised Signatory Missing"],
                "document_id": 103,
            },
            # 4. Missing / None evidence
            {
                "rule_id": "DOC-002",
                "severity": "high",
                "result": "NOT_VERIFIED",
                "message": "Issuer authenticity unverified",
                "source_reference": "AICTE Handbook clause 2.1",
                "evidence": None,
                "document_id": 104,
            },
            # 5. Empty dictionary evidence
            {
                "rule_id": "FACULTY-01",
                "severity": "high",
                "result": "FAIL",
                "message": "Cadre ratio does not satisfy 1:2:6 norm",
                "source_reference": "AICTE Approval Process Handbook",
                "evidence": {},
                "document_id": 105,
            },
        ]

        app_dict = {"id": 109, "institution_name": "Multi Type Evidence Institute", "assigned_officer_name": "Officer Test"}
        result = services.gemini_memo(app_dict, diverse_findings, sleep_fn=lambda _: None)

        assert result["ai_assisted"] is True
        assert result["is_fallback"] is False
        assert result["status"] == "success"

        # Verify prompt contained serialized JSON for dict and list evidence
        prompt_text = captured_prompt[0]["contents"][0]["parts"][0]["text"]
        assert "syllabus_duplicate.pdf" in prompt_text
        assert "same_application" in prompt_text
        assert "Notarized Stamp Missing" in prompt_text

        # Verify deterministic fallback memo also formats dict and list evidence without error
        fallback_text = services.generate_deterministic_memo(app_dict, diverse_findings, fallback_reason="Test")
        assert "syllabus_duplicate.pdf" in fallback_text
        assert "Notarized Stamp Missing" in fallback_text
        assert "DOC-003" in fallback_text
        assert "DOC-001" in fallback_text

    def test_format_evidence_text_helper_unit(self):
        from app.services import format_evidence_text

        # None / empty
        assert format_evidence_text(None) == ""
        assert format_evidence_text("") == ""

        # String with whitespace
        assert format_evidence_text("  evidence string  ") == "evidence string"

        # Dictionary with deterministic keys
        d = {"z_key": 1, "a_key": "val"}
        res_d = format_evidence_text(d)
        assert res_d == '{"a_key": "val", "z_key": 1}'

        # List
        lst = ["a", "b"]
        assert format_evidence_text(lst) == '["a", "b"]'

        # Numbers and Booleans
        assert format_evidence_text(123) == "123"
        assert format_evidence_text(True) == "True"

    def test_gemini_startup_log_safe_and_redacts_keys(self, monkeypatch, caplog):
        import logging
        from app.main import log_gemini_startup_configuration
        from app.config import settings

        secret_key = "AIzaSySecretKeyNeverLogMe12345"
        monkeypatch.setattr(settings, "gemini_api_key", secret_key)
        monkeypatch.setattr(settings, "gemini_model", "gemini-3.8-flash")
        monkeypatch.setattr(settings, "gemini_fallback_model", "gemini-2.5-flash")

        with caplog.at_level(logging.INFO):
            result = log_gemini_startup_configuration()

        log_text = caplog.text
        # Must show effective primary and fallback models
        assert "Effective Primary Model:  'gemini-3.8-flash'" in log_text
        assert "Effective Fallback Model: 'gemini-2.5-flash'" in log_text
        assert "YES (masked)" in log_text
        # MUST NEVER log the real API key
        assert secret_key not in log_text
        assert result["diagnostics"]["effective_primary_model"] == "gemini-3.8-flash"
        assert result["diagnostics"]["effective_fallback_model"] == "gemini-2.5-flash"

    def test_gemini_live_model_validation_against_google_api(self, monkeypatch):
        from unittest.mock import MagicMock
        from app import services

        services.clear_gemini_models_cache()

        mock_models = {
            "models": [
                {"name": "models/gemini-3.8-flash", "supportedGenerationMethods": ["generateContent"]},
                {"name": "models/gemini-2.5-flash", "supportedGenerationMethods": ["generateContent"]},
                {"name": "models/embedding-001", "supportedGenerationMethods": ["embedContent"]},
            ]
        }

        def mock_get(url, **kwargs):
            mock_res = MagicMock()
            mock_res.status_code = 200
            mock_res.json.return_value = mock_models
            return mock_res

        monkeypatch.setattr("httpx.get", mock_get)

        report = services.validate_gemini_models(
            primary_model="gemini-3.8-flash",
            fallback_model="gemini-2.5-flash",
            api_key="valid-test-key-for-test",
        )

        assert report["remote_check_performed"] is True
        assert report["remote_check_success"] is True
        assert report["validation_source"] == "google_api_live"
        assert report["primary_valid"] is True
        assert report["fallback_valid"] is True
        assert "verified and available" in report["detail"]

    def test_gemini_live_model_validation_rejects_unavailable_model(self, monkeypatch):
        from unittest.mock import MagicMock
        from app import services

        services.clear_gemini_models_cache()

        mock_models = {
            "models": [
                {"name": "models/gemini-3.8-flash", "supportedGenerationMethods": ["generateContent"]},
                {"name": "models/gemini-2.5-flash", "supportedGenerationMethods": ["generateContent"]},
            ]
        }

        def mock_get(url, **kwargs):
            mock_res = MagicMock()
            mock_res.status_code = 200
            mock_res.json.return_value = mock_models
            return mock_res

        monkeypatch.setattr("httpx.get", mock_get)

        # gemini-2.0-flash is NOT in available models
        report = services.validate_gemini_models(
            primary_model="gemini-2.0-flash",
            fallback_model="",
            api_key="valid-test-key-for-test",
        )

        assert report["remote_check_performed"] is True
        assert report["remote_check_success"] is True
        assert report["validation_source"] == "google_api_live"
        assert report["primary_valid"] is False
        assert "NOT available in this Google Gemini project/key" in report["detail"]

    def test_model_config_diagnostics_detects_env_overrides(self, monkeypatch):
        import os
        from app.config import get_model_config_diagnostics, settings

        monkeypatch.setenv("GEMINI_MODEL", "gemini-3.8-flash")
        monkeypatch.setenv("GEMINI_FALLBACK_MODEL", "gemini-2.5-flash")

        diag = get_model_config_diagnostics()
        assert diag["env_var_override_primary"] == "gemini-3.8-flash"
        assert diag["env_var_override_fallback"] == "gemini-2.5-flash"
        assert diag["is_overridden_by_env"] is True
        assert len(diag["inspected_env_files"]) >= 2





