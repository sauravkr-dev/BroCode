# BroCode — AICTE Regulatory Compliance Verification (SIH 26261)

A security-conscious, demo-ready compliance pre-screening platform. It is **not an official AICTE system** and does not grant/deny approvals. All demo rules are explicitly marked illustrative until mapped and reviewed against the applicable official handbook, amendments, and institutional category.

## Stack
- FastAPI + SQLAlchemy + SQLite (SQLite for local demo; PostgreSQL recommended for deployment)
- JWT auth, password hashing, role-based access (institution/officer/admin)
- PDF/image upload, optional PDF text extraction and OCR fallback
- Versioned YAML rule pack, evidence-linked findings, duplicate image hash checks
- SHA-256 hash-chained audit events
- Optional Gemini deficiency memo (never used as the rule engine)
- React + Vite frontend

## Run locally (Windows PowerShell)
### Backend
```powershell
cd backend
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
# Change SECRET_KEY before any shared deployment. Add GEMINI_API_KEY only if desired.
uvicorn app.main:app --reload
```
Open http://127.0.0.1:8000/docs

### Frontend (second terminal)
```powershell
cd frontend
npm install
npm run dev
```
Open the URL Vite prints (usually http://localhost:5173).

Demo users are created only when `SEED_DEMO_USERS=true`:
- institution@example.com / DemoInstitution123!
- officer@example.com / DemoOfficer123!
- admin@example.com / DemoAdmin123!

**Change/remove these demo credentials before deployment.**

## Important production checklist
1. Replace SQLite with PostgreSQL; configure backups, migrations, connection pooling.
2. Set a long random `SECRET_KEY`; set `CORS_ORIGINS` to exact trusted origins.
3. Use HTTPS, reverse proxy, rate limiting, MFA/SSO, email verification and account recovery.
4. Store uploaded files in private object storage with malware scanning, file size/type validation, retention/deletion policy and access logs.
5. Obtain legal/security review for personal data and institutional records; minimize data and define retention.
6. Map each active rule to an exact handbook clause/page and applicable academic year; have a qualified compliance officer approve rule packs before activation.
7. Integrate only authorized issuer/AICTE data sources. No live AICTE API is assumed or bundled. Without one, status remains `MANUAL_VERIFICATION_REQUIRED`.
8. Add external key management, monitoring/alerting, CI/CD, dependency scanning, load/security testing and disaster recovery.
9. Review and threat-model the audit trail. Hash chaining is tamper-evident, not a substitute for immutable external storage/signatures.
10. Run end-to-end acceptance tests with approved synthetic data before any real institutional use.

## Compliance behaviour
- Rule engine output is `PASS`, `FAIL`, or `NEEDS_REVIEW`; missing evidence is not silently treated as compliance.
- The included rule pack is **illustrative** and carries no claim of official AICTE status.
- OCR, metadata, duplicate images, and AI summaries are indicators only; they do not establish fraud/authenticity.
- Final decision remains with an authorized human officer.
- Issuer verification is explicitly unavailable until an authorized integration is configured.

## Handbook reference
AICTE Approval Process Handbook 2024–25 to 2026–27: https://aicte-qa.aicte-india.org/sites/default/files/APH%20Final.pdf
Government of India release: https://www.pib.gov.in/Pressreleaseshare.aspx?PRID=1983013&lang=2&reg=48

Before applying to a real academic year, check AICTE's current portal for amendments/corrigenda and the institution/programme-specific provisions.
