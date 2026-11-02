
from types import SimpleNamespace
from unittest.mock import MagicMock
import pytest

from app.services import (
    classify_document,
    get_rule_by_id,
    heuristic_risk,
    load_rules,
    store_findings,
)


def test_classification():
    assert (
        classify_document("Extension of Approval AICTE", "file.pdf")
        == "Approval Letter"
    )


def test_unclassified():
    assert classify_document("hello world", "random.pdf") == "Unclassified"


def test_risk_score_caps():
    class F:
        result = "NEEDS_REVIEW"
        severity = "high"

    assert heuristic_risk([F(), F(), F(), F(), F()]) == 100


def test_load_rules_returns_valid_rule_pack():
    rules = load_rules()

    assert isinstance(rules, dict)
    assert isinstance(rules.get("rules"), list)
    assert rules["status"] == "illustrative_unapproved"


def test_load_rules_has_unique_ids():
    rules = load_rules()
    rule_ids = [rule["id"] for rule in rules["rules"]]

    assert len(rule_ids) == len(set(rule_ids))


def test_load_rules_rejects_missing_file(monkeypatch, tmp_path):
    from app import services

    missing_file = tmp_path / "missing.yaml"
    monkeypatch.setattr(services, "RULE_FILE", missing_file)

    with pytest.raises(FileNotFoundError, match="Rule pack file not found"):
        load_rules()


@pytest.mark.parametrize(
    "invalid_content",
    [
        "just a string",
        "rules: {}",
        "rules:\n  - title: Missing ID",
    ],
)
def test_load_rules_rejects_invalid_structure(
    monkeypatch, tmp_path, invalid_content
):
    from app import services

    rule_file = tmp_path / "invalid.yaml"
    rule_file.write_text(invalid_content, encoding="utf-8")
    monkeypatch.setattr(services, "RULE_FILE", rule_file)

    with pytest.raises(ValueError):
        load_rules()


def test_load_rules_rejects_duplicate_ids(monkeypatch, tmp_path):
    from app import services

    rule_file = tmp_path / "duplicate.yaml"
    rule_file.write_text(
        "rules:\n"
        "  - id: DOC-001\n"
        "  - id: DOC-001\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(services, "RULE_FILE", rule_file)

    with pytest.raises(ValueError, match="duplicate rule IDs"):
        load_rules()


def test_get_rule_by_id_returns_metadata():
    for rule_id in ("DOC-001", "DOC-002", "DOC-003", "DOC-004", "DOC-005"):
        rule = get_rule_by_id(rule_id)
        assert rule is not None
        assert rule["id"] == rule_id
        assert "severity" in rule
        assert "title" in rule


def test_get_rule_by_id_nonexistent_or_invalid():
    assert get_rule_by_id("DOC-999") is None
    assert get_rule_by_id("NONEXISTENT", rules_data={"rules": []}) is None
    assert get_rule_by_id("DOC-001", rules_data="invalid") is None


def test_get_rule_by_id_with_missing_rule_file(monkeypatch, tmp_path):
    from app import services
    monkeypatch.setattr(services, "RULE_FILE", tmp_path / "nonexistent.yaml")
    assert get_rule_by_id("DOC-001") is None


def test_store_findings_aligns_with_rule_pack():
    db = MagicMock()
    doc = SimpleNamespace(
        id=10,
        doc_type="Unclassified",
        extracted_text="",
        sha256="abc123hash",
    )
    findings = store_findings(
        db,
        application_id=1,
        doc=doc,
        duplicate=True,
        duplicate_info={"scope": "same_application"},
    )
    findings_by_rule = {f.rule_id: f for f in findings}

    # Verify DOC-004 deficiency severity is "medium" (preserves review severity)
    assert findings_by_rule["DOC-004"].severity == "medium"
    assert findings_by_rule["DOC-004"].result == "NEEDS_REVIEW"

    # Verify DOC-005 deficiency severity is "medium" (aligned with YAML)
    assert findings_by_rule["DOC-005"].severity == "medium"
    assert findings_by_rule["DOC-005"].result == "NEEDS_REVIEW"

    # Verify DOC-002 severity is "high" (aligned with YAML)
    assert findings_by_rule["DOC-002"].severity == "high"
    assert findings_by_rule["DOC-002"].result == "NOT_VERIFIED"

    # Verify DOC-003 severity is "medium" when duplicate (aligned with YAML)
    assert findings_by_rule["DOC-003"].severity == "medium"
    assert findings_by_rule["DOC-003"].result == "NEEDS_REVIEW"


def test_store_findings_verified_checks():
    db = MagicMock()
    doc = SimpleNamespace(
        id=11,
        doc_type="Approval Letter",
        extracted_text="Extension of Approval valid text content",
        sha256="uniquehash456",
    )
    findings = store_findings(db, application_id=1, doc=doc, duplicate=False)
    findings_by_rule = {f.rule_id: f for f in findings}

    assert findings_by_rule["DOC-005"].severity == "low"
    assert findings_by_rule["DOC-005"].result == "VERIFIED"

    assert findings_by_rule["DOC-004"].severity == "low"
    assert findings_by_rule["DOC-004"].result == "VERIFIED"

    assert findings_by_rule["DOC-003"].severity == "low"
    assert findings_by_rule["DOC-003"].result == "VERIFIED"


def test_store_findings_fallback_when_rule_pack_unavailable(monkeypatch, tmp_path):
    from app import services
    monkeypatch.setattr(services, "RULE_FILE", tmp_path / "missing_pack.yaml")

    db = MagicMock()
    doc = SimpleNamespace(
        id=12,
        doc_type="Unclassified",
        extracted_text="",
        sha256="safehash789",
    )
    findings = store_findings(db, application_id=1, doc=doc, duplicate=False)
    assert len(findings) == 4
    findings_by_rule = {f.rule_id: f for f in findings}
    assert findings_by_rule["DOC-004"].severity == "medium"
    assert findings_by_rule["DOC-005"].severity == "medium"
    assert findings_by_rule["DOC-002"].severity == "high"


def test_doc004_successful_extraction():
    db = MagicMock()
    doc = SimpleNamespace(
        id=20,
        doc_type="Approval Letter",
        extracted_text="Readable text extracted from official PDF",
        sha256="hash20",
    )
    findings = store_findings(db, application_id=1, doc=doc, duplicate=False)
    doc004 = next(f for f in findings if f.rule_id == "DOC-004")
    assert doc004.result == "VERIFIED"
    assert doc004.severity == "low"
    assert "characters_extracted" in doc004.evidence


def test_doc004_failed_extraction_preserves_review_severity():
    db = MagicMock()
    # Test with empty string
    doc_empty = SimpleNamespace(
        id=21,
        doc_type="Approval Letter",
        extracted_text="",
        sha256="hash21",
    )
    findings_empty = store_findings(db, application_id=1, doc=doc_empty, duplicate=False)
    doc004_empty = next(f for f in findings_empty if f.rule_id == "DOC-004")
    assert doc004_empty.result == "NEEDS_REVIEW"
    assert doc004_empty.severity == "medium"

    # Test with whitespace only
    doc_whitespace = SimpleNamespace(
        id=22,
        doc_type="Approval Letter",
        extracted_text="   \n\t  ",
        sha256="hash22",
    )
    findings_ws = store_findings(db, application_id=1, doc=doc_whitespace, duplicate=False)
    doc004_ws = next(f for f in findings_ws if f.rule_id == "DOC-004")
    assert doc004_ws.result == "NEEDS_REVIEW"
    assert doc004_ws.severity == "medium"


def test_doc004_yaml_unavailable_fallback(monkeypatch, tmp_path):
    from app import services
    monkeypatch.setattr(services, "RULE_FILE", tmp_path / "missing_rules.yaml")

    db = MagicMock()
    # Successful extraction fallback -> low severity
    doc_pass = SimpleNamespace(
        id=23,
        doc_type="Approval Letter",
        extracted_text="Valid text when rules file is missing",
        sha256="hash23",
    )
    findings_pass = store_findings(db, application_id=1, doc=doc_pass, duplicate=False)
    doc004_pass = next(f for f in findings_pass if f.rule_id == "DOC-004")
    assert doc004_pass.result == "VERIFIED"
    assert doc004_pass.severity == "low"

    # Failed extraction fallback -> medium review severity
    doc_fail = SimpleNamespace(
        id=24,
        doc_type="Approval Letter",
        extracted_text="",
        sha256="hash24",
    )
    findings_fail = store_findings(db, application_id=1, doc=doc_fail, duplicate=False)
    doc004_fail = next(f for f in findings_fail if f.rule_id == "DOC-004")
    assert doc004_fail.result == "NEEDS_REVIEW"
    assert doc004_fail.severity == "medium"


def test_doc004_custom_configured_severity(monkeypatch, tmp_path):
    from app import services
    custom_rule_file = tmp_path / "custom_rules.yaml"
    custom_rule_file.write_text(
        "rule_pack_id: custom-v1\n"
        "rules:\n"
        "  - id: DOC-004\n"
        "    title: Text extraction availability\n"
        "    severity: low\n"
        "    pass_severity: low\n"
        "    fail_severity: high\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(services, "RULE_FILE", custom_rule_file)

    db = MagicMock()
    doc = SimpleNamespace(
        id=25,
        doc_type="Approval Letter",
        extracted_text="",
        sha256="hash25",
    )
    findings = store_findings(db, application_id=1, doc=doc, duplicate=False)
    doc004 = next(f for f in findings if f.rule_id == "DOC-004")
    assert doc004.result == "NEEDS_REVIEW"
    assert doc004.severity == "high"
