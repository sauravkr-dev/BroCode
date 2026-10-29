
import pytest

from app.services import (
    classify_document,
    heuristic_risk,
    load_rules,
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
