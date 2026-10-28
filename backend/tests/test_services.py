from app.services import classify_document, heuristic_risk
def test_classification():
    assert classify_document("Extension of Approval AICTE", "file.pdf") == "Approval Letter"
def test_unclassified():
    assert classify_document("hello world", "random.pdf") == "Unclassified"
def test_risk_score_caps():
    class F: result="NEEDS_REVIEW"; severity="high"
    assert heuristic_risk([F(),F(),F(),F(),F()]) == 100
