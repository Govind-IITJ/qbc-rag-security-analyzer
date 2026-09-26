from qbc_rag_security.sage import govern


def base(rule_risk=0, findings=None):
    return {"risk_score": rule_risk, "confidence": 55, "findings": findings or []}


def test_defensive_security_topic_can_remain_safe():
    intent = {
        "goal":"defend","action":"analyze","target":"security_concept","purpose":"defensive",
        "authorization":"not_applicable","activity":"descriptive","security_intent":"defensive",
        "requested_effect":"improve security","rationale":"defensive analysis","confidence":0.95,
    }
    out=govern(base(0), intent, {"available":True,"model":"test","provider":"ollama"})
    assert out["decision"] == "SAFE"


def test_malicious_protected_extraction_rejects():
    intent = {
        "goal":"extract","action":"reveal","target":"credential","purpose":"operational",
        "authorization":"unauthorized","activity":"requested_execution","security_intent":"malicious",
        "requested_effect":"disclose credentials","rationale":"unauthorized extraction","confidence":0.96,
    }
    out=govern(base(0), intent, {"available":True,"model":"test","provider":"ollama"})
    assert out["decision"] == "REJECT"


def test_model_unavailable_preserves_rule_baseline():
    out=govern(base(0), {"security_intent":"malicious","confidence":1}, {"available":False})
    assert out["decision"] == "SAFE"
    assert out["local_llm_used"] is False
