import json
from unittest.mock import patch
from qbc_rag_security.intent_engine import infer_intent


class FakeResponse:
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def read(self):
        return json.dumps({
            "message": {"content": json.dumps({
                "goal": "defend",
                "action": "analyze",
                "target": "security_concept",
                "purpose": "defensive",
                "authorization": "not_applicable",
                "activity": "descriptive",
                "security_intent": "defensive",
                "requested_effect": "improve RAG security",
                "rationale": "The query asks for defensive analysis.",
                "confidence": 0.94,
            })}
        }).encode()


def test_ollama_intent_contract():
    with patch("qbc_rag_security.intent_engine.urllib.request.urlopen", return_value=FakeResponse()):
        intent, meta = infer_intent("How can I defend a RAG system against prompt injection?")
    assert meta["available"] is True
    assert intent["security_intent"] == "defensive"
    assert intent["target"] == "security_concept"
    assert intent["confidence"] == 0.94
