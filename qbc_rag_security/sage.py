from __future__ import annotations

from typing import Any

CRITICAL_TARGETS = {"system_instruction", "credential", "secret", "tenant_data", "database"}
CRITICAL_ACTIONS = {"reveal", "dump", "override", "execute", "delete", "transmit", "extract"}
MALICIOUS_GOALS = {"extract", "modify", "execute", "bypass", "persist", "transmit"}


def _intent_signal(intent: dict[str, Any]) -> tuple[float, list[str]]:
    score = 0.0
    reasons: list[str] = []
    sec = intent.get("security_intent")
    purpose = intent.get("purpose")
    action = intent.get("action")
    goal = intent.get("goal")
    target = intent.get("target")
    auth = intent.get("authorization")
    activity = intent.get("activity")

    if sec == "malicious":
        score += 0.62; reasons.append("semantic model classified the intent as malicious")
    elif sec == "dual_use":
        score += 0.20; reasons.append("semantic model classified the intent as dual-use")
    elif sec == "defensive" or purpose == "defensive":
        score -= 0.28; reasons.append("semantic model identified a defensive purpose")
    elif purpose in {"educational", "analytical"}:
        score -= 0.18; reasons.append("semantic model identified an educational/analytical purpose")

    if action in CRITICAL_ACTIONS or goal in MALICIOUS_GOALS:
        score += 0.25; reasons.append("requested action/goal has security impact")
    if target in CRITICAL_TARGETS:
        score += 0.20; reasons.append("target is a protected security resource")
    if auth == "unauthorized":
        score += 0.25; reasons.append("request is semantically unauthorized")
    elif auth == "unknown":
        score += 0.04
    if activity == "requested_execution":
        score += 0.15; reasons.append("request describes an operational effect")
    elif activity in {"hypothetical", "descriptive"}:
        score -= 0.08

    return max(0.0, min(1.0, score)), reasons


def govern(base: dict[str, Any], intent: dict[str, Any], intent_meta: dict[str, Any]) -> dict[str, Any]:
    """Fuse semantic intent with deterministic findings. AI never has sole authority."""
    findings = base.get("findings", [])
    rule_risk = float(base.get("risk_score", 0.0)) / 100.0
    intent_conf = float(intent.get("confidence", 0.0))
    semantic, reasons = _intent_signal(intent)

    # Only allow semantic influence when the model is sufficiently confident.
    influence = semantic * max(0.0, min(1.0, intent_conf))
    final_risk = min(1.0, 0.62 * rule_risk + 0.38 * influence)

    # Defensive/educational intent should not be punished merely because a security topic is named.
    if intent.get("security_intent") in {"defensive", "benign"} and intent_conf >= 0.72:
        final_risk = min(final_risk, max(0.28, rule_risk * 0.55))

    # Hard gates: semantic model cannot override deterministic critical findings.
    critical = {"secret_exfiltration", "cross_tenant", "database_extraction", "tool_manipulation", "cross_tool_exfiltration", "excessive_agency"}
    if any(f.get("category") in critical for f in findings):
        final_risk = max(final_risk, 0.78)
        reasons.append("deterministic critical security gate activated")

    # Semantic hard gate for paraphrased attacks that contain no known rule phrase.
    # Require a strong conjunction instead of trusting a single model field.
    protected_extraction = (
        intent.get("security_intent") == "malicious"
        and intent_conf >= 0.80
        and intent.get("target") in CRITICAL_TARGETS
        and (intent.get("action") in CRITICAL_ACTIONS or intent.get("goal") in MALICIOUS_GOALS)
        and intent.get("authorization") == "unauthorized"
        and intent.get("activity") == "requested_execution"
    )
    if protected_extraction:
        final_risk = max(final_risk, 0.92)
        reasons.append("semantic hard gate: malicious unauthorized operation on protected resource")

    # Prompt-injection patterns are only hard-reject when coupled with an operational/protected target signal.
    if any(f.get("category") == "prompt_injection" for f in findings):
        if intent.get("target") in CRITICAL_TARGETS or intent.get("action") in CRITICAL_ACTIONS or intent.get("security_intent") == "malicious":
            final_risk = max(final_risk, 0.78)
            reasons.append("prompt-injection pattern corroborated by semantic intent")

    # Unknown AI / unavailable model: preserve the deterministic baseline rather than inventing intent.
    if not intent_meta.get("available"):
        final_risk = rule_risk
        reasons.append("local semantic model unavailable; deterministic baseline retained")

    # QBC-SAGE v4.1 semantic-effect hard gates.
    # The local LLM provides evidence; these gates retain deterministic authority.
    sec = intent.get("security_adjudication") or {}
    harmful = bool(sec.get("harmful_capability"))
    effect = str(sec.get("security_effect") or "none")
    protected = str(sec.get("protected_resource") or "none")
    auth = str(sec.get("authorization_basis") or "unknown")
    operational = bool(sec.get("operational_request"))
    sec_conf = float(sec.get("confidence") or 0.0)

    critical_effects = {
        "unauthorized_access",
        "secret_disclosure",
        "cross_tenant_access",
        "privilege_escalation",
        "security_bypass",
        "security_evasion",
        "destructive_change",
        "protected_instruction_disclosure",
        "data_exfiltration",
        "control_disablement",
    }

    critical_resources = {
        "system_instruction",
        "credential",
        "secret",
        "tenant_data",
        "user_data",
        "database",
        "audit_log",
        "access_control",
        "security_boundary",
    }

    # High-confidence harmful operational requests against protected
    # resources/effects are REJECT, regardless of benign educational wording.
    if (
        harmful
        and operational
        and sec_conf >= 0.80
        and auth == "unauthorized"
        and (effect in critical_effects or protected in critical_resources)
    ):
        final_risk = max(final_risk, 0.92)
        reasons.append("semantic security-effect hard gate triggered")

    # Explicit malicious intent with a critical security effect.
    if (
        str(intent.get("security_intent")) == "malicious"
        and sec_conf >= 0.80
        and effect in critical_effects
    ):
        final_risk = max(final_risk, 0.92)
        reasons.append("malicious critical-effect hard gate triggered")

    # Protected instruction disclosure is critical even when the model
    # does not classify the request as malicious.
    if (
        protected == "system_instruction"
        and sec_conf >= 0.80
        and operational
    ):
        final_risk = max(final_risk, 0.92)
        reasons.append("protected-instruction disclosure hard gate triggered")

    if (
        effect == "protected_instruction_disclosure"
        and sec_conf >= 0.80
        and operational
    ):
        final_risk = max(final_risk, 0.92)
        reasons.append("protected-instruction-effect hard gate triggered")

    if effect in critical_effects and sec_conf >= 0.80 and not bool(sec.get("educational_only")):
        final_risk = max(final_risk, 0.92)
        reasons.append("high-confidence critical semantic-effect gate")

    if final_risk < 0.30:
        decision = "SAFE"
    elif final_risk < 0.70:
        decision = "REVIEW"
    else:
        decision = "REJECT"

    # Low-confidence semantic security queries should not silently become SAFE when rules found nothing.
    if intent_meta.get("available") and intent_conf < 0.45 and intent.get("target") in CRITICAL_TARGETS and final_risk < 0.70:
        decision = "REVIEW"
        final_risk = max(final_risk, 0.40)
        reasons.append("low semantic confidence on a protected target")

    base["decision"] = decision
    base["risk_score"] = round(final_risk * 100, 2)
    base["confidence"] = round(max(float(base.get("confidence", 0.0)) / 100.0, intent_conf) * 100, 2)
    base["semantic_intent"] = intent
    base["semantic_model"] = intent_meta
    base["reasoning"] = {
        "rule_risk": round(rule_risk * 100, 2),
        "semantic_risk": round(influence * 100, 2),
        "fusion": "0.62*deterministic + 0.38*semantic",
        "reasons": reasons,
        "final_authority": "deterministic QBC-SAGE security gates",
    }
    base["engine_version"] = "4.1.0-qbc-sage-semantic-effect"
    base["external_llm_used"] = False
    base["local_llm_used"] = bool(intent_meta.get("available"))
    return base
