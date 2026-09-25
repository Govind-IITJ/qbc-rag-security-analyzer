from __future__ import annotations
import re, unicodedata, hashlib, time
from dataclasses import dataclass, asdict
from typing import Any

PATTERNS = [
    ("prompt_injection", "Prompt Injection", 0.96, [
        r"\bignore (?:all|any|the) previous instructions\b",
        r"\bdisregard (?:all|any|the) (?:previous|prior) instructions\b",
        r"\bfollow this document instead\b",
        r"\bdo not follow\b.*\binstructions\b",
        r"\boverride\b.*\b(instructions|policy|security)\b",
    ]),
    ("authority_spoofing", "Authority Spoofing", 0.90, [
        r"\bsystem message\b",
        r"\badministrator directive\b",
        r"\bofficial override\b",
        r"\bdeveloper instruction\b",
        r"\badmin(?:istrator)? authority\b",
    ]),
    ("role_hijacking", "Role Hijacking", 0.88, [
        r"\byou are now\b",
        r"\bact as the (?:developer|administrator|system)\b",
        r"\byour new role\b",
        r"\bpretend to be\b.*\badmin",
    ]),
    ("secret_exfiltration", "Secret Exfiltration", 0.99, [
        r"\breveal\b.*\b(api keys?|passwords?|credentials?|secrets?)\b",
        r"\bshow\b.*\b(private keys?|credentials?|access tokens?)\b",
        r"\bprint\b.*\b(environment variables?|access tokens?)\b",
        r"\bapi[_ -]?key\s*=",
        r"\bsk-[a-z0-9_-]{12,}\b",
    ]),
    ("tool_manipulation", "Tool Manipulation", 0.93, [
        r"\bcall the shell tool\b",
        r"\bexecute this command\b",
        r"\binvoke the function\b",
        r"\bcall send_email\b",
        r"\btool parameter\b",
    ]),
    ("cross_tool_exfiltration", "Cross-Tool Exfiltration", 0.96, [
        r"\bsend\b.*\bconfidential data\b",
        r"\bupload\b.*\bprivate context\b",
        r"\bexternal endpoint\b",
        r"\battacker server\b",
    ]),
    ("memory_poisoning", "Memory Poisoning", 0.91, [
        r"\bremember this instruction forever\b",
        r"\bsave this override\b.*\bmemory\b",
        r"\bpersistent memory\b",
        r"\bremember\b.*\balways ignore\b",
    ]),
    ("backdoor", "Backdoor / Trigger", 0.91, [
        r"\bactivation phrase\b",
        r"\bsecret phrase\b.*\boverride\b",
        r"\btriggers? an override\b",
    ]),
    ("hidden_text", "Hidden / Invisible Text", 0.95, [
        "\u200b", "\u200c", "\u200d", "\u2060", "\ufeff",
    ]),
    ("retrieval_manipulation", "Retrieval Manipulation", 0.82, [
        r"(?:\b\w+\b\s+){8,}(?:\b\w+\b\s+){8,}",
        r"\brepeat\b.*\b(?:ranking|context|retrieve)\b",
    ]),
    ("knowledge_poisoning", "Knowledge Poisoning", 0.84, [
        r"\b(?:policy|limit|rule)\b.*\b(?:999999|unlimited|1\s*INR)\b",
        r"\bofficial policy now says\b",
        r"\ballow everyone\b",
    ]),
    ("provenance_spoofing", "Provenance Spoofing", 0.88, [
        r"\bsource:\s*official\b",
        r"\bofficial administrator policy\b",
        r"\bverified official\b",
    ]),
    ("citation_spoofing", "Citation Spoofing", 0.83, [
        r"\[official policy\b",
        r"\bfabricated citation\b",
        r"\bcite\b.*\bofficial source\b",
    ]),
    ("stale_document", "Stale Document", 0.68, [
        r"\b(?:19|20)\d{2}\s+policy\b",
        r"\bstale\b.*\bpolicy\b",
        r"\bold version\b",
    ]),
    ("version_confusion", "Version Confusion", 0.77, [
        r"\bpolicy v\d+\b",
        r"\bversion\b.*\bunlimited\b",
        r"\bversion confusion\b",
    ]),
    ("sybil_source", "Sybil / Fake Corroboration", 0.80, [
        r"\bindependent official source says\b",
        r"\bindependent source\b.*\battacker\b",
    ]),
    ("context_flooding", "Context Flooding", 0.86, [
        r"(?:\bignore\b|\breveal secrets\b).{200,}",
    ]),
    ("adversarial_query", "Adversarial Query", 0.73, [
        r"\bconfidential administrative exception\b",
        r"\beven if access is denied\b",
    ]),
    ("membership_inference", "Membership Inference", 0.91, [
        r"\bis .*\.pdf present\b",
        r"\bconfirm whether\b.*\bsecrets?\b.*\bdatabase\b",
        r"\bdoes .* exist\b.*\bprivate\b",
    ]),
    ("index_inference", "Index / Enumeration Inference", 0.88, [
        r"\blist every document\b",
        r"\benumerate all sources\b",
        r"\bhidden index\b",
    ]),
    ("embedding_leakage", "Embedding Leakage", 0.88, [
        r"\breveal the embedding vectors\b",
        r"\bvector index contents\b",
        r"\bprivate document representation\b",
    ]),
    ("database_extraction", "Database Extraction", 0.95, [
        r"\bdump the complete knowledge base\b",
        r"\brepeat every private document\b",
        r"\breconstruct the entire corpus\b",
    ]),
    ("cross_tenant", "Cross-Tenant Access", 0.99, [
        r"\banother user's private documents\b",
        r"\btenant [ab]\b.*\btenant [ab]\b",
        r"\bshow tenant\b.*\brecords\b",
        r"\bprivate documents\b.*\banother user\b",
    ]),
    ("excessive_agency", "Excessive Agency", 0.94, [
        r"\bdelete files\b.*\bsend an email\b",
        r"\busing available tools\b",
        r"\bunauthorized actions?\b",
    ]),
    ("multimodal_injection", "Multimodal Injection", 0.86, [
        r"\bthe image says\b.*\bignore\b",
    ]),
    ("ocr_injection", "OCR Injection", 0.86, [
        r"\bocr text\b.*\bsystem message\b",
    ]),
    ("resource_exhaustion", "Resource Exhaustion", 0.88, [
        r"\benormous answer\b",
        r"\bevery document\b.*\btoken limit\b",
        r"\buntil the token limit\b",
        r"\brepeat the context\b",
    ]),
    ("conflicting_evidence", "Conflicting Evidence", 0.79, [
        r"\bpolicy a says\b.*\bpolicy b says\b",
        r"\bconflicting evidence\b",
    ]),
    ("unicode_evasion", "Unicode / Encoding Evasion", 0.82, [
        r"\b(?:base64|rot13|homoglyph|confusable)\b",
    ]),
]

CATEGORY_SEVERITY = {
    "secret_exfiltration": "critical", "cross_tenant": "critical",
    "database_extraction": "critical", "prompt_injection": "critical",
    "tool_manipulation": "critical", "cross_tool_exfiltration": "critical",
    "excessive_agency": "critical",
    "authority_spoofing": "high", "role_hijacking": "high",
    "memory_poisoning": "high", "backdoor": "high", "hidden_text": "high",
    "retrieval_manipulation": "high", "knowledge_poisoning": "high",
    "provenance_spoofing": "high", "context_flooding": "high",
    "membership_inference": "high", "index_inference": "high",
    "embedding_leakage": "high", "resource_exhaustion": "high",
}

@dataclass
class Finding:
    category: str
    label: str
    severity: str
    confidence: float
    matched_evidence: list[str]
    rationale: str

def normalize(text: str) -> str:
    return unicodedata.normalize("NFKC", text or "")

def _matched(pattern, text):
    if pattern in {"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"}:
        return pattern if pattern in text else None
    m = re.search(pattern, text, re.I | re.S)
    return m.group(0)[:180] if m else None

def analyze_query(query: str) -> dict[str, Any]:
    started = time.perf_counter()
    normalized = normalize(query)
    findings: list[Finding] = []
    activated = {}
    for category, label, confidence, patterns in PATTERNS:
        hits = []
        for p in patterns:
            hit = _matched(p, normalized)
            if hit and hit not in hits:
                hits.append(hit)
        if hits:
            sev = CATEGORY_SEVERITY.get(category, "medium")
            rationale = {
                "prompt_injection": "Attempts to override or replace the instruction hierarchy.",
                "secret_exfiltration": "Targets credentials, secrets, keys or protected authentication material.",
                "authority_spoofing": "Attempts to manufacture system, administrator or developer authority.",
                "role_hijacking": "Attempts to change the assistant's role or authority.",
                "tool_manipulation": "Attempts to turn text into an instruction to invoke or manipulate tools.",
                "cross_tenant": "Requests data belonging to another tenant or user boundary.",
                "database_extraction": "Requests reconstruction or bulk disclosure of protected corpus data.",
                "hidden_text": "Contains invisible Unicode controls that can conceal instructions.",
            }.get(category, "Pattern indicates adversarial, extraction, manipulation or resource-abuse behavior.")
            findings.append(Finding(category, label, sev, confidence, hits, rationale))
            activated[category] = confidence

    # Generic structural signals.
    token_count = len(re.findall(r"\b\w+\b", normalized))
    instruction_terms = len(re.findall(r"\b(ignore|reveal|override|disregard|bypass|execute|dump|delete|send|upload)\b", normalized, re.I))
    if token_count > 180:
        activated["length_anomaly"] = min(1.0, token_count / 500)
    if instruction_terms >= 3:
        activated["instruction_density"] = min(1.0, instruction_terms / 6)

    # Weighted union-style risk: overlapping detectors should increase confidence,
    # but repeated matches should not trivially push beyond 100.
    weights = [activated[k] for k in activated if k not in {"length_anomaly", "instruction_density"}]
    structural = [activated[k] for k in ("length_anomaly", "instruction_density") if k in activated]
    if weights:
        risk = 1.0 - __import__("math").prod(1.0 - min(0.99, x) for x in weights)
        risk = min(1.0, risk + 0.08 * sum(structural))
    else:
        risk = min(1.0, 0.08 * sum(structural))

    if any(f.category in {"secret_exfiltration","cross_tenant","database_extraction","prompt_injection","tool_manipulation"} for f in findings):
        risk = max(risk, 0.78)
    if not findings and risk < 0.30:
        decision = "SAFE"
    elif risk < 0.60:
        decision = "REVIEW"
    else:
        decision = "REJECT"

    confidence = max([f.confidence for f in findings], default=max(0.55, 1 - risk/2))
    # Explanation vector for the UI.
    vector = {
        "Prompt Injection": round(activated.get("prompt_injection", 0)*100, 1),
        "Authority": round(activated.get("authority_spoofing", 0)*100, 1),
        "Exfiltration": round(max(activated.get("secret_exfiltration",0), activated.get("database_extraction",0), activated.get("cross_tenant",0))*100, 1),
        "Tool / Agency": round(max(activated.get("tool_manipulation",0), activated.get("excessive_agency",0))*100, 1),
        "Retrieval Poisoning": round(max(activated.get("retrieval_manipulation",0), activated.get("knowledge_poisoning",0), activated.get("provenance_spoofing",0))*100, 1),
        "Persistence": round(max(activated.get("memory_poisoning",0), activated.get("backdoor",0))*100, 1),
    }

    digest = hashlib.sha256(normalized.encode()).hexdigest()[:16]
    return {
        "query": query,
        "normalized_query": normalized,
        "decision": decision,
        "risk_score": round(risk*100, 2),
        "confidence": round(confidence*100, 2),
        "finding_count": len(findings),
        "findings": [asdict(f) for f in findings],
        "behavior_vector": vector,
        "activated_features": {k: round(v,4) for k,v in activated.items()},
        "query_hash": digest,
        "token_count": token_count,
        "latency_ms": round((time.perf_counter()-started)*1000, 3),
        "engine_version": "2.1.0-security-analyzer",
        "external_llm_used": False,
    }
