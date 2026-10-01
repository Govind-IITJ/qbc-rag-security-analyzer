from pathlib import Path
p=Path('qbc_rag_security/analyzer.py')
s=p.read_text(encoding='utf-8')
if 'def _rule_analyze_query(' not in s:
 s=s.replace('def analyze_query(', 'def _rule_analyze_query(', 1)
 wrapper=r'''

# v3.0 hybrid ML wrapper. The original deterministic implementation is preserved above.
def analyze_query(query: str) -> dict:
    result = _rule_analyze_query(query)
    try:
        import sys
        from pathlib import Path
        root = Path(__file__).resolve().parents[1]
        ml_dir = root / "ml_security"
        if str(ml_dir) not in sys.path:
            sys.path.insert(0, str(ml_dir))
        from engine import predict
        ml = predict(query)
        result["ml"] = ml
        if ml.get("available"):
            rule_risk = float(result.get("risk_score", 0.0)) / 100.0
            hybrid = min(1.0, 0.45 * rule_risk + 0.55 * float(ml.get("risk", 0.0)))
            if float(ml.get("probabilities", {}).get("REJECT", 0.0)) >= 0.80:
                hybrid = max(hybrid, 0.70)
            result["rule_risk_score"] = round(rule_risk * 100, 2)
            result["ml_risk_score"] = round(float(ml.get("risk", 0.0)) * 100, 2)
            result["hybrid_risk_score"] = round(hybrid * 100, 2)
            result["hybrid_decision"] = "SAFE" if hybrid < 0.30 else "REVIEW" if hybrid < 0.70 else "REJECT"
            result["ml_threat_category"] = ml.get("threat_category", "none")
            # Final decision is now produced by the hybrid gate; all original rule evidence remains.
            result["decision"] = result["hybrid_decision"]
        return result
    except Exception as exc:
        result["ml"] = {"available": False, "error": str(exc)}
        result["hybrid_decision"] = result.get("decision")
        return result
'''
 s += wrapper
 p.write_text(s,encoding='utf-8')
 print('Hybrid ML wrapper integrated into qbc_rag_security/analyzer.py')
else: print('Already integrated; no change.')
