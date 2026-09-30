from pathlib import Path
import re
p=Path("qbc_rag_security/analyzer.py")
s=p.read_text(encoding="utf-8")
s=s.replace('qbc_sage_student_v5.joblib','qbc_sage_student_v6.joblib')
s=s.replace('ml_security/models/qbc_sage_student_v5.joblib','ml_security/v6/models/qbc_sage_student_v6.joblib')
p.write_text(s,encoding="utf-8")
print("Analyzer model path -> V6")
