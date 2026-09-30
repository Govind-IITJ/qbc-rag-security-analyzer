from pathlib import Path
p=Path("qbc_rag_security/analyzer.py")
s=p.read_text(encoding="utf-8")
s=s.replace('"ml_security/models/qbc_sage_student_v6.joblib"','"ml_security/v6/models/qbc_sage_student_v6.joblib"')
s=s.replace('student.predict_proba([query])[0]','(student["model"].predict_proba(student["features"].transform([query]))[0] if isinstance(student, dict) else student.predict_proba([query])[0])')
s=s.replace('classes = student.classes_','classes = student["labels"] if isinstance(student, dict) else student.classes_')
p.write_text(s,encoding="utf-8")
print("V6 analyzer integration fixed")
