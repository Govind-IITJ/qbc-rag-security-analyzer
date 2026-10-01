import csv,random,os
from collections import Counter
random.seed(42)
OUT="ml_security/data/large/qbc_sage_v4_contrastive.csv"
os.makedirs(os.path.dirname(OUT),exist_ok=True)
targets=["MFA","authentication","authorization","API keys","audit logging","database access","cross-tenant access","privilege escalation","SQL injection","prompt injection","system prompts","security monitoring","session management","access controls","data exfiltration","endpoint monitoring","tenant isolation","credential storage","password reset","security controls","database exports","web application security","API authentication","administrator access"]
contexts=["in production","in a test environment","in an isolated lab","for an authorized assessment","during a security audit","for a defensive review","on our own application","on a test account","without affecting users","in a controlled environment","for incident response","during penetration testing"]
attack=["Bypass {t} {c}.","Disable {t} {c}.","Evade {t} {c}.","Extract {t} {c}.","Override {t} {c}.","Dump protected {t} {c}.","Steal {t} from another user {c}.","Exploit {t} {c}.","Remove {t} protections {c}.","Hide activity from {t} {c}."]
safe=["How can I protect {t} {c}?","How can I detect attacks involving {t} {c}?","How can I prevent abuse of {t} {c}?","How should I securely configure {t} {c}?","How can I monitor {t} for suspicious activity {c}?","How can I investigate {t} safely {c}?","How can I improve defenses for {t} {c}?","How can I audit {t} securely {c}?","How can I detect unauthorized use of {t} {c}?","How can I harden {t} {c}?"]
review=["How does {t} work from a security perspective {c}?","How can I safely test {t} {c}?","How can I perform an authorized assessment of {t} {c}?","What risks should I evaluate for {t} {c}?","How can a security team reproduce a suspected {t} issue {c}?","How should I validate the security of {t} {c}?","How can I assess {t} without causing harm {c}?","What should an authorized security test of {t} cover {c}?"]
rows=[]
for label,templates,n in [("ATTACK",attack,2500),("SAFE",safe,2500),("REVIEW",review,2500)]:
    for _ in range(n):
        rows.append((random.choice(templates).format(t=random.choice(targets),c=random.choice(contexts)),label))
verbs_attack=["bypass","disable","evade","circumvent","override","extract","dump","steal","suppress","remove"]
verbs_def=["detect","prevent","monitor","audit","investigate","harden","protect","identify","mitigate","validate"]
for _ in range(15000):
    t=random.choice(targets); c=random.choice(contexts)
    rows.append((f"How can I {random.choice(verbs_attack)} {t} {c}?", "ATTACK"))
    rows.append((f"How can I {random.choice(verbs_def)} {t} {c}?", "SAFE"))
random.shuffle(rows)
with open(OUT,"w",newline="",encoding="utf-8") as f:
    w=csv.writer(f); w.writerow(["query","label"]); w.writerows(rows)
print("Generated:",len(rows))
print("Counts:",dict(Counter(x[1] for x in rows)))
print("Saved:",OUT)
