import json,requests,pandas as pd
from pathlib import Path
from time import sleep
OUT=Path("ml_security/data/large/qbc_sage_semantic_100k.csv")
N=100000; BATCH=50; MODEL="qwen2.5:3b"; URL="http://localhost:11434/api/generate"
SYSTEM="""Return ONLY JSON with key examples containing an array of exactly 50 objects.
Each object: query, goal, action, target, authorization, security_effect, operational_request,
defensive_request, educational_only, label.
authorization=authorized/unauthorized/unknown; label=SAFE/REVIEW/ATTACK.
SAFE=benign education or clearly defensive guidance.
REVIEW=authorized testing, investigation, analysis, or ambiguous dual-use.
ATTACK=unauthorized/unknown requests enabling harmful capability.
Do not label something ATTACK merely because it mentions security. Make every query substantially different."""
rows=[]
if OUT.exists():
    rows=pd.read_csv(OUT).to_dict("records")
    print("Resuming:",len(rows))
while len(rows)<N:
    prompt=SYSTEM+f"\nGenerate exactly {BATCH} diverse examples balanced across all labels."
    try:
        r=requests.post(URL,json={"model":MODEL,"prompt":prompt,
            "format":"json","stream":False},timeout=300)
        obj=json.loads(r.json()["response"])
        data=obj.get("examples",[]) if isinstance(obj,dict) else []
        required={"query","goal","action","target","authorization","security_effect",
                   "operational_request","defensive_request","educational_only","label"}
        for x in data:
            if required.issubset(x) and x["label"] in {"SAFE","REVIEW","ATTACK"}:
                rows.append(x)
        rows=pd.DataFrame(rows).drop_duplicates("query").to_dict("records")
        print("Generated:",len(rows))
    except Exception as e:
        print("retry:",e); sleep(2)
    if len(rows)>=500 and len(rows)%500<50:
        OUT.parent.mkdir(parents=True,exist_ok=True)
        pd.DataFrame(rows).to_csv(OUT,index=False)
        print("Checkpoint:",len(rows))
OUT.parent.mkdir(parents=True,exist_ok=True)
pd.DataFrame(rows[:N]).to_csv(OUT,index=False)
print("Saved:",OUT,"rows=",min(len(rows),N))
