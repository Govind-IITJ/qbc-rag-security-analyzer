import json,requests,pandas as pd
from pathlib import Path
from time import sleep

SEED=Path("ml_security/data/QBC-RAG_1200_Query_Dataset.csv")
OUT=Path("ml_security/data/large/qbc_sage_100k.csv")
N=100000; MODEL="qwen2.5:3b"; URL="http://localhost:11434/api/generate"
df=pd.read_csv(SEED)
examples=df.groupby("label").sample(n=20,random_state=42).reset_index(drop=True)
system="""Generate cybersecurity intent queries. Labels:
SAFE=benign educational or defensive requests.
REVIEW=security analysis, authorized testing, investigation, or ambiguous dual-use.
ATTACK=requests enabling unauthorized access, secret disclosure, bypass, evasion, destructive action,
privilege escalation, cross-tenant access, exfiltration, protected-instruction disclosure, or disabling controls.
Return ONLY a JSON array of objects with exactly query and label fields."""

rows=[]
if OUT.exists():
    rows=pd.read_csv(OUT).to_dict("records")
    print("Resuming from",len(rows),"existing rows")

while len(rows)<N:
    sample=examples.sample(12).to_dict("records")
    prompt=system+"\nExamples:\n"+json.dumps(sample,ensure_ascii=False)
    prompt+="\nGenerate exactly 20 NEW diverse queries balanced across SAFE, REVIEW, ATTACK."
    try:
        r=requests.post(URL,json={"model":MODEL,"prompt":prompt,
            "format":"json","stream":False},timeout=180)
        data=json.loads(r.json()["response"])
        if isinstance(data,dict):
            data=data.get("queries",[])
        added=0
        for x in data if isinstance(data,list) else []:
            q=str(x.get("query","")).strip()
            label=x.get("label")
            if q and label in {"SAFE","REVIEW","ATTACK"}:
                rows.append({"query":q,"label":label}); added+=1
        rows=pd.DataFrame(rows).drop_duplicates("query").to_dict("records")
        if added: print("Generated:",len(rows))
        else: print("No valid rows; retrying")
    except Exception as e:
        print("retry:",e); sleep(2)
    if len(rows)%500<20:
        pd.DataFrame(rows).to_csv(OUT,index=False)
        print("Checkpoint:",len(rows))
pd.DataFrame(rows[:N]).to_csv(OUT,index=False)
print("Saved:",OUT,"rows=",min(len(rows),N))
