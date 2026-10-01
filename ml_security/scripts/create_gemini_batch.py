import json
from pathlib import Path
import pandas as pd

SEED=Path("ml_security/data/QBC-RAG_1200_Query_Dataset.csv")
OUT=Path("ml_security/data/gemini_batch_1000.jsonl")
df=pd.read_csv(SEED).sample(1000,random_state=42)

schema={"type":"object","properties":{
"query":{"type":"string"},"goal":{"type":"string"},"action":{"type":"string"},
"target":{"type":"string"},"authorization":{"type":"string"},
"security_effect":{"type":"string"},"operational_request":{"type":"boolean"},
"defensive_request":{"type":"boolean"},"educational_only":{"type":"boolean"},
"label":{"type":"string"}},"required":["query","goal","action","target",
"authorization","security_effect","operational_request",
"defensive_request","educational_only","label"]}

system="""Classify and rewrite the cybersecurity query as a diverse training example.
SAFE=benign education or clearly defensive guidance.
REVIEW=authorized testing, investigation, analysis, or ambiguous dual-use.
ATTACK=unauthorized or unknown-authorization requests enabling harmful capability.
Do not label something ATTACK merely because it mentions security.
Return exactly one JSON object matching the supplied schema."""
with OUT.open("w",encoding="utf-8") as f:
    for i,row in enumerate(df.itertuples(index=False)):
        req={"key":f"qbc-{i:04d}","request":{"contents":[{"parts":[
        {"text":system+"\nOriginal query:\n"+row.query}]}],
        "generationConfig":{"responseMimeType":"application/json",
        "responseSchema":schema}}}
        f.write(json.dumps(req,ensure_ascii=False)+"\n")
print("Created:",OUT)
print("Requests:",len(df))
