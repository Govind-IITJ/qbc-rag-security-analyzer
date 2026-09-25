from __future__ import annotations
import os, sqlite3, json, uuid, time
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from qbc_rag_security.analyzer import analyze_query
from qbc_rag_security.benchmark import run_benchmark, ATTACKS, BENIGN
from qbc_rag_security import __version__

BASE = Path(__file__).parent
FRONTEND = BASE / "frontend"
DB = Path(os.getenv("QBC_SECURITY_DB","/tmp/qbc_security.sqlite3"))
DB.parent.mkdir(parents=True, exist_ok=True)

def db():
    c=sqlite3.connect(DB)
    c.row_factory=sqlite3.Row
    return c

with db() as c:
    c.execute("""CREATE TABLE IF NOT EXISTS experiments(
        id TEXT PRIMARY KEY, created_at TEXT NOT NULL, query TEXT NOT NULL,
        expected TEXT, result_json TEXT NOT NULL)""")
    c.commit()

app=FastAPI(title="QBC-RAG Security Analyzer",version=__version__)
origins=os.getenv("QBC_CORS_ORIGINS","*")
app.add_middleware(CORSMiddleware,allow_origins=[x.strip() for x in origins.split(",")],allow_methods=["*"],allow_headers=["*"])

class AnalyzeRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=10000)
    expected: str|None = None

@app.get("/health")
def health():
    return {"status":"ok","service":"qbc-rag-security-analyzer","version":__version__,"external_llm":False}

@app.get("/api/metrics/live")
def live():
    with db() as c:
        count=c.execute("SELECT COUNT(*) FROM experiments").fetchone()[0]
    return {"version":__version__,"experiments":count,"engine":"local-rule-analysis","external_llm":False,"database":True}

@app.post("/api/analyze")
def analyze(req: AnalyzeRequest):
    result=analyze_query(req.query)
    eid="QBC-"+time.strftime("%Y%m%d")+"-"+uuid.uuid4().hex[:8].upper()
    result["experiment_id"]=eid
    result["expected_label"]=req.expected
    if req.expected:
        expected=req.expected.lower()
        predicted="attack" if result["decision"] in {"REJECT","REVIEW"} else "safe"
        result["evaluation"]={"predicted":predicted,"correct":predicted==expected}
    with db() as c:
        c.execute("INSERT INTO experiments VALUES(?,?,?,?,?)",(eid,time.strftime("%Y-%m-%dT%H:%M:%SZ"),req.query,req.expected,json.dumps(result)))
        c.commit()
    return {"success":True,**result}


class BatchAnalyzeRequest(BaseModel):
    questions: list[str] = Field(..., min_length=1, max_length=100)
    max_question_length: int = Field(default=4000, ge=1, le=10000)


@app.post("/api/batch-analyze")
def batch_analyze(req: BatchAnalyzeRequest):
    results = []

    safe_count = 0
    review_count = 0
    reject_count = 0
    total_risk = 0.0

    for index, question in enumerate(req.questions, start=1):
        question = question.strip()

        if not question:
            continue

        question = question[:req.max_question_length]

        result = analyze_query(question)

        decision = str(result.get("decision", "REVIEW")).upper()
        risk = float(result.get("risk_score", result.get("risk", 0.0)))

        if decision == "SAFE":
            safe_count += 1
        elif decision == "REJECT":
            reject_count += 1
        else:
            review_count += 1

        total_risk += risk

        results.append({
            "index": index,
            "question": question,
            "decision": decision,
            "risk_score": risk,
            "findings": result.get("findings", [])
        })

    processed = len(results)

    return {
        "success": True,
        "total_submitted": len(req.questions),
        "total_processed": processed,
        "summary": {
            "safe": safe_count,
            "review": review_count,
            "reject": reject_count,
            "average_risk": round(total_risk / processed, 4) if processed else 0.0,
            "safe_rate": round(safe_count / processed, 4) if processed else 0.0,
            "review_rate": round(review_count / processed, 4) if processed else 0.0,
            "reject_rate": round(reject_count / processed, 4) if processed else 0.0
        },
        "results": results
    }

@app.get("/api/history")
def history(limit:int=100):
    limit=max(1,min(500,limit))
    with db() as c:
        rows=c.execute("SELECT id,created_at,query,expected,result_json FROM experiments ORDER BY rowid DESC LIMIT ?",(limit,)).fetchall()
    return {"success":True,"experiments":[{"id":r["id"],"created_at":r["created_at"],"query":r["query"],"expected":r["expected"],**json.loads(r["result_json"])} for r in rows]}

@app.delete("/api/history")
def clear_history():
    with db() as c:
        c.execute("DELETE FROM experiments"); c.commit()
    return {"success":True}

@app.get("/api/attacks")
def attacks():
    return {"success":True,"count":len(ATTACKS),"attacks":[{"id":a,"category":c,"query":q} for a,c,q in ATTACKS]}

@app.post("/api/evaluation/benchmark")
def benchmark():
    return {"success":True,"benchmark":run_benchmark()}

@app.get("/api/evaluation/summary")
def summary():
    with db() as c:
        rows=c.execute("SELECT result_json,expected FROM experiments").fetchall()
    tp=tn=fp=fn=0
    for row in rows:
        d=json.loads(row["result_json"])
        if not row["expected"]: continue
        pred=d["decision"] in {"REJECT","REVIEW"}
        exp=row["expected"].lower()=="attack"
        if exp and pred: tp+=1
        elif exp and not pred: fn+=1
        elif not exp and pred: fp+=1
        else: tn+=1
    total=tp+tn+fp+fn
    acc=(tp+tn)/total if total else 0
    prec=tp/(tp+fp) if tp+fp else 0
    rec=tp/(tp+fn) if tp+fn else 0
    f1=2*prec*rec/(prec+rec) if prec+rec else 0
    fpr=fp/(fp+tn) if fp+tn else 0
    return {"success":True,"tests":total,"accuracy":round(acc*100,2),"precision":round(prec*100,2),"recall":round(rec*100,2),"f1":round(f1*100,2),"false_positive_rate":round(fpr*100,2),"confusion_matrix":{"tp":tp,"tn":tn,"fp":fp,"fn":fn}}


@app.get("/batch")
def batch_page():
    return FileResponse(FRONTEND/"batch.html")

@app.get("/")
def index():
    return FileResponse(FRONTEND/"index.html")

@app.get("/{path:path}")
def static(path:str):
    p=FRONTEND/path
    if p.is_file(): return FileResponse(p)
    return FileResponse(FRONTEND/"index.html")
