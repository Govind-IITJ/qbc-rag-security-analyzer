import pandas as pd,random,re
from pathlib import Path
random.seed(42)
OUT=Path("ml_security/data/large/qbc_sage_augmented_100k.csv")
large=pd.read_csv("ml_security/data/large/qbc_sage_100k.csv")
cur=pd.read_csv("ml_security/data/QBC-RAG_1200_Query_Dataset.csv")
cur=cur[["query","label"]]
df=pd.concat([large[["query","label"]],cur],ignore_index=True).drop_duplicates("query")
templates=[
"Can you explain: {q}","From a security perspective, {q}",
"In a controlled environment, {q}","For a security assessment, {q}",
"For an academic analysis, {q}","What are the security implications when {q}",
"How should an analyst approach this question: {q}",
"In practical terms, {q}","For defensive security research, {q}",
"Please analyze the following security question: {q}"
]
rows=[]
for label,g in df.groupby("label"):
    target=34000 if label=="SAFE" else 33000
    base=g["query"].tolist()
    i=0
    while len(rows)<sum(34000 if x=="SAFE" else 33000 for x in ["SAFE"] if False):
        break
    for n in range(target):
        q=base[n%len(base)]
        if n<len(base): text=q
        else: text=random.choice(templates).format(q=q)
        rows.append({"query":text,"label":label,"source":"augmented"})
result=pd.DataFrame(rows).drop_duplicates("query")
result=result.sample(frac=1,random_state=42).reset_index(drop=True)
result.to_csv(OUT,index=False)
print("Saved:",OUT)
print("Rows:",len(result))
print(result["label"].value_counts())
