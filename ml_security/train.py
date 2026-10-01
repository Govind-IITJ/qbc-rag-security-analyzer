import pandas as pd
from pathlib import Path
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score
import joblib

BASE=Path("ml_security/data/dataset/QBC-RAG-1200-Query-Dataset")
OUT=Path("ml_security/models/qbc_sage_student_v1.joblib")
train=pd.read_csv(BASE/"QBC-RAG_1200_train.csv")
val=pd.read_csv(BASE/"QBC-RAG_1200_validation.csv")
test=pd.read_csv(BASE/"QBC-RAG_1200_test.csv")
X_train,y_train=train["query"],train["label"]
X_val,y_val=val["query"],val["label"]
X_test,y_test=test["query"],test["label"]
model=Pipeline([("tfidf",TfidfVectorizer(ngram_range=(1,2),sublinear_tf=True)),("clf",LogisticRegression(max_iter=2000,class_weight="balanced"))])
print("Training QBC-SAGE Student v1...")
model.fit(X_train,y_train)
for name,X,y in [("VALIDATION",X_val,y_val),("TEST",X_test,y_test)]:
    pred=model.predict(X)
    print(f"\n=== {name} ===")
    print("Accuracy:",round(accuracy_score(y,pred),4))
    print(classification_report(y,pred,digits=4))
OUT.parent.mkdir(parents=True,exist_ok=True)
joblib.dump(model,OUT)
print(f"\nSaved: {OUT}")
