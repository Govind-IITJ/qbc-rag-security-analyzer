import pandas as pd,joblib
from pathlib import Path
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report,accuracy_score

BASE=Path("ml_security/data")
TRAIN=BASE/"large/qbc_sage_augmented_100k.csv"
VAL=BASE/"dataset/QBC-RAG-1200-Query-Dataset/QBC-RAG_1200_validation.csv"
TEST=BASE/"dataset/QBC-RAG-1200-Query-Dataset/QBC-RAG_1200_test.csv"
OUT=Path("ml_security/models/qbc_sage_student_v2.joblib")

train=pd.read_csv(TRAIN)
val=pd.read_csv(VAL); test=pd.read_csv(TEST)

model=Pipeline([
 ("tfidf",TfidfVectorizer(ngram_range=(1,3),min_df=2,sublinear_tf=True,
                          max_features=250000)),
 ("clf",LogisticRegression(max_iter=3000,class_weight="balanced"))
])

print("Training Student v2:",len(train),"rows")
model.fit(train["query"],train["label"])

for name,df in [("VALIDATION",val),("TEST",test)]:
    pred=model.predict(df["query"])
    print(f"\n=== {name} ===")
    print("Accuracy:",round(accuracy_score(df["label"],pred),4))
    print(classification_report(df["label"],pred,digits=4))

OUT.parent.mkdir(parents=True,exist_ok=True)
joblib.dump(model,OUT)
print("\nSaved:",OUT)
