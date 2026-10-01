import pandas as pd, joblib
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report

D="ml_security/data/large/qbc_sage_augmented_100k.csv"
V="ml_security/data/dataset/QBC-RAG-1200-Query-Dataset/QBC-RAG_1200_validation.csv"
T="ml_security/data/dataset/QBC-RAG-1200-Query-Dataset/QBC-RAG_1200_test.csv"

d=pd.read_csv(D); v=pd.read_csv(V); t=pd.read_csv(T)
print("Training Student v3:",len(d),"rows")
features=FeatureUnion([
("word",TfidfVectorizer(ngram_range=(1,3),min_df=2,sublinear_tf=True,max_features=300000)),
("char",TfidfVectorizer(analyzer="char_wb",ngram_range=(3,5),min_df=2,sublinear_tf=True,max_features=200000))
])
model=Pipeline([("features",features),("clf",LogisticRegression(max_iter=3000,class_weight="balanced",C=8.0,n_jobs=-1))])
model.fit(d["query"],d["label"])
for name,z in [("VALIDATION",v),("TEST",t)]:
    pred=model.predict(z["query"])
    print("\n===",name,"===")
    print("Accuracy:",round(accuracy_score(z["label"],pred),4))
    print(classification_report(z["label"],pred,digits=4))
joblib.dump(model,"ml_security/models/qbc_sage_student_C8.0.joblib")
print("\nSaved: ml_security/models/qbc_sage_student_C8.0.joblib")
