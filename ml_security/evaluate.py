from pathlib import Path
import json,joblib,pandas as pd
from sklearn.metrics import accuracy_score,precision_recall_fscore_support,confusion_matrix,classification_report
ROOT=Path(__file__).resolve().parent; DATA=ROOT/'data'; ART=ROOT/'artifacts'; REP=ROOT/'reports'; REP.mkdir(exist_ok=True)
b=joblib.load(ART/'decision_model.joblib'); df=pd.read_csv(DATA/'test.csv'); pred=b['classifier'].predict(b['vectorizer'].transform(df['query'])); y=df['decision']
p,r,f,_=precision_recall_fscore_support(y,pred,average='macro',zero_division=0); labels=['SAFE','REVIEW','REJECT']; out={'test_rows':len(df),'accuracy':accuracy_score(y,pred),'macro_precision':p,'macro_recall':r,'macro_f1':f,'confusion_matrix':confusion_matrix(y,pred,labels=labels).tolist(),'classification_report':classification_report(y,pred,labels=labels,output_dict=True,zero_division=0)}
(REP/'baseline_metrics.json').write_text(json.dumps(out,indent=2)); print(json.dumps(out,indent=2))
