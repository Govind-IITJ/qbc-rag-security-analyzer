from pathlib import Path
import joblib
ROOT=Path(__file__).resolve().parent; ART=ROOT/'artifacts'
class MLEngine:
 def __init__(self):
  self.ready=(ART/'decision_model.joblib').exists() and (ART/'category_model.joblib').exists()
  if self.ready:
   self.d=joblib.load(ART/'decision_model.joblib'); self.c=joblib.load(ART/'category_model.joblib')
 def predict(self,q):
  if not self.ready: return {'available':False}
  X=self.d['vectorizer'].transform([q]); probs=self.d['classifier'].predict_proba(X)[0]; classes=list(self.d['classifier'].classes_); p=dict(zip(classes,map(float,probs))); dec=classes[int(probs.argmax())]
  risk=min(1.0,p.get('REJECT',0)+0.55*p.get('REVIEW',0)); cat='none'
  if dec=='REJECT': cat=str(self.c['classifier'].predict(self.c['vectorizer'].transform([q]))[0])
  return {'available':True,'decision':dec,'risk':risk,'probabilities':p,'threat_category':cat}
_engine=None
def predict(q):
 global _engine
 if _engine is None: _engine=MLEngine()
 return _engine.predict(q)
