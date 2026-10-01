import argparse,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from engine import predict
p=argparse.ArgumentParser(); p.add_argument('--query',required=True); p.add_argument('--rule-risk',type=float,default=0); a=p.parse_args()
m=predict(a.query); rule=a.rule_risk/100 if a.rule_risk>1 else a.rule_risk
if not m.get('available'): print(json.dumps({'error':'Train model first.'},indent=2)); raise SystemExit(1)
final=min(1,.45*rule+.55*m['risk'])
if m['probabilities'].get('REJECT',0)>=.80: final=max(final,.70)
dec='SAFE' if final<.30 else 'REVIEW' if final<.70 else 'REJECT'
print(json.dumps({'ml_decision':m['decision'],'ml_risk':round(m['risk'],4),'rule_risk':round(rule,4),'hybrid_risk':round(final,4),'decision':dec,'threat_category':m['threat_category'],'probabilities':{k:round(v,4) for k,v in m['probabilities'].items()}},indent=2))
