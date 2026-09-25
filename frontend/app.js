const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
const state={last:null, attacks:[]};
function esc(s){return String(s??"").replace(/[&<>"']/g,m=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[m]))}
function page(name){$$(".page").forEach(x=>x.classList.toggle("active",x.id===name));$$(".navbtn").forEach(x=>x.classList.toggle("active",x.dataset.page===name));window.scrollTo({top:0,behavior:"smooth"});if(name==="experiments")loadHistory();if(name==="benchmark")loadSummary();if(name==="attacks")loadAttacks()}
$$(".navbtn").forEach(b=>b.onclick=()=>page(b.dataset.page));
$("#theme").onclick=()=>document.body.classList.toggle("light");
$("#query").oninput=()=>$("#charcount").textContent=`${$("#query").value.length} / 10000`;
$$(".examples button").forEach(b=>b.onclick=()=>{$("#query").value=b.dataset.example;$("#query").dispatchEvent(new Event("input"));});
$("#analyze").onclick=analyze;
async function analyze(){
 const q=$("#query").value.trim(); if(!q){$("#query").focus();return}
 const btn=$("#analyze");btn.disabled=true;btn.innerHTML="Analyzing…";
 try{
  const r=await fetch("/api/analyze",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({query:q,expected:$("#expected").value||null})}).then(x=>x.json());
  state.last=r;renderResult(r);$("#details").classList.remove("hidden");
 }catch(e){alert("Analyzer request failed: "+e.message)}finally{btn.disabled=false;btn.innerHTML="Analyze Query <span>↗</span>"}
}
function renderResult(r){
 const d=r.decision.toLowerCase(), risk=r.risk_score;
 $("#verdictTitle").textContent=d==="reject"?"Vulnerable query":d==="review"?"Review required":"Query appears safe";
 $("#decisionPill").textContent=r.decision;$("#decisionPill").className="pill "+(d==="reject"?"reject":d==="review"?"review":"safe");
 $("#risk").textContent=risk.toFixed(1);$("#confidence").textContent=r.confidence.toFixed(1)+"%";$("#decision").textContent=r.decision;$("#latency").textContent=r.latency_ms.toFixed(2)+" ms";$("#hash").textContent="SHA-256 "+r.query_hash;
 const deg=Math.max(1,Math.min(360,risk*3.6));$(".gauge").style.background=`conic-gradient(${d==="reject"?"var(--red)":d==="review"?"var(--amber)":"var(--green)"} 0deg ${deg}deg,#223143 ${deg}deg 360deg)`;
 $("#findings").innerHTML=r.findings.length?r.findings.map(f=>`<div class="finding"><div class="findingtop"><h3>${esc(f.label)}</h3><span class="sev ${f.severity}">${esc(f.severity)}</span></div><p>${esc(f.rationale)}</p><span class="evidence">${esc(f.matched_evidence[0]||"matched behavior")}</span></div>`).join(""):`<div class="finding"><h3>No adversarial pattern detected</h3><p>The current deterministic detector did not find a released attack-family signal. This is not a proof of universal safety.</p></div>`;
 $("#features").innerHTML=Object.entries(r.behavior_vector).map(([k,v])=>`<div>${esc(k)}</div><div>${v.toFixed(1)}%</div><div class="featurebar"><i style="width:${v}%"></i></div>`).join("");
 drawRadar(r.behavior_vector);
}
function drawRadar(v){
 const c=$("#radar"),ctx=c.getContext("2d"),dpr=devicePixelRatio||1,w=c.clientWidth||500,h=c.clientHeight||330;c.width=w*dpr;c.height=h*dpr;ctx.scale(dpr,dpr);ctx.clearRect(0,0,w,h);
 const vals=Object.values(v),labels=Object.keys(v),n=vals.length,cx=w/2,cy=h/2,r=Math.min(w,h)*.34;
 ctx.strokeStyle="#253342";ctx.fillStyle="rgba(80,228,223,.12)";ctx.lineWidth=1;
 for(let ring=1;ring<=4;ring++){ctx.beginPath();for(let i=0;i<n;i++){let a=-Math.PI/2+i*2*Math.PI/n,x=cx+Math.cos(a)*r*ring/4,y=cy+Math.sin(a)*r*ring/4;i?ctx.lineTo(x,y):ctx.moveTo(x,y)}ctx.closePath();ctx.stroke()}
 ctx.beginPath();vals.forEach((val,i)=>{let a=-Math.PI/2+i*2*Math.PI/n,x=cx+Math.cos(a)*r*val/100,y=cy+Math.sin(a)*r*val/100;i?ctx.lineTo(x,y):ctx.moveTo(x,y)});ctx.closePath();ctx.fill();ctx.strokeStyle="#50e4df";ctx.stroke();
 ctx.fillStyle="#8e9bad";ctx.font="10px JetBrains Mono";labels.forEach((lab,i)=>{let a=-Math.PI/2+i*2*Math.PI/n;ctx.fillText(lab,cx+Math.cos(a)*(r+22)-25,cy+Math.sin(a)*(r+22)+4)})
}
async function loadHistory(){
 const r=await fetch("/api/history").then(x=>x.json());const rows=r.experiments||[];
 $("#history").innerHTML=rows.length?rows.map(x=>`<div class="historyrow"><span class="time">${esc(x.created_at)}</span><span class="q">${esc(x.query)}</span><span class="id">${esc(x.id)}</span><span class="result ${x.decision==="REJECT"?"reject":x.decision==="REVIEW"?"review":"safe"}">${esc(x.decision)} · ${x.risk_score}%</span></div>`).join(""):`<div class="empty">No labeled experiments yet. Analyze queries with Ground truth selected to build evaluation history.</div>`;
 const s=await fetch("/api/evaluation/summary").then(x=>x.json());$("#liveStats").innerHTML=[["TESTS",s.tests],["ACCURACY",s.accuracy+"%"],["PRECISION",s.precision+"%"],["RECALL",s.recall+"%"],["F1",s.f1+"%"]].map(x=>`<div class="kpi"><span>${x[0]}</span><strong>${x[1]}</strong></div>`).join("");
}
$("#clearHistory").onclick=async()=>{if(confirm("Clear all experiment history?")){await fetch("/api/history",{method:"DELETE"});loadHistory()}};
async function loadSummary(){
 const r=await fetch("/api/evaluation/summary").then(x=>x.json());$("#benchKpis").innerHTML=[["LAB TESTS",r.tests],["ACCURACY",r.accuracy+"%"],["PRECISION",r.precision+"%"],["RECALL",r.recall+"%"],["F1",r.f1+"%"]].map(x=>`<div class="kpi"><span>${x[0]}</span><strong>${x[1]}</strong></div>`).join("");
 $("#confusion").innerHTML=`<label>CONFUSION MATRIX · LABELED TESTS</label><div class="matrix"><div></div><div class="head">PRED SAFE</div><div class="head">PRED ATTACK</div><div class="head">ACTUAL SAFE</div><div>${r.confusion_matrix.tn}</div><div>${r.confusion_matrix.fp}</div><div class="head">ACTUAL ATTACK</div><div>${r.confusion_matrix.fn}</div><div>${r.confusion_matrix.tp}</div></div>`;
 $("#benchNote").innerHTML=`<label>INTERPRETATION</label><h2>Live experiments are separate from the recorded suite.</h2><p style="color:var(--muted);line-height:1.7">Only experiments with an explicit ground-truth label contribute to accuracy, precision, recall and F1. Unlabeled analyses remain useful security observations but are not silently counted as performance evidence.</p>`;
}
$("#runBench").onclick=async()=>{const b=$("#runBench");b.disabled=true;b.textContent="Running benchmark…";const r=await fetch("/api/evaluation/benchmark",{method:"POST"}).then(x=>x.json());const x=r.benchmark;$("#benchKpis").innerHTML=[["CASES",x.total],["ACCURACY",x.accuracy+"%"],["DETECTION",x.attack_detection_rate+"%"],["ATTACK SUCCESS",x.attack_success_rate+"%"],["FPR",x.false_positive_rate+"%"]].map(a=>`<div class="kpi"><span>${a[0]}</span><strong>${a[1]}</strong></div>`).join("");$("#confusion").innerHTML=`<label>CONFUSION MATRIX · LOCAL BENCHMARK</label><div class="matrix"><div></div><div class="head">PRED SAFE</div><div class="head">PRED ATTACK</div><div class="head">ACTUAL SAFE</div><div>${x.confusion_matrix.tn}</div><div>${x.confusion_matrix.fp}</div><div class="head">ACTUAL ATTACK</div><div>${x.confusion_matrix.fn}</div><div>${x.confusion_matrix.tp}</div></div>`;$("#benchNote").innerHTML=`<label>RESULT</label><h2>${esc(x.status)}</h2><p style="color:var(--muted);line-height:1.7">${esc(x.note)}</p>`;b.disabled=false;b.textContent="Run benchmark ↗"};
async function loadAttacks(){if(state.attacks.length===0)state.attacks=(await fetch("/api/attacks").then(x=>x.json())).attacks;renderAttacks()}
function renderAttacks(){const q=$("#attackSearch").value.toLowerCase();$("#attackGrid").innerHTML=state.attacks.filter(a=>(a.id+a.category+a.query).toLowerCase().includes(q)).map(a=>`<article class="attack"><span class="aid">${esc(a.id)}</span><h3>${esc(a.category.replaceAll("_"," "))}</h3><p>${esc(a.query)}</p></article>`).join("")}
$("#attackSearch").oninput=renderAttacks;
loadAttacks();
