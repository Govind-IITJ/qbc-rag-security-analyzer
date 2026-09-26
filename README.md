# QBC-RAG Security Analyzer v2.1

**A deterministic, explainable, credit-free security analysis layer for LLM/RAG queries.**

QBC-RAG Security Analyzer v2.1 is a research-oriented security gate that analyzes query behavior **locally**, without calling an external LLM or requiring a paid API key. It normalizes input, detects suspicious patterns, maps them to security categories, generates structured findings, computes a bounded risk score, and returns an explicit:

**SAFE · REVIEW · REJECT**

decision.

> **Research scope:** This repository is a security-analysis layer and research/demo system. It is not a general-purpose LLM and should not be interpreted as a universal security guarantee.

---

## Why this project?

Retrieval-Augmented Generation (RAG) systems can improve the factual grounding of LLM applications, but the query and retrieval pipeline can also be exposed to adversarial behavior.

A security gate can therefore be placed before sensitive processing to provide:

- deterministic analysis
- explainable findings
- explicit risk scoring
- structured security evidence
- reproducible regression testing
- local, credit-free execution

The analyzer is deliberately designed so that the core security decision does **not** depend on an external generative model.

---

## Key Features

| Capability | Description |
|---|---|
| **Local analysis** | Query analysis runs locally without an external LLM |
| **Credit-free** | No paid LLM/API key is required |
| **Deterministic** | The same input produces reproducible analysis behavior |
| **Explainable** | Findings expose category, matched pattern, confidence, severity, and evidence |
| **Risk scoring** | Multiple findings are aggregated into a bounded risk score |
| **Security decisions** | Produces `SAFE`, `REVIEW`, or `REJECT` |
| **SQLite experiments** | Analysis history can be stored locally |
| **Benchmark API** | Local regression evaluation can be executed through the API |
| **Evaluation dashboard** | Summary metrics and benchmark results are exposed |
| **Batch analysis** | Multiple queries can be analyzed together through the web interface |
| **Docker-ready** | Includes a Dockerfile |
| **Render-ready** | Includes `render.yaml` for deployment |
| **No external LLM dependency** | The analyzer itself does not call an LLM |

---

# 1. System Architecture

The processing path is intentionally simple and auditable:

```text
                    USER QUERY
                        │
                        ▼
               ┌─────────────────┐
               │   NORMALIZATION  │
               └────────┬────────┘
                        │
                        ▼
               ┌─────────────────┐
               │ PATTERN MATCHING │
               └────────┬────────┘
                        │
                        ▼
               ┌─────────────────┐
               │ CATEGORY +       │
               │ SEVERITY LOGIC   │
               └────────┬────────┘
                        │
                        ▼
               ┌─────────────────┐
               │ FINDING OBJECTS  │
               └────────┬────────┘
                        │
                        ▼
               ┌─────────────────┐
               │ RISK AGGREGATION │
               └────────┬────────┘
                        │
                        ▼
             ┌────────────────────────┐
             │ SAFE / REVIEW / REJECT │
             └────────────────────────┘
```

The important design boundary is between **query analysis** and any downstream LLM/RAG processing. The analyzer can therefore be studied independently as a deterministic security component.

---

# 2. Threat Analysis Model

The rule library covers multiple adversarial behavior families, including categories such as:

- Prompt Injection
- Jailbreak Attempts
- Secret / Data Exfiltration
- Malicious Code
- Tool Manipulation
- Cross-Tenant Access
- Knowledge Poisoning
- Provenance Spoofing
- Retrieval Manipulation
- Duplicate-Source Manipulation
- Memory Poisoning
- Authority Spoofing
- Role Hijacking
- Hidden Text
- Context Flooding
- Resource Exhaustion
- Membership / Index Inference
- Embedding Leakage
- Excessive Agency
- Cross-Tool Exfiltration
- Database Extraction
- Backdoor-style behavior

The exact rule library is implemented in the repository and should be treated as the source of truth for the currently supported patterns.

Each detected pattern produces a structured finding rather than only a binary flag.

Conceptually:

```text
Finding
├── category
├── pattern / rule
├── confidence
├── severity
├── evidence
├── matched span
├── context
└── metadata
```

This structure makes the decision traceable and suitable for regression testing.

---

# 3. Risk Scoring

For matched pattern confidences \(c_i\), the analyzer uses the following base-risk aggregation:

\[
R_0 =
1-\prod_i \left(1-\min(0.99,c_i)\right)
\]

where:

- \(c_i\) is the confidence of the \(i\)-th matched pattern
- \(R_0\) is the aggregated base risk

Structural signals can then contribute to the final score:

\[
R =
\min\left(
1,\,
R_0 + 0.08\sum_j s_j
\right)
\]

where:

- \(s_j\) is a structural signal
- \(R\) is the final bounded risk score

The score is mapped to an explicit security decision:

| Decision | Risk range |
|---|---:|
| **SAFE** | \(R < 0.30\) |
| **REVIEW** | \(0.30 \le R < 0.60\) |
| **REJECT** | \(R \ge 0.60\) |

> These thresholds describe the implemented analyzer policy. They should not be interpreted as universal risk standards.

---

# 4. Explainability

A major research objective is to make security decisions inspectable.

For every analyzed query, the system can expose information such as:

```json
{
  "decision": "REJECT",
  "risk_score": 96.4,
  "confidence": 96.4,
  "finding_count": 1,
  "findings": [
    {
      "category": "prompt_injection",
      "name": "ignore_previous_instructions",
      "confidence": 0.96,
      "severity": "critical",
      "evidence": "ignore previous instructions"
    }
  ]
}
```

The exact response schema is defined by the running application version.

This makes the analyzer useful for:

- debugging detection rules
- auditing decisions
- building regression tests
- comparing rule revisions
- studying false positives and false negatives

---

# 5. Benchmark and Evaluation

The repository contains a **local regression benchmark** used to evaluate the deterministic analyzer.

## Current local regression benchmark

The current benchmark contains:

| Class | Cases |
|---|---:|
| Attack | **60** |
| Benign | **4** |
| **Total** | **64** |

The benchmark is intentionally fixed so that rule changes can be evaluated against the same regression corpus.

### Recorded benchmark result

The current regression run recorded:

| Metric | Result |
|---|---:|
| Accuracy | **100.00%** |
| Precision | **100.00%** |
| Recall | **100.00%** |
| F1 | **100.00%** |
| Attack Detection Rate | **100%** |
| Attack Rejection Rate | **100%** |
| Attack Containment Rate | **100%** |
| Attack Success Rate | **0%** |
| False Positive Rate | **0%** |
| True Positives | **60** |
| True Negatives | **4** |
| False Positives | **0** |
| False Negatives | **0** |

Confusion matrix:

```text
                         PREDICTED
                    ATTACK       BENIGN
                ┌────────────┬────────────┐
ACTUAL ATTACK   │ TP = 60    │ FN = 0     │
                ├────────────┼────────────┤
ACTUAL BENIGN   │ FP = 0     │ TN = 4     │
                └────────────┴────────────┘
```

### Important scientific qualification

These results describe performance on the **fixed 64-case local regression corpus**.

They do **not** establish universal security against:

- unseen attacks
- novel prompt-injection variants
- distribution shifts
- larger real-world workloads
- different application domains
- adversarial adaptation against the detector

The benchmark is therefore best understood as a **regression and reproducibility instrument**, not as proof of production-grade universal protection.

---

# 6. Development Regression

The project uses failure-driven regression refinement.

Representative development cases include:

```text
PI-003
Prompt Injection
        │
        ▼
Detection-rule refinement
        │
        ▼
DUP-001
Duplicate Source Manipulation
        │
        ▼
Pattern refinement
        │
        ▼
POISON-003
Knowledge Poisoning
        │
        ▼
Rule refinement
        │
        ▼
64-case regression benchmark
```

These cases document individual rule-development failures and fixes. They should not be interpreted as a complete catalogue of detector weaknesses.

---

# 7. Web Application

The repository includes a browser-based interface for interactive analysis and evaluation.

The interface supports:

- single-query security analysis
- batch analysis
- risk and decision visualization
- structured findings
- analysis history
- benchmark execution
- evaluation summaries
- live metrics

The batch analyzer is intended for quickly testing multiple queries against the same local rule engine.

---

# 8. API

The application exposes the following primary endpoints:

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/api/analyze` | Analyze a query |
| `GET` | `/api/history` | Retrieve stored analysis history |
| `DELETE` | `/api/history` | Clear analysis history |
| `GET` | `/api/evaluation/summary` | Retrieve evaluation summary |
| `POST` | `/api/evaluation/benchmark` | Run the regression benchmark |
| `GET` | `/api/attacks` | Inspect benchmark attack cases |
| `GET` | `/api/metrics/live` | Retrieve live system metrics |

Health endpoint:

```text
GET /health
```

---

# 9. Run Locally

## Windows

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app:app --reload
```

Open:

```text
http://127.0.0.1:8000
```

## macOS / Linux

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --reload
```

Then open:

```text
http://127.0.0.1:8000
```

---

# 10. Docker

Build:

```bash
docker build -t qbc-rag-security .
```

Run:

```bash
docker run --rm -p 8000:8000 qbc-rag-security
```

Open:

```text
http://127.0.0.1:8000
```

---

# 11. Render Deployment

The repository includes:

```text
Dockerfile
render.yaml
```

The analyzer does not require an external LLM or paid API key.

A Docker web service can therefore be deployed using the repository's Render configuration.

Live demonstration:

**https://qbc-rag-security-analyzer.onrender.com/**

Repository:

**https://github.com/Govind-IITJ/qbc-rag-security-analyzer**

---

# 12. Project Structure

```text
qbc-rag-security-analyzer/
│
├── app.py
├── requirements.txt
├── Dockerfile
├── render.yaml
├── README.md
│
├── qbc_rag_security/
│   ├── __init__.py
│   ├── analyzer.py
│   └── benchmark.py
│
├── frontend/
│   ├── index.html
│   ├── styles.css
│   └── app.js
│
└── tests/
    └── test_app.py
```

The exact repository structure may evolve as the research prototype develops.

---

# 13. Testing

Run the automated tests:

```bash
python -m pytest -q
```

Run the benchmark through the application API after starting the server, or use the evaluation interface provided by the web application.

A successful benchmark should be interpreted together with its fixed corpus size and scope.

---

# 14. Research Reproducibility

A central goal of this project is reproducible security experimentation.

A basic experiment can follow:

```text
1. Start a clean environment
        ↓
2. Install requirements
        ↓
3. Start the application
        ↓
4. Run the fixed regression benchmark
        ↓
5. Record confusion matrix and metrics
        ↓
6. Modify detection rules
        ↓
7. Re-run benchmark
        ↓
8. Compare regressions
```

Because the core analyzer is deterministic and local, experiments do not require LLM inference credits.

---

# 15. Relationship to QBC-RAG

QBC-RAG is framed around evidence governance between retrieval and generation.

The Security Analyzer is a complementary security-analysis layer focused specifically on **query-level threat detection and risk decisioning**.

It should not be described as a byte-for-byte replacement for the original QBC-RAG engine.

The two systems have different scopes:

```text
QBC-RAG
Evidence retrieval + governance + grounded generation
                         │
                         │ security boundary
                         ▼
QBC-RAG Security Analyzer
Local deterministic query security analysis
```

This repository is therefore best understood as a standalone research implementation of the security-analysis concept.

---

# 16. Limitations

This project is intentionally transparent about its current limitations.

### Fixed benchmark

The evaluation corpus is small relative to the diversity of real-world LLM/RAG inputs.

### Rule-based detection

Handcrafted pattern rules can miss semantically novel or obfuscated attacks.

### Distribution shift

Performance on the local regression corpus cannot be assumed to transfer directly to other domains.

### Benign coverage

Four benign cases are useful for regression testing but are not sufficient to establish a robust production false-positive estimate.

### Adaptive attackers

An attacker who knows the detection rules may attempt to construct inputs that evade them.

### Integration scope

The analyzer evaluates query behavior. It does not, by itself, secure every component of an LLM/RAG application.

These limitations motivate broader future evaluation.

---

# 17. Future Research

Potential next steps include:

1. Larger adversarial and benign corpora
2. Automated adversarial mutation
3. Semantic and obfuscation-aware detection
4. Cross-domain evaluation
5. Long-context stress testing
6. External independent validation
7. More systematic false-positive analysis
8. Detector ablation studies
9. Integration-level security evaluation
10. Continuous regression benchmarking

The objective is to move from a deterministic research prototype toward a more extensively validated security-analysis component.

---

# 18. Research Paper

A six-page research-paper version of the project documents the:

- research motivation
- security problem
- architecture
- threat detection model
- mathematical risk aggregation
- benchmark methodology
- recorded evaluation results
- development regression
- limitations
- future research direction

The paper deliberately distinguishes **recorded benchmark performance** from broader security claims.

---

# 19. Citation

If you use this project in academic work, cite the repository and the accompanying research paper.

```text
Govind Prajapat,
"QBC-RAG Security Analyzer v2.1:
A Deterministic, Explainable Security Gate for LLM/RAG Queries,"
2026.
```

Repository:

https://github.com/Govind-IITJ/qbc-rag-security-analyzer

---

# 20. License

---
---

## Research Scope Statement

**QBC-RAG Security Analyzer v2.1 is a deterministic, explainable security-analysis research prototype. Its recorded 64-case regression results demonstrate behavior on the evaluated local corpus only; they do not establish universal security or guarantee protection against all real-world attacks.**

