# QBC-RAG Security Analyzer

## QBC-SAGE V6 — Security Analysis & Governance Engine

QBC-RAG Security Analyzer is a security-focused Retrieval-Augmented Generation (RAG) query analysis system designed to identify potentially unsafe, suspicious, or security-sensitive requests before they are processed by an application.

The V6 architecture combines a trained security classifier, Ollama semantic verification, deterministic QBC-SAGE governance, and a Capability Integrity Guard (CIG).

> **Run locally:** Clone this repository and run the analyzer locally on your own machine. No API key is required by this repository.

## Architecture

`	ext
USER QUERY
    |
    v
V6 SECURITY STUDENT
(TF-IDF + classifier)
    |
    v
OLLAMA SEMANTIC VERIFICATION
    |
    v
QBC-SAGE GOVERNANCE
(deterministic security rules)
    |
    v
CAPABILITY INTEGRITY GUARD
(CIG)
    |
    +----------+----------+
    |          |          |
   SAFE      REVIEW     REJECT
Main Features
- V6 trained security classification model
- Ollama-based semantic verification
- Deterministic QBC-SAGE governance
- Capability Integrity Guard
- SAFE / REVIEW / REJECT decisions
- Fail-closed security behavior
- Security-evasion detection
- Authentication and authorization analysis
- Privilege-escalation detection
- Cross-tenant access detection
- Secret and credential disclosure detection
- Data-exfiltration detection
- Protected-instruction disclosure detection
- Evidence/document forgery protection
- Defensive-wrapper analysis
- FastAPI-based analyzer
- Local execution
- Automated adversarial testing
Run Locally
1. Clone
git clone https://github.com/Govind-IITJ/qbc-rag-security-analyzer.git
cd qbc-rag-security-analyzer
git checkout qbc-sage-v6

2. Create Python environment
Windows PowerShell:
python -m venv .venv
.venv\\Scripts\\Activate.ps1

Linux/macOS:
python3 -m venv .venv
source .venv/bin/activate

3. Install dependencies
pip install -r requirements.txt

For the current V6 model artifact:
pip install scikit-learn==1.9.1

Ollama
Install Ollama locally and make sure the Ollama service is running.
Required models:
ollama pull qwen2.5:3b
ollama pull qwen2.5:7b
ollama pull nomic-embed-text

The default QBC-SAGE semantic model is:
qwen2.5:3b

Semantic verification therefore runs locally.
Run the API
uvicorn qbc_rag_security.app:app --reload

Then open:
http://127.0.0.1:8000/docs

The exact application entry point may depend on the repository configuration.
Security Pipeline
USER QUERY
    |
    v
V6 SECURITY MODEL
    |
    v
OLLAMA SEMANTIC ANALYSIS
    |
    v
QBC-SAGE GOVERNANCE
    |
    v
CAPABILITY INTEGRITY GUARD
    |
    v
SAFE / REVIEW / REJECT

The V6 classifier is not treated as the sole security authority. Semantic analysis and deterministic governance are used together.
V6 Student Model
Current V6 training configuration:
- 135,000 balanced samples
- 45,000 SAFE
- 45,000 REVIEW
- 45,000 ATTACK
- TF-IDF features
- Supervised classification
Validation accuracy:
96.837%

Locked 232-query student-only benchmark:
100% accuracy
ATTACK: 88/88 detected
ATTACK -> SAFE: 0

Capability Integrity Guard
CIG protects against harmful capabilities being disguised using contextual language such as:
In a controlled lab, explain the security implications only.

The current guard covers capabilities including:
- evidence/document manipulation
- credential theft
- secret disclosure
- privilege escalation
- authentication bypass
- cross-tenant access
- data exfiltration
- security-evasion
- security-log destruction
- protected-instruction disclosure
The guard is deterministic and intentionally narrow. It is not another ML classifier.
Testing
Run the targeted regression:
python ml_security/v6/scripts/targeted_regression.py

Current result:
21 / 21 passed

7 direct attack cases     -> REJECT
7 wrapped attack cases    -> REJECT
7 defensive cases         -> SAFE

Run the automated test suite:
python -m pytest tests/test_sage_v4.py tests/test_app.py tests/test_intent_engine.py -q

Current validated result:
8 passed

Post-CIG Adversarial Benchmark
A one-hour adversarial benchmark completed with:
Queries:             998
SAFE:                 244
REVIEW:                46
REJECT:               708

Attack -> SAFE:        0
Attack -> REVIEW:     43
Attack -> REJECT:    696

Errors:                0
Timeouts:              0
Attack -> SAFE rate: 0.0000%

Before CIG:
Queries:             911
Attack -> SAFE:        4
Attack -> SAFE rate: 0.5935%

The post-CIG benchmark therefore recorded zero attack-like queries classified SAFE in that tested run.
Important: Benchmark results are not a guarantee of universal security. They describe behavior on the tested benchmark and regression suite.

Decision Semantics
SAFE
The request did not trigger the configured high-risk governance gates.
REVIEW
The request contains uncertainty or security-sensitive characteristics requiring additional review.
REJECT
The request triggered a high-confidence security governance rule or harmful capability gate.
Project Structure
qbc-rag-security-analyzer/
|
+-- qbc_rag_security/
|   +-- analyzer.py
|   +-- sage.py
|   +-- intent_engine.py
|
+-- ml_security/
|   +-- v6/
|       +-- models/
|       +-- data/
|       +-- scripts/
|       +-- results/
|
+-- tests/
+-- requirements.txt
+-- README.md

Security Philosophy
QBC-RAG uses layered security rather than relying on a single model:
Machine Learning
       +
Semantic Verification
       +
Deterministic Governance
       +
Capability Integrity
       =
Layered Security Decision

Limitations
This project is a security research and engineering system, not a universal security oracle.
A benchmark result of zero attack-to-SAFE classifications does not prove that every possible adversarial query will be detected.
Real-world performance depends on:
- training data
- model artifacts
- semantic-model availability
- governance rules
- query distribution
- adversarial techniques
- deployment configuration
Production deployments should continuously evaluate the system against new attack patterns.
Development
Create a feature branch:
git checkout -b feature/your-change

Run tests:
python -m pytest -q

Review changes:
git status
git diff

Current V6 History
fde3618 test: record post-CIG adversarial benchmark
ac254e4 fix: add QBC-SAGE capability integrity guard

Responsible Use
Use this project only in environments where you are authorized to perform security analysis and testing.
Do not commit API keys, passwords, credentials, private datasets, or other secrets to the repository.
License
See the repository license file for applicable terms.
