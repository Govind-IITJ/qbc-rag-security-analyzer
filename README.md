# QBC-RAG Security Analyzer v2.1

A credit-free, research-grade security analysis website for QBC-RAG.

This edition deliberately does **not** call an external LLM. It analyzes query behavior locally,
produces explainable risk/features, stores experiments in SQLite, and exposes benchmark/evaluation
dashboards.

## Run locally

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --reload
```

Open http://127.0.0.1:8000

## Docker

```bash
docker build -t qbc-rag-security .
docker run --rm -p 8000:8000 qbc-rag-security
```

## Render

This repository includes `render.yaml` and a Dockerfile. Deploy the repository as a Docker web
service. No LLM or paid API key is required.

## API

- `POST /api/analyze`
- `GET /api/history`
- `DELETE /api/history`
- `GET /api/evaluation/summary`
- `POST /api/evaluation/benchmark`
- `GET /api/attacks`
- `GET /api/metrics/live`

## Research framing

The supplied QBC-RAG v2.1 report describes evidence governance between retrieval and generation,
and records a 60-case security regression benchmark with 100% detection, 100% rejection,
100% containment and 0% attack success. Those recorded values are shown as historical benchmark
results in the UI, while newly run local experiments are stored separately.

The report also explicitly notes that 0% attack success does not prove universal security and that
the single benign case is not enough to establish a robust false-positive rate.

## Important scope

The analyzer is a deterministic security-analysis layer, not a general-purpose LLM. It should be
used as a research/demo security gate and expanded with larger benign/adversarial datasets before
making production-security claims.
