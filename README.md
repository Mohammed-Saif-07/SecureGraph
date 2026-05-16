# SecureGraph

AI-powered vulnerability intelligence platform that turns CVE lists into attack paths, patch ROI, and grounded graph answers.

## Quick Start

```bash
cd securegraph
docker compose up --build
```

Open:

- Frontend: http://localhost:5173
- Backend docs: http://localhost:8000/docs
- Neo4j browser: http://localhost:7474 (`neo4j` / `password`)

Optional free keys:

```bash
export GROQ_API_KEY=your_free_groq_key
export GITHUB_TOKEN=your_free_github_token
```

Without keys, SecureGraph still runs with deterministic graph-grounded answers and a seeded demo attack graph.

## What Works

- FastAPI backend with Neo4j, PostgreSQL, Redis, and Docker Compose.
- NVD, EPSS, MITRE ATT&CK, OSV, and GitHub Advisory integration modules.
- Repository and manifest scanning for `requirements.txt` and `package.json`.
- Attack path traversal from CVE to package to service to server to business data.
- Patch ROI ranking based on graph reachability and exploit likelihood.
- Graph-grounded LLM answers via Groq `llama-3.1-8b-instant`, with deterministic fallback.
- React + D3 force-directed attack graph.
- PDF report export.
- Kubernetes manifests for Minikube-style deployment.
- GitHub Actions CI.

## Kubernetes

```bash
kubectl apply -f kubernetes/configmap.yaml
kubectl apply -f kubernetes/deployment.yaml
kubectl apply -f kubernetes/service.yaml
```

For Minikube local images:

```bash
eval "$(minikube docker-env)"
docker compose build
kubectl apply -f kubernetes/
```
