#!/usr/bin/env bash
set -euo pipefail

DATASET="${1:-backend/core/ml/models/training_data.csv}"
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -x ".venv/bin/python" ]]; then
  .venv/bin/python backend/core/ml/train_model.py "$DATASET" --model-path backend/core/ml/models/exploit_predictor.joblib
elif command -v docker >/dev/null 2>&1 && docker compose ps --services --filter status=running 2>/dev/null | grep -qx "backend"; then
  if docker compose exec -T backend test -f core/ml/train_model.py >/dev/null 2>&1; then
    docker compose exec -T backend python core/ml/train_model.py "../$DATASET" --model-path core/ml/models/exploit_predictor.joblib
  else
    echo "Backend container is stale. Run: docker compose up -d --build backend"
    exit 1
  fi
else
  python backend/core/ml/train_model.py "$DATASET" --model-path backend/core/ml/models/exploit_predictor.joblib
fi
