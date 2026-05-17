#!/usr/bin/env bash
set -euo pipefail

MONTHS="${MONTHS:-24}"
MAX_PAGES="${MAX_PAGES:-}"
EPSS_LIMIT="${EPSS_LIMIT:-50000}"

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

run_backend_python() {
  local code="$1"
  if command -v docker >/dev/null 2>&1 && docker compose ps --services --filter status=running 2>/dev/null | grep -qx "backend"; then
    if docker compose exec -T backend python -c "import core.ingestion.nvd_fetcher" >/dev/null 2>&1; then
      docker compose exec -T backend python -c "$code"
      return
    fi
    cat <<'EOF'
Your backend container is running, but it was built before the new NVD importer files existed.
Rebuild it, then rerun the import:

  docker compose up -d --build backend
  MONTHS=1 MAX_PAGES=1 ./scripts/import_nvd_data.sh

EOF
    exit 1
  fi

  if [[ -x ".venv/bin/python" ]]; then
    .venv/bin/python -c "$code"
    return
  fi

  if ! python -c "import neo4j, httpx" >/dev/null 2>&1; then
    cat <<'EOF'
SecureGraph backend Python dependencies are not installed in this shell.

Use one of these options:
  1. Start Docker first, then rerun this import:
     docker compose up -d --build
     MONTHS=1 MAX_PAGES=1 ./scripts/import_nvd_data.sh

  2. Or install local backend dependencies:
     python -m venv .venv
     source .venv/bin/activate
     pip install -r backend/requirements.txt
     MONTHS=1 MAX_PAGES=1 ./scripts/import_nvd_data.sh
EOF
    exit 1
  fi

  PYTHONPATH="$ROOT_DIR/backend" python -c "$code"
}

if [[ -n "$MAX_PAGES" ]]; then
  run_backend_python "import asyncio; from core.ingestion.nvd_fetcher import import_recent_cves; print(asyncio.run(import_recent_cves(months=${MONTHS}, max_pages=${MAX_PAGES})))"
else
  run_backend_python "import asyncio; from core.ingestion.nvd_fetcher import import_recent_cves; print(asyncio.run(import_recent_cves(months=${MONTHS})))"
fi

run_backend_python "import asyncio; from core.ingestion.epss_fetcher import import_epss; print(asyncio.run(import_epss(limit=${EPSS_LIMIT})))"
