#!/usr/bin/env bash
set -euo pipefail

docker compose up -d neo4j
echo "Neo4j is starting at http://localhost:7474 (neo4j/password)"
