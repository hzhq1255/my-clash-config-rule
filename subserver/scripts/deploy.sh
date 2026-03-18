#!/bin/bash

set -euo pipefail

SERVICES_DIR="/root/services"
IMAGE="ghcr.io/hzhq1255/my-clash-config-rule/subserver:0.0.1"

echo "Deploying ${IMAGE} to Racknerd..."
ssh racknerd "python3 - <<'PY'
from pathlib import Path

compose_path = Path('/root/services/docker-compose.yaml')
text = compose_path.read_text()
old = '  sub-server:\n    container_name: sub-server\n    build: ./sub-server\n'
new = '  sub-server:\n    container_name: sub-server\n    image: ghcr.io/hzhq1255/my-clash-config-rule/subserver:0.0.1\n'
if old not in text:
    raise SystemExit('sub-server build block not found or already migrated')
compose_path.write_text(text.replace(old, new, 1))
PY
cd ${SERVICES_DIR} && docker compose pull sub-server && docker compose up -d sub-server && docker compose ps sub-server"

echo "Deployment completed."
