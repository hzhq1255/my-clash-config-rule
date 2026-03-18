#!/bin/bash
# Deploy script for Racknerd server

set -e

SERVER_USER="root"
SERVER_HOST="your-racknerd-host"
SERVICES_DIR="/root/services"
IMAGE="ghcr.io/hzhq1255/my-clash-config-rule/subserver:0.0.1"

echo "Deploying subserver to Racknerd..."

# Copy docker-compose override to server
scp docker-compose.prod.yml ${SERVER_USER}@${SERVER_HOST}:${SERVICES_DIR}/docker-compose.subserver.yml

# Pull latest image
ssh ${SERVER_USER}@${SERVER_HOST} "cd ${SERVICES_DIR} && docker-compose -f docker-compose.subserver.yml pull"

# Restart service
ssh ${SERVER_USER}@${SERVER_HOST} "cd ${SERVICES_DIR} && docker-compose -f docker-compose.subserver.yml up -d sub-server"

# Wait for health check
echo "Waiting for service to be healthy..."
sleep 10

# Check service status
ssh ${SERVER_USER}@${SERVER_HOST} "docker-compose -f ${SERVICES_DIR}/docker-compose.subserver.yml ps sub-server"

echo "Deployment completed!"
