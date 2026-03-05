#!/bin/bash

# Script to rebuild Docker containers and clean up old images/cache
# This prevents disk space from accumulating

echo "🔨 Building containers..."
docker compose -f docker-compose.production.yml up --build -d

echo ""
echo "🧹 Cleaning up old Docker images and cache..."
# Remove old images that aren't being used
docker image prune -a -f

# Remove build cache older than 24 hours
docker builder prune -a -f --filter "until=24h"

echo ""
echo "✅ Done! Docker resources cleaned up."
echo ""
echo "📊 Current Docker disk usage:"
docker system df
