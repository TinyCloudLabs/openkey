#!/bin/bash
# Staging Deployment Script for OpenKey

set -e

echo "🚀 Deploying OpenKey to Staging Environment..."

# Load environment variables
source .env.staging

# Ensure required variables are set
if [[ -z "$STAGING_HOST" || -z "$STAGING_USER" || -z "$STAGING_KEY_PATH" ]]; then
    echo "❌ Missing required environment variables in .env.staging"
    echo "Required: STAGING_HOST, STAGING_USER, STAGING_KEY_PATH"
    exit 1
fi

# Build production images
echo "📦 Building production Docker images..."
cd ../../project
docker build -t openkey/backend:staging -f backend/Dockerfile .
docker build -t openkey/frontend:staging -f frontend/Dockerfile .

# Push to staging registry
echo "📤 Pushing images to staging registry..."
docker tag openkey/backend:staging $STAGING_REGISTRY/openkey/backend:staging
docker tag openkey/frontend:staging $STAGING_REGISTRY/openkey/frontend:staging
docker push $STAGING_REGISTRY/openkey/backend:staging
docker push $STAGING_REGISTRY/openkey/frontend:staging

# Deploy to staging server
echo "🚢 Deploying to staging server..."
ssh -i $STAGING_KEY_PATH $STAGING_USER@$STAGING_HOST << 'ENDSSH'
    cd /opt/openkey
    
    # Pull latest images
    docker-compose -f docker-compose.staging.yml pull
    
    # Run database migrations
    docker-compose -f docker-compose.staging.yml run --rm backend npm run migrate
    
    # Restart services with zero downtime
    docker-compose -f docker-compose.staging.yml up -d --no-deps --scale backend=2 backend
    sleep 10
    docker-compose -f docker-compose.staging.yml up -d --no-deps backend
    
    docker-compose -f docker-compose.staging.yml up -d --no-deps --scale frontend=2 frontend
    sleep 10
    docker-compose -f docker-compose.staging.yml up -d --no-deps frontend
    
    # Clean up old images
    docker image prune -f
ENDSSH

# Run smoke tests
echo "🧪 Running smoke tests..."
cd ../../project/tests
npm run test:staging

# Check deployment health
echo "🏥 Checking deployment health..."
curl -f https://staging.openkey.com/health || {
    echo "❌ Health check failed!"
    exit 1
}

echo "✅ Staging deployment completed successfully!"
echo "🌐 Access at: https://staging.openkey.com"
echo "📊 Monitoring at: https://staging.openkey.com/metrics"