#!/bin/bash
# Production Deployment Script for OpenKey

set -e

echo "🚀 Deploying OpenKey to Production Environment..."

# Confirm production deployment
read -p "⚠️  Are you sure you want to deploy to PRODUCTION? (yes/no): " confirm
if [[ "$confirm" != "yes" ]]; then
    echo "❌ Deployment cancelled"
    exit 1
fi

# Load environment variables
source .env.production

# Run pre-deployment checks
echo "🔍 Running pre-deployment checks..."
./pre-deploy-checks.sh || {
    echo "❌ Pre-deployment checks failed!"
    exit 1
}

# Backup current deployment
echo "💾 Creating backup of current deployment..."
ssh -i $PROD_KEY_PATH $PROD_USER@$PROD_HOST << 'ENDSSH'
    cd /opt/openkey
    docker-compose -f docker-compose.production.yml exec -T postgres pg_dump -U openkey openkey > backup-$(date +%Y%m%d-%H%M%S).sql
ENDSSH

# Build and tag production images
echo "📦 Building production Docker images..."
cd ../../project

# Use commit hash for production tags
COMMIT_HASH=$(git rev-parse --short HEAD)
docker build -t openkey/backend:$COMMIT_HASH -f backend/Dockerfile.production .
docker build -t openkey/frontend:$COMMIT_HASH -f frontend/Dockerfile.production .

# Push to production registry
echo "📤 Pushing images to production registry..."
docker tag openkey/backend:$COMMIT_HASH $PROD_REGISTRY/openkey/backend:$COMMIT_HASH
docker tag openkey/frontend:$COMMIT_HASH $PROD_REGISTRY/openkey/frontend:$COMMIT_HASH
docker push $PROD_REGISTRY/openkey/backend:$COMMIT_HASH
docker push $PROD_REGISTRY/openkey/frontend:$COMMIT_HASH

# Update production tags
docker tag $PROD_REGISTRY/openkey/backend:$COMMIT_HASH $PROD_REGISTRY/openkey/backend:latest
docker tag $PROD_REGISTRY/openkey/frontend:$COMMIT_HASH $PROD_REGISTRY/openkey/frontend:latest
docker push $PROD_REGISTRY/openkey/backend:latest
docker push $PROD_REGISTRY/openkey/frontend:latest

# Deploy using blue-green strategy
echo "🚢 Deploying to production (Blue-Green)..."
ssh -i $PROD_KEY_PATH $PROD_USER@$PROD_HOST << ENDSSH
    cd /opt/openkey
    
    # Update image tags
    export IMAGE_TAG=$COMMIT_HASH
    
    # Start green environment
    docker-compose -f docker-compose.production.yml -p openkey-green up -d
    
    # Wait for green to be healthy
    sleep 30
    
    # Run migrations on green
    docker-compose -f docker-compose.production.yml -p openkey-green run --rm backend npm run migrate:production
    
    # Switch load balancer to green
    ./switch-to-green.sh
    
    # Stop blue environment
    docker-compose -f docker-compose.production.yml -p openkey-blue down
    
    # Rename green to blue for next deployment
    docker-compose -f docker-compose.production.yml -p openkey-green down
    docker-compose -f docker-compose.production.yml -p openkey-blue up -d
ENDSSH

# Run production tests
echo "🧪 Running production smoke tests..."
cd ../../project/tests
npm run test:production

# Monitor for 5 minutes
echo "📊 Monitoring deployment for 5 minutes..."
./monitor-production.sh --duration 300 || {
    echo "❌ Issues detected! Consider rollback."
    echo "Run: ./rollback-production.sh $COMMIT_HASH"
    exit 1
}

# Send deployment notification
echo "📧 Sending deployment notification..."
./notify-deployment.sh "$COMMIT_HASH" "success"

echo "✅ Production deployment completed successfully!"
echo "🌐 Live at: https://openkey.com"
echo "📊 Monitoring: https://monitor.openkey.com"
echo "🏷️ Deployed version: $COMMIT_HASH"