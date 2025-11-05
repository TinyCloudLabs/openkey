#!/bin/bash
# Production Rollback Script for OpenKey

set -e

if [ -z "$1" ]; then
    echo "❌ Usage: ./rollback-production.sh <previous-commit-hash>"
    exit 1
fi

ROLLBACK_VERSION=$1

echo "🔄 Rolling back OpenKey Production to version: $ROLLBACK_VERSION"

# Confirm rollback
read -p "⚠️  Are you sure you want to rollback PRODUCTION to $ROLLBACK_VERSION? (yes/no): " confirm
if [[ "$confirm" != "yes" ]]; then
    echo "❌ Rollback cancelled"
    exit 1
fi

# Load environment variables
source .env.production

# Create rollback backup
echo "💾 Creating backup before rollback..."
ssh -i $PROD_KEY_PATH $PROD_USER@$PROD_HOST << 'ENDSSH'
    cd /opt/openkey
    docker-compose -f docker-compose.production.yml exec -T postgres pg_dump -U openkey openkey > rollback-backup-$(date +%Y%m%d-%H%M%S).sql
ENDSSH

# Perform rollback
echo "🔄 Rolling back to version $ROLLBACK_VERSION..."
ssh -i $PROD_KEY_PATH $PROD_USER@$PROD_HOST << ENDSSH
    cd /opt/openkey
    
    # Update image tags
    export IMAGE_TAG=$ROLLBACK_VERSION
    
    # Start rollback environment
    docker-compose -f docker-compose.production.yml -p openkey-rollback up -d
    
    # Wait for services to be healthy
    sleep 30
    
    # Switch load balancer to rollback
    ./switch-to-rollback.sh
    
    # Stop current environment
    docker-compose -f docker-compose.production.yml -p openkey-blue down
    
    # Rename rollback to blue
    docker-compose -f docker-compose.production.yml -p openkey-rollback down
    docker-compose -f docker-compose.production.yml -p openkey-blue up -d
ENDSSH

# Verify rollback
echo "🧪 Verifying rollback..."
cd ../../project/tests
npm run test:production || {
    echo "❌ Rollback verification failed!"
    echo "⚠️  Manual intervention required!"
    exit 1
}

# Send notification
echo "📧 Sending rollback notification..."
./notify-deployment.sh "$ROLLBACK_VERSION" "rollback"

echo "✅ Rollback completed successfully!"
echo "🏷️ Now running version: $ROLLBACK_VERSION"
echo "⚠️  Remember to investigate what caused the need for rollback"