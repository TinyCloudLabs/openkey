#!/bin/bash
# Local Development Deployment Script for OpenKey

set -e

echo "🚀 Starting OpenKey Local Development Environment..."

# Navigate to project directory
cd ../../project

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker Desktop."
    exit 1
fi

# Build and start services
echo "📦 Building Docker images..."
docker-compose build

echo "🔧 Starting services..."
docker-compose up -d

# Wait for services to be ready
echo "⏳ Waiting for services to be healthy..."
sleep 10

# Run database migrations
echo "🗄️ Running database migrations..."
docker-compose exec backend npm run migrate

# Show status
echo "✅ Services started successfully!"
echo ""
echo "🌐 Access points:"
echo "   Frontend: http://localhost:3000"
echo "   Backend API: http://localhost:3001"
echo "   Database: postgresql://localhost:5432/openkey"
echo ""
echo "📋 Useful commands:"
echo "   View logs: docker-compose logs -f"
echo "   Stop services: docker-compose down"
echo "   Reset database: docker-compose down -v"
echo ""
echo "🔐 Test credentials:"
echo "   Demo user: demo@openkey.local"
echo "   Demo passkey: Will be created on first login"