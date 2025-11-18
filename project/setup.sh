#!/bin/bash

echo "🚀 Setting up OpenKey development environment..."

# Check if Bun is installed
if ! command -v bun &> /dev/null; then
    echo "❌ Bun is not installed. Please install Bun first:"
    echo "   curl -fsSL https://bun.sh/install | bash"
    exit 1
fi

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

echo "📦 Installing dependencies..."

# Install root dependencies
bun install

# Install workspace dependencies
echo "🔧 Installing backend dependencies..."
cd backend && bun install && cd ..

echo "🎨 Installing frontend dependencies..."
cd frontend && bun install && cd ..

echo "📝 Installing shared dependencies..."
cd shared && bun install && cd ..

echo "🧪 Installing test dependencies..."
cd tests && bun install && cd ..

echo "🏗️ Building shared package..."
cd shared && bun run build && cd ..

echo "📄 Creating .env file from example..."
if [ ! -f .env ]; then
    cp .env.example .env
    echo "⚠️  Please edit .env file with your configuration before running 'bun run dev'"
else
    echo "✅ .env file already exists"
fi

echo ""
echo "✅ Setup complete! Next steps:"
echo ""
echo "1. Edit .env file with your configuration:"
echo "   - Add your ngrok auth token for HTTPS testing"
echo "   - Configure email settings (optional)"
echo ""
echo "2. Start the development environment:"
echo "   bun run dev"
echo ""
echo "3. Access the application:"
echo "   - Frontend: http://localhost:3000"
echo "   - Backend: http://localhost:3001"
echo "   - ngrok tunnel: http://localhost:4040"
echo ""