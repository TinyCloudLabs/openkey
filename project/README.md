# OpenKey

Open-source authentication service combining WebAuthn with Ethereum key management

## 🚀 Quick Start

### Prerequisites
- Node.js 18+
- Docker & Docker Compose
- ngrok account (for WebAuthn testing)

### Local Development

1. Clone the repository:
```bash
git clone https://github.com/your-org/openkey.git
cd openkey/project
```

2. Run the setup script:
```bash
./setup.sh
```

3. Edit the `.env` file with your configuration:
```bash
# Add your ngrok auth token
NGROK_AUTHTOKEN=your-ngrok-token-here

# Configure other settings as needed
```

4. Start the development environment:
```bash
npm run dev
```

5. Access the application:
- Frontend: http://localhost:3000
- Backend API: http://localhost:3001
- ngrok tunnel: Check http://localhost:4040

## 🏗️ Architecture

### Components
- **Backend**: Express API with TypeScript
- **Frontend**: Next.js application with React
- **Database**: PostgreSQL with Prisma ORM
- **Cache**: Redis for sessions
- **Authentication**: WebAuthn (Passkeys)
- **Blockchain**: Ethereum key management

### Tech Stack
- Backend: Express.js with TypeScript
- Frontend: Next.js with TypeScript
- Database: PostgreSQL
- Authentication: WebAuthn (Passkeys)
- Blockchain: Ethereum key management

## 🧪 Testing

Run all tests:
```bash
npm test
```

Run specific test suites:
```bash
npm run test:unit       # Unit tests
npm run test:integration # Integration tests
npm run test:e2e        # End-to-end tests
```

## 📦 Deployment

### Local Deployment
```bash
npm run deploy:local
```

### Staging Deployment
```bash
npm run deploy:staging
```

### Production Deployment
```bash
npm run deploy:production
```

## 🔒 Security

- AES-256 encryption for keys at rest
- TLS 1.3 for transport
- WebAuthn Level 2 compliance
- Domain binding for GPL enforcement
- Rate limiting and DDoS protection

## 📄 License

GPL-3.0

## 👥 Authors

- TinyCloud Team

## 🔧 API Documentation

### Authentication Endpoints

#### POST /api/auth/register/begin
Start WebAuthn registration process

#### POST /api/auth/register/finish
Complete WebAuthn registration

#### POST /api/auth/login/begin
Start WebAuthn authentication

#### POST /api/auth/login/finish
Complete WebAuthn authentication

### Key Management Endpoints

#### POST /api/keys/generate
Generate a new Ethereum key

#### POST /api/keys/sign
Sign a message with Ethereum key

#### POST /api/keys/sign-transaction
Sign an Ethereum transaction

#### GET /api/keys/list
List user's Ethereum keys

### User Endpoints

#### GET /api/user/profile
Get user profile

#### GET /api/user/devices
Get registered WebAuthn devices

#### GET /api/user/stats
Get user statistics

### Recovery Endpoints

#### POST /api/recovery/initiate
Start account recovery process

#### POST /api/recovery/verify
Verify recovery token

#### POST /api/recovery/complete
Complete account recovery

## 🛠️ Development

### Project Structure
```
project/
├── backend/           # Express API
├── frontend/          # Next.js app
├── shared/            # Shared types/utils
├── tests/             # Test suites
├── docs/              # Documentation
└── docker-compose.yml # Local development
```

### Environment Variables

See `.env.example` for all required environment variables.

Key variables:
- `DATABASE_URL` - PostgreSQL connection string
- `REDIS_URL` - Redis connection string
- `JWT_SECRET` - Secret for JWT tokens
- `ENCRYPTION_KEY` - Key for encrypting Ethereum private keys
- `NGROK_AUTHTOKEN` - ngrok token for HTTPS testing

### Database Setup

The project uses Prisma for database management:

```bash
# Generate Prisma client
cd backend && npm run generate

# Run migrations
npm run migrate

# Seed database (optional)
npm run db:seed
```

### Testing Setup

OpenKey uses Playwright for integration testing:

```bash
# Install Playwright browsers
cd tests && npx playwright install

# Run tests
npm run test:integration

# Run tests with UI
npm run test:ui
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

Please ensure all tests pass and follow the existing code style.

## 📞 Support

For questions and support:
- Create an issue on GitHub
- Check the documentation in `/docs`
- Review the API examples

## 🎯 Roadmap

- [ ] TEE integration for enhanced key security
- [ ] Hardware Security Module (HSM) support
- [ ] Multi-chain support (beyond Ethereum)
- [ ] Social recovery mechanisms
- [ ] Mobile app with biometric authentication
- [ ] Enterprise SSO integration