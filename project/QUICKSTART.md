# OpenKey Quick Start Guide

## 🚀 Get Running in 5 Minutes

### Step 1: Setup
```bash
cd project
./setup.sh
```

### Step 2: Configure
```bash
# Edit .env file - at minimum, add ngrok token for HTTPS
NGROK_AUTHTOKEN=your-token-here
```

### Step 3: Start
```bash
npm run dev
```

### Step 4: Access
- **Frontend**: http://localhost:3000
- **Backend**: http://localhost:3001  
- **ngrok HTTPS**: Check http://localhost:4040 for the tunnel URL

### Step 5: Test
1. Go to the frontend URL
2. Click "Get Started" 
3. Register with your email
4. Complete passkey setup using your device's biometrics
5. Generate an Ethereum key
6. Sign a message!

## 🧪 Testing the Full Flow

### 1. Register Account
- Navigate to http://localhost:3000
- Click "Get Started"
- Enter your email
- Complete WebAuthn registration (use your device's biometrics)

### 2. Dashboard
- View your account stats
- Generate an Ethereum key
- Sign messages with your private key
- Copy your Ethereum address

### 3. Recovery (Optional)
- Test account recovery flow
- Email recovery tokens

## 🔧 Development Commands

```bash
# Start everything
npm run dev

# Install all dependencies
npm run install:all

# Run tests
npm test

# Build for production
npm run build

# Deploy to staging
npm run deploy:staging
```

## 🐛 Troubleshooting

### Docker Issues
```bash
# Reset Docker environment
docker-compose down -v
docker-compose up --build
```

### ngrok Issues
- Get free auth token from https://ngrok.com
- Add to .env: `NGROK_AUTHTOKEN=your-token`
- WebAuthn requires HTTPS in production

### Database Issues
```bash
# Reset database
docker-compose down -v postgres
docker-compose up postgres
```

### Frontend Build Issues
```bash
cd frontend
rm -rf node_modules .next
npm install
npm run build
```

### Backend Build Issues
```bash
cd backend
rm -rf node_modules dist
npm install
npm run build
```

## 📱 Mobile Testing

1. Get your ngrok URL from http://localhost:4040
2. Open the HTTPS URL on your mobile device
3. Test passkey registration with Face ID/Touch ID
4. Test signing transactions

## 🔐 Security Notes

- **Development**: Uses localhost and ngrok HTTPS
- **Production**: Requires proper TLS certificates
- **Keys**: Encrypted with AES-256 and stored securely
- **WebAuthn**: Requires HTTPS in production environments

## 🎯 Next Steps

1. **Customize**: Modify the UI in `frontend/src/`
2. **Extend**: Add more endpoints in `backend/src/controllers/`
3. **Deploy**: Use the deployment scripts for staging/production
4. **Test**: Write more tests in `tests/integration/`

Happy building! 🎉