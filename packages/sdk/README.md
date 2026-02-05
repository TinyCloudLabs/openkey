# @openkey/sdk

The official JavaScript/TypeScript SDK for [OpenKey](https://openkey.so) - secure key management powered by passkeys.

## What is OpenKey?

OpenKey provides secure cryptographic key management using passkeys (WebAuthn). Instead of managing seed phrases or private keys directly, OpenKey stores your keys securely and lets you authorize operations with biometric authentication (Face ID, Touch ID, etc.).

**Key features:**
- **Passkey-secured keys** - Keys are protected by WebAuthn, not passwords
- **No seed phrases** - Never worry about losing or exposing recovery phrases
- **Popup-based signing** - Clean UX with authorization popups
- **EIP-1193 compatible** - Works with ethers.js, viem, and other web3 libraries

## Installation

```bash
npm install @openkey/sdk
# or
yarn add @openkey/sdk
# or
bun add @openkey/sdk
```

## Quick Start

```typescript
import { OpenKey } from '@openkey/sdk';

// Initialize the SDK
const openkey = new OpenKey({
  host: 'https://openkey.so', // Production
  // host: 'http://localhost:5173', // Development
});

// Connect to OpenKey (opens popup for user to select/create a key)
const { address, keyId } = await openkey.connect();
console.log('Connected:', address);

// Sign a message (opens popup for user approval)
const signature = await openkey.signMessage({
  message: 'Hello, OpenKey!',
  keyId,
});
console.log('Signature:', signature);
```

## API Reference

### `new OpenKey(options)`

Create a new OpenKey instance.

```typescript
const openkey = new OpenKey({
  host: 'https://openkey.so', // OpenKey server URL
});
```

**Options:**
- `host` (string): The OpenKey server URL. Use `https://openkey.so` for production.

### `openkey.connect()`

Opens the OpenKey popup for the user to authenticate and select a key.

```typescript
const { address, keyId } = await openkey.connect();
```

**Returns:**
- `address` (string): The Ethereum address of the selected key
- `keyId` (string): The unique identifier for the key (used in signing operations)

### `openkey.signMessage(params)`

Sign a message with the user's key. Opens a popup for user approval.

```typescript
const signature = await openkey.signMessage({
  message: 'Hello, World!',
  keyId: 'key-id-from-connect',
});
```

**Parameters:**
- `message` (string): The message to sign
- `keyId` (string): The key ID from `connect()`

**Returns:**
- `signature` (string): The hex-encoded signature

### `openkey.signTypedData(params)`

Sign EIP-712 typed data with the user's key.

```typescript
const signature = await openkey.signTypedData({
  domain: {
    name: 'My App',
    version: '1',
    chainId: 1,
  },
  types: {
    Message: [{ name: 'content', type: 'string' }],
  },
  primaryType: 'Message',
  message: {
    content: 'Hello!',
  },
  keyId: 'key-id-from-connect',
});
```

## Integration with ethers.js

OpenKey can be used as an EIP-1193 provider with ethers.js:

```typescript
import { OpenKey } from '@openkey/sdk';
import { BrowserProvider } from 'ethers';

// Create OpenKey instance
const openkey = new OpenKey({ host: 'https://openkey.so' });

// Connect and get the address
const { address, keyId } = await openkey.connect();

// Create an EIP-1193 compatible provider
const eip1193Provider = {
  async request({ method, params }: { method: string; params?: any[] }) {
    switch (method) {
      case 'eth_accounts':
      case 'eth_requestAccounts':
        return [address];
      case 'eth_chainId':
        return '0x1'; // Mainnet
      case 'personal_sign': {
        const message = hexToString(params![0]);
        const result = await openkey.signMessage({ message, keyId });
        return result.signature;
      }
      default:
        throw new Error(`Unsupported method: ${method}`);
    }
  },
};

// Use with ethers
const provider = new BrowserProvider(eip1193Provider);
const signer = await provider.getSigner();
```

## Integration with TinyCloud

OpenKey works seamlessly with [TinyCloud](https://tinycloud.xyz) for decentralized storage:

```typescript
import { OpenKey } from '@openkey/sdk';
import { TinyCloudWeb } from '@tinycloud/web-sdk';
import { BrowserProvider } from 'ethers';

// Setup OpenKey
const openkey = new OpenKey({ host: 'https://openkey.so' });
const { address, keyId } = await openkey.connect();

// Create EIP-1193 provider (see above)
const eip1193Provider = createOpenKeyProvider(openkey, address, keyId);
const ethersProvider = new BrowserProvider(eip1193Provider);

// Initialize TinyCloud with OpenKey as the signer
const tcw = new TinyCloudWeb({
  providers: {
    web3: {
      driver: ethersProvider,
    },
  },
});

// Sign in to TinyCloud (uses OpenKey for SIWE signature)
await tcw.signIn();

// Now you can use TinyCloud storage
await tcw.kv.put('hello', 'world');
const result = await tcw.kv.get('hello');
```

## Development

For local development, point the SDK to your local OpenKey instance:

```typescript
const openkey = new OpenKey({
  host: 'http://localhost:5173',
});
```

You can also enable dev mode in your app to use local OpenKey:

```javascript
localStorage.setItem('__DEV_MODE__', 'true');
```

## Browser Support

OpenKey requires WebAuthn support:
- Chrome 67+
- Firefox 60+
- Safari 13+
- Edge 79+

## Security

- Keys never leave the OpenKey TEE (Trusted Execution Environment)
- All signing operations require explicit user approval via passkey
- No seed phrases or private keys to manage or lose

## Links

- [OpenKey Website](https://openkey.so)
- [Documentation](https://docs.openkey.so)
- [GitHub](https://github.com/AstroX11/openkey)
- [TinyCloud Integration](https://tinycloud.xyz)

## License

MIT
