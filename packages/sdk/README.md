# @openkey/sdk

The official JavaScript/TypeScript SDK for [OpenKey](https://openkey.so) - secure key management powered by passkeys.

## What is OpenKey?

OpenKey provides secure cryptographic key management using passkeys (WebAuthn). Instead of managing seed phrases or private keys directly, OpenKey stores your keys securely and lets you authorize operations with biometric authentication (Face ID, Touch ID, etc.).

**Key features:**
- **Passkey-secured keys** - Keys are protected by WebAuthn, not passwords
- **No seed phrases** - Never worry about losing or exposing recovery phrases
- **Iframe modal signing** - Clean inline UX with auto-fallback to popup
- **External wallet support** - Link and sign with MetaMask, Rainbow, etc.
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
import { OpenKey, OpenKeyEIP1193Provider } from '@openkey/sdk';

// Initialize the SDK (iframe modal by default)
const openkey = new OpenKey({
  host: 'https://openkey.so',
});

// Connect (opens iframe modal for passkey auth + key selection)
const authResult = await openkey.connect();
console.log('Connected:', authResult.address, authResult.keyType);

// Sign a message (opens iframe modal for user approval)
const { signature } = await openkey.signMessage({
  message: 'Hello, OpenKey!',
  keyId: authResult.keyId,
});
```

## UI Modes

The SDK supports three UI modes for auth and signing flows:

| Mode | Description |
|------|-------------|
| `'iframe'` (default) | Inline modal overlay. No popup blockers. Responsive (card on desktop, bottom sheet on mobile). |
| `'popup'` | Separate browser window. Classic approach. May be blocked by browsers. |
| `'redirect'` | Full page navigation to OpenKey. User returns after completion. |

```typescript
// Set default mode in constructor
const openkey = new OpenKey({ mode: 'iframe' });

// Override per operation
await openkey.connect({ mode: 'popup' });
```

### Auto-fallback

When using `'iframe'` mode, the SDK automatically falls back to `'popup'` if the iframe is blocked by the app's CSP. A brief toast notification ("Opening in new window...") is shown. To avoid the fallback, add to your CSP:

```
frame-src https://openkey.so;
```

## API Reference

### `new OpenKey(options)`

```typescript
const openkey = new OpenKey({
  host: 'https://openkey.so',  // OpenKey server URL
  appName: 'My App',           // Display name in auth UI
  mode: 'iframe',              // 'iframe' | 'popup' | 'redirect'
  externalProvider: provider,  // Optional: app-provided wallet for external key signing
});
```

### `openkey.connect(opts?)`

Authenticate and select a key.

```typescript
const { address, keyId, keyType } = await openkey.connect();
// keyType: 'MANAGED' (TEE-secured) or 'EXTERNAL' (linked wallet)
```

### `openkey.signMessage(request, opts?)`

Sign a message. External keys route directly to the user's wallet.

```typescript
const { signature, address } = await openkey.signMessage({
  message: 'Hello, World!',
  keyId: 'key-id-from-connect',
});
```

### `openkey.signTypedData(request, opts?)`

Sign EIP-712 typed data.

```typescript
const { signature } = await openkey.signTypedData({
  domain: { name: 'My App', version: '1', chainId: 1 },
  types: { Message: [{ name: 'content', type: 'string' }] },
  primaryType: 'Message',
  message: { content: 'Hello!' },
  keyId: 'key-id-from-connect',
});
```

### `openkey.linkWallet(opts?)`

Link an external wallet to the user's OpenKey account.

```typescript
const { address, keyId } = await openkey.linkWallet();
```

### `OpenKeyEIP1193Provider`

A drop-in EIP-1193 provider that routes signing through OpenKey. Handles both managed and external keys transparently.

```typescript
import { OpenKey, OpenKeyEIP1193Provider } from '@openkey/sdk';

const openkey = new OpenKey({ host: 'https://openkey.so' });
const authResult = await openkey.connect();

// Create provider that works with ethers.js, viem, etc.
const provider = new OpenKeyEIP1193Provider(openkey, authResult);
```

## Integration with ethers.js

```typescript
import { OpenKey, OpenKeyEIP1193Provider } from '@openkey/sdk';
import { BrowserProvider } from 'ethers';

const openkey = new OpenKey({ host: 'https://openkey.so' });
const authResult = await openkey.connect();
const provider = new OpenKeyEIP1193Provider(openkey, authResult);

const ethersProvider = new BrowserProvider(provider);
const signer = await ethersProvider.getSigner();
```

## Integration with TinyCloud

```typescript
import { OpenKey, OpenKeyEIP1193Provider } from '@openkey/sdk';
import { TinyCloudWeb } from '@tinycloud/web-sdk';
import { providers } from 'ethers';

const openkey = new OpenKey({ host: 'https://openkey.so' });
const authResult = await openkey.connect();
const eip1193Provider = new OpenKeyEIP1193Provider(openkey, authResult);
const web3Provider = new providers.Web3Provider(eip1193Provider);

const tcw = new TinyCloudWeb({
  providers: { web3: { driver: web3Provider } },
});

await tcw.signIn();
await tcw.kv.put('hello', 'world');
```

## Development

For local development, point the SDK to your local OpenKey instance:

```typescript
const openkey = new OpenKey({
  host: 'http://localhost:5173',
});
```

## Browser Support

OpenKey requires WebAuthn support:
- Chrome 67+
- Firefox 60+
- Safari 13+
- Edge 79+

Iframe mode requires cross-origin WebAuthn support:
- Chrome 84+
- Firefox 84+
- Safari 14.5+

## Security

- Keys never leave the OpenKey TEE (Trusted Execution Environment)
- All signing operations require explicit user approval via passkey
- No seed phrases or private keys to manage or lose
- Iframe communicates via `postMessage` with origin validation
- Auto-fallback to popup ensures signing always works

## Links

- [OpenKey Website](https://openkey.so)
- [GitHub](https://github.com/TinyCloudLabs/openkey)
- [TinyCloud Integration](https://tinycloud.xyz)

## License

MIT
