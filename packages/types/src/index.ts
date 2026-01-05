// OpenKey Types - Shared Zod schemas and TypeScript types
import { z } from 'zod';

// Re-export zod for convenience
export { z };

// Ethereum address validation
export const EthereumAddress = z.string().regex(/^0x[a-fA-F0-9]{40}$/, 'Invalid Ethereum address');
export type EthereumAddress = z.infer<typeof EthereumAddress>;

// Sign message request
export const SignMessageRequest = z.object({
  address: EthereumAddress,
  message: z.string().min(1).max(10000),
});
export type SignMessageRequest = z.infer<typeof SignMessageRequest>;

// Sign message response
export const SignMessageResponse = z.object({
  signature: z.string(),
});
export type SignMessageResponse = z.infer<typeof SignMessageResponse>;

// Key info (public)
export const KeyInfo = z.object({
  address: EthereumAddress,
  publicKey: z.string(),
  label: z.string().nullable(),
  createdAt: z.string().datetime(),
});
export type KeyInfo = z.infer<typeof KeyInfo>;
