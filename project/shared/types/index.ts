// Shared types between frontend and backend

export interface User {
  id: string;
  email: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface Credential {
  id: string;
  userId: string;
  credentialId: string;
  transports: string[];
  createdAt: Date;
  updatedAt: Date;
}

export interface EthereumKey {
  id: string;
  userId: string;
  address: string;
  keyIndex: number;
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
}

// API Request/Response types
export interface RegisterRequest {
  email: string;
  credential: {
    id: string;
    rawId: string;
    response: {
      clientDataJSON: string;
      attestationObject: string;
    };
    type: string;
  };
}

export interface RegisterResponse {
  success: boolean;
  user: User;
  token: string;
}

export interface LoginRequest {
  email: string;
  credential: {
    id: string;
    rawId: string;
    response: {
      clientDataJSON: string;
      authenticatorData: string;
      signature: string;
      userHandle?: string;
    };
    type: string;
  };
}

export interface LoginResponse {
  success: boolean;
  user: User;
  token: string;
}

export interface GenerateKeyResponse {
  success: boolean;
  address: string;
  keyId: string;
}

export interface SignMessageRequest {
  message: string;
  keyId: string;
}

export interface SignMessageResponse {
  success: boolean;
  signature: string;
  address: string;
}

export interface SignTransactionRequest {
  transaction: {
    to: string;
    value: string;
    data?: string;
    gasLimit?: string;
    gasPrice?: string;
  };
  keyId: string;
}

export interface SignTransactionResponse {
  success: boolean;
  signedTransaction: string;
  hash: string;
}

export interface RecoveryRequest {
  email: string;
}

export interface RecoveryResponse {
  success: boolean;
  message: string;
}

export interface ApiError {
  error: string;
  message: string;
  statusCode: number;
}