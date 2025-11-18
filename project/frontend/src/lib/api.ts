const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
}

class ApiClient {
  private baseUrl: string;

  constructor(baseUrl: string = API_BASE_URL) {
    this.baseUrl = baseUrl;
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${this.baseUrl}/api${endpoint}`;
    
    const config: RequestInit = {
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
      ...options,
    };

    // Add auth token if available
    const token = localStorage.getItem('openkey_token');
    if (token) {
      config.headers = {
        ...config.headers,
        'Authorization': `Bearer ${token}`,
      };
    }

    try {
      const response = await fetch(url, config);
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || data.error || 'Request failed');
      }

      return data;
    } catch (error) {
      console.error('API request failed:', error);
      throw error;
    }
  }

  // Auth endpoints
  async registerBegin(email: string) {
    return this.request('/auth/register/begin', {
      method: 'POST',
      body: JSON.stringify({ email }),
    });
  }

  async registerFinish(email: string, credential: any) {
    return this.request('/auth/register/finish', {
      method: 'POST',
      body: JSON.stringify({ email, credential }),
    });
  }

  async loginBegin(email?: string) {
    return this.request('/auth/login/begin', {
      method: 'POST',
      body: JSON.stringify({ email }),
    });
  }

  async loginFinish(credential: any, challengeId: string) {
    return this.request('/auth/login/finish', {
      method: 'POST',
      body: JSON.stringify({ credential, challengeId }),
    });
  }

  async verifyToken(token: string) {
    return this.request('/auth/verify', {
      method: 'POST',
      body: JSON.stringify({ token }),
    });
  }

  // Key management
  async generateKey() {
    return this.request('/keys/generate', {
      method: 'POST',
    });
  }

  async signMessage(message: string, keyId?: string) {
    return this.request('/keys/sign', {
      method: 'POST',
      body: JSON.stringify({ message, keyId }),
    });
  }

  async signTransaction(transaction: any, keyId?: string) {
    return this.request('/keys/sign-transaction', {
      method: 'POST',
      body: JSON.stringify({ transaction, keyId }),
    });
  }

  async listKeys() {
    return this.request('/keys/list');
  }

  async activateKey(keyId: string) {
    return this.request(`/keys/${keyId}/activate`, {
      method: 'PUT',
    });
  }

  // User endpoints
  async getUserProfile() {
    return this.request('/user/profile');
  }

  async getUserDevices() {
    return this.request('/user/devices');
  }

  async getUserKeys() {
    return this.request('/user/keys');
  }

  async getUserStats() {
    return this.request('/user/stats');
  }

  async removeDevice(credentialId: string) {
    return this.request(`/user/devices/${credentialId}`, {
      method: 'DELETE',
    });
  }

  // Recovery endpoints
  async initiateRecovery(email: string) {
    return this.request('/recovery/initiate', {
      method: 'POST',
      body: JSON.stringify({ email }),
    });
  }

  async verifyRecovery(token: string) {
    return this.request('/recovery/verify', {
      method: 'POST',
      body: JSON.stringify({ token }),
    });
  }

  async completeRecovery(token: string, newCredential: any) {
    return this.request('/recovery/complete', {
      method: 'POST',
      body: JSON.stringify({ token, newCredential }),
    });
  }

  async getRecoveryStatus(token: string) {
    return this.request(`/recovery/status/${token}`);
  }
}

export const api = new ApiClient();
export default api;