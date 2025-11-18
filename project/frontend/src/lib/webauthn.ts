import { 
  startRegistration, 
  startAuthentication,
  type RegistrationResponseJSON,
  type AuthenticationResponseJSON 
} from '@simplewebauthn/browser';
import { api } from './api';

export class WebAuthnClient {
  /**
   * Register a new WebAuthn credential
   */
  static async register(email: string): Promise<{ user: any; token: string }> {
    try {
      // Start registration
      const { options } = await api.registerBegin(email);
      
      // Create credential using WebAuthn
      const credential = await startRegistration(options);
      
      // Complete registration
      const result = await api.registerFinish(email, credential);
      
      return result;
    } catch (error) {
      console.error('WebAuthn registration failed:', error);
      throw new Error(
        error instanceof Error 
          ? error.message 
          : 'Registration failed. Please try again.'
      );
    }
  }

  /**
   * Authenticate using WebAuthn
   */
  static async authenticate(email?: string): Promise<{ user: any; token: string }> {
    try {
      // Start authentication
      const { options, challengeId } = await api.loginBegin(email);
      
      // Get assertion using WebAuthn
      const credential = await startAuthentication(options);
      
      // Complete authentication
      const result = await api.loginFinish(credential, challengeId);
      
      return result;
    } catch (error) {
      console.error('WebAuthn authentication failed:', error);
      throw new Error(
        error instanceof Error 
          ? error.message 
          : 'Authentication failed. Please try again.'
      );
    }
  }

  /**
   * Check if WebAuthn is supported
   */
  static isSupported(): boolean {
    return !!(
      window.PublicKeyCredential &&
      window.navigator.credentials &&
      window.navigator.credentials.create &&
      window.navigator.credentials.get
    );
  }

  /**
   * Check if platform authenticator is available
   */
  static async isPlatformAuthenticatorAvailable(): Promise<boolean> {
    if (!this.isSupported()) return false;
    
    try {
      return await window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    } catch (error) {
      console.warn('Could not check platform authenticator availability:', error);
      return false;
    }
  }

  /**
   * Get available authenticator transport methods
   */
  static getAvailableTransports(): string[] {
    const transports: string[] = [];
    
    if (this.isSupported()) {
      transports.push('cross-platform');
      
      // Platform authenticator check is async, so this is a best guess
      if (window.navigator.userAgent.includes('Mobile')) {
        transports.push('internal');
      }
    }
    
    return transports;
  }

  /**
   * Format error message for user display
   */
  static formatError(error: any): string {
    if (error?.name === 'NotAllowedError') {
      return 'Authentication was cancelled or timed out. Please try again.';
    }
    
    if (error?.name === 'InvalidStateError') {
      return 'This device is already registered. Try signing in instead.';
    }
    
    if (error?.name === 'NotSupportedError') {
      return 'WebAuthn is not supported on this device or browser.';
    }
    
    if (error?.name === 'SecurityError') {
      return 'Security error occurred. Please ensure you are on a secure connection (HTTPS).';
    }
    
    if (error?.name === 'NetworkError') {
      return 'Network error occurred. Please check your connection and try again.';
    }
    
    return error?.message || 'An unexpected error occurred. Please try again.';
  }
}