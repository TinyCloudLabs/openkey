'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/app/providers';
import { WebAuthnClient } from '@/lib/webauthn';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Shield, Fingerprint, AlertCircle, CheckCircle } from 'lucide-react';

export default function RegisterPage() {
  const [email, setEmail] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [step, setStep] = useState<'email' | 'webauthn' | 'success'>('email');
  const { login } = useAuth();
  const router = useRouter();

  const handleEmailSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!email) {
      setError('Email is required');
      return;
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      setError('Please enter a valid email address');
      return;
    }

    // Check WebAuthn support
    if (!WebAuthnClient.isSupported()) {
      setError('WebAuthn is not supported on this device or browser. Please use a modern browser with HTTPS.');
      return;
    }

    setError('');
    setStep('webauthn');
  };

  const handleWebAuthnRegister = async () => {
    setIsLoading(true);
    setError('');

    try {
      const { user, token } = await WebAuthnClient.register(email);
      
      // Store auth data
      login(user, token);
      
      setStep('success');
      
      // Redirect to dashboard after a moment
      setTimeout(() => {
        router.push('/dashboard');
      }, 2000);
      
    } catch (error) {
      console.error('Registration error:', error);
      setError(WebAuthnClient.formatError(error));
    } finally {
      setIsLoading(false);
    }
  };

  const goBack = () => {
    if (step === 'webauthn') {
      setStep('email');
    } else {
      router.push('/');
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex justify-center mb-4">
            <Shield className="h-12 w-12 text-indigo-600" />
          </div>
          <h1 className="text-3xl font-bold text-gray-900">Create Account</h1>
          <p className="text-gray-600 mt-2">
            Get started with OpenKey's secure authentication
          </p>
        </div>

        <Card>
          <CardHeader className="text-center">
            <CardTitle>
              {step === 'email' && 'Enter Your Email'}
              {step === 'webauthn' && 'Set Up Passkey'}
              {step === 'success' && 'Account Created!'}
            </CardTitle>
            <CardDescription>
              {step === 'email' && 'We\'ll use this to create your secure account'}
              {step === 'webauthn' && 'Use your device\'s biometrics or security key'}
              {step === 'success' && 'Welcome to OpenKey! Redirecting...'}
            </CardDescription>
          </CardHeader>

          <CardContent className="space-y-6">
            {/* Email Step */}
            {step === 'email' && (
              <form onSubmit={handleEmailSubmit} className="space-y-4">
                <div>
                  <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-2">
                    Email Address
                  </label>
                  <input
                    type="email"
                    id="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                    placeholder="you@example.com"
                    required
                  />
                </div>
                
                <Button type="submit" className="w-full">
                  Continue
                </Button>
              </form>
            )}

            {/* WebAuthn Step */}
            {step === 'webauthn' && (
              <div className="text-center space-y-6">
                <div className="bg-indigo-50 rounded-lg p-6">
                  <Fingerprint className="h-16 w-16 text-indigo-600 mx-auto mb-4" />
                  <h3 className="text-lg font-semibold text-gray-900 mb-2">
                    Secure Your Account
                  </h3>
                  <p className="text-gray-600 text-sm">
                    Use your device's built-in security features like Face ID, Touch ID, 
                    or Windows Hello to protect your account.
                  </p>
                </div>

                <Button
                  onClick={handleWebAuthnRegister}
                  disabled={isLoading}
                  className="w-full"
                  size="lg"
                >
                  {isLoading ? (
                    <div className="flex items-center">
                      <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                      Creating Passkey...
                    </div>
                  ) : (
                    'Create Passkey'
                  )}
                </Button>

                <p className="text-xs text-gray-500">
                  You'll be prompted to use your device's authentication method
                </p>
              </div>
            )}

            {/* Success Step */}
            {step === 'success' && (
              <div className="text-center space-y-6">
                <div className="bg-green-50 rounded-lg p-6">
                  <CheckCircle className="h-16 w-16 text-green-600 mx-auto mb-4" />
                  <h3 className="text-lg font-semibold text-gray-900 mb-2">
                    Account Created Successfully!
                  </h3>
                  <p className="text-gray-600 text-sm">
                    Your OpenKey account is ready. You'll be redirected to your dashboard.
                  </p>
                </div>
                
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-600 mx-auto"></div>
              </div>
            )}

            {/* Error Display */}
            {error && (
              <div className="bg-red-50 border border-red-200 rounded-md p-4">
                <div className="flex">
                  <AlertCircle className="h-5 w-5 text-red-400" />
                  <div className="ml-3">
                    <p className="text-sm text-red-800">{error}</p>
                  </div>
                </div>
              </div>
            )}

            {/* Navigation */}
            <div className="flex justify-between items-center pt-4">
              <Button variant="ghost" onClick={goBack}>
                ← Back
              </Button>
              
              <Button
                variant="link"
                onClick={() => router.push('/auth/login')}
                className="text-sm"
              >
                Already have an account? Sign in
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}